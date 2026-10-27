# ADR-0013 — D5: Upstream tracking by release tags, with master read ahead

- **Status:** Accepted (decision D5) by the project owner on 2026-10-26,
  with the other recommendations of that day, to take effect when dcrd
  tags v2.2.0. Until then the pin follows master as set on 2026-10-25 (see
  "Until the tag"). Nothing the first tag move needs is built yet: "What
  the first tag move needs" lists it, and that move waits on it.
- **Date:** 2026-10-26

## Context

The project brief left D5 open as "Upstream tracking cadence once 2.2
lands upstream: parity branch policy, how consensus PRs are mirrored, who
owns the watch" (§9, D5 in its original list). The rules around it were
already set: code at the pinned upstream commit is the specification
(principle 1, `docs/dcroxide-project-brief.md:522`, and R2 in §10); all
parity claims reference one pin, and a standing "upstream watch" reviews
dcrd's releases and merged consensus changes (principle 7, `:528`), a
watch nothing had defined: no ADR, schedule or CI job. The plan expected
the pin to track "upstream releases thereafter" (`:430`), with
"pinned-tag parity claims" (R7, §10) and work that "matches the pinned
dcrd tag" (§12's definition of done).

**How the pin has moved.** Seven times in about 14 weeks: from
`release-v2.1.5` to master `452c1a6c`, then to `29f17894`, `036b7090`,
`b9634e01`, `6f6cf21b`, `382ff4dd` and `3360ae4d` (`docs/PARITY.md:3-11`),
carrying 294, 19, 19, 3, 31, 39 and 1 upstream commits, each move landing
within six days of the upstream commit it pinned. Since the `036b7090`
move each one has a PARITY.md section, titled by its commit range, that
ports or accounts for every upstream commit in it (`docs/PARITY.md:134`,
`:165`, `:394`, `:805`, `:832`), starting from `tools/pinbump`'s review
list (`tools/pinbump/main.go:3-31`). On 2026-10-25 the project owner made
dcrd v2.2 the target: upstream has not released it, so the pin follows
master until v2.2 is tagged, moving at upstream milestones and on the
project owner's word (`docs/PARITY.md:5-7`; ADR-0001's addendum of that
date). That cadence covers only the time until the tag. `3360ae4d` was
master's head on 2026-10-25, with no `release-v2.2` branch
(`docs/PARITY.md:136-137`) and no `release-v2.2` tag.

**What the master pin cost.** A move shifts citations even when it changes
little: the one-commit `3360ae4d` move moved 62 undated citations of
`rpcserver.go` four lines (`docs/PARITY.md:159-163`). And the reference an
operator runs is a release. The acceptance run of 2026-10-23 used the dcrd
2.1.7 release binaries, and every reply that differed followed dcrd
master's source at the pin of the day, came from a part not yet ported,
or matched a second dcrd in the same role
(`docs/dcroxide-project-brief.md:68-76`). Two entries `1668c5a` added to
PARITY.md keep master's behaviour where 2.1.7 differs: `addnode` and
`node`, protocol version 12 against 11 and `debuglevel`'s subsystems in
one, and the retry backoff for an unreachable `--connect` peer in the
other (`docs/PARITY.md:2307-2362`).

**How dcrd releases**, read from its repository as fetched on 2026-10-25:

- A release line is cut from master on the day of its `.0` tag. For v2.1,
  master's "main: Update to use all new module versions." (`8f571ec2`,
  2025-11-24) is the branch point; `release-v2.1` adds the removal of the
  module replacements (`a3f246a7`) and the bump for 2.1.0 (`3efd2731`,
  the `release-v2.1.0` tag), and master moved to the next cycle the same
  day (`14f7b06e`).
- The `.0` tags came on 2023-06-09 (v1.8.0), 2024-05-16 (v2.0.0) and
  2025-11-24 (v2.1.0), cycles of 11 and 18 months; the current one is 11
  months old, and master is 406 commits past the v2.1 branch point.
- Point releases are made of backports from master. All 169 commits on
  `release-v2.1` past the branch point carry the "[release-v2.1]" prefix
  and none a cherry-pick trailer; 141 of them were committed on the day of
  a tag. v2.1 has had seven point releases in about eleven months; v2.1.7
  alone was 87 commits touching 161 files.
- Backports wait on master. Of the 142 `release-v2.1` backports matched to
  master by subject line, 43 were on master within 7 days of the tag that
  shipped them; v2.1.6's 19 matched backports had been there a mean 84
  days, v2.1.7's 80 a mean 44.
- A release line has defects and gaps of its own. v2.1.4 shipped a
  backport (`664d136e`) whose revert (`d33bde2f`, in v2.1.5) describes a
  data race or nil dereference unique to the release branch. v2.1.6
  shipped the same-block stake-spend rule without master's testnet3
  exception (`9b7ab54a`, 2026-08-19), which the release line took in
  v2.1.7 (`059742a9`, 2026-10-13); the port took both together
  (`docs/PARITY.md:836-839`).
- A tag drops the replace block. dcrd's `go.mod` has no `replace` at
  `release-v2.0.0`, `release-v2.1.0` or `release-v2.1.7`, against 28
  replace lines at master `3360ae4d`, and neither carries a `go.work`. A
  dcrd built at a tag therefore links each nested module at the version
  its `go.mod` requires, and those versions are module tags cut on master:
  at `release-v2.1.7`, `wire` v1.8.0 (master `efa17f60`, 2026-10-05),
  `blockchain` v5.1.1 (`e201209e`) and `blockchain/standalone` v2.3.0
  (`59e2c9d3`). They need not match the tag's own directories. `wire`
  v1.8.0 differs from `release-v2.1.7`'s `wire/` in 14 files, among them
  `msgaddrv2.go` and `netaddressv2.go`, which only the module has;
  `blockchain/standalone`, `mixing`, `dcrec/secp256k1`, `txscript`, `gcs`
  and `peer` differ in 6, 11, 2, 1, 1 and 1; `chaincfg` and
  `blockchain/stake` match.

**What a tag pin breaks.** Reaching the v2.2 target at its tag meets three
things built for a master pin, whatever rule follows it:

- The consistency test reads the `go.mod` header text after "dcrd master
  commit " (`crates/dcroxide-testutil/src/lib.rs:1385-1391`) and fails when
  no dcrd module is pinned by pseudo-version (`:993-996`). At a tag every
  module would be pinned by tag.
- The interop harness would refuse CI's own build. dcrd's note for
  maintainers sets the build metadata `release.local` on a release branch
  and has reproducible release builds override `Version` through linker
  flags (`internal/version/version.go:34-46` at `release-v2.1.7`); the
  2.1.5, 2.1.6 and 2.1.7 tags carry `Version = "2.1.N+release.local"`
  (`:60` at each), and `init` stamps the VCS revision only when the build
  metadata is empty (`:161-177`). The harness's `assert_dcrd_revision`
  takes eight or more characters after a `+` for a stamped revision, and
  any revision but the pin's for a different specification
  (`crates/dcroxide-testutil/src/lib.rs:630-672`, the check at
  `:656-664`), so `release.local` is refused. Inference: the v2.2 tags
  follow the same documented process.
- Nested modules. `tools/pinbump` lists the files a tree diff between the
  two refs changes (`tools/pinbump/main.go:166`), and the port's citations
  read dcrd's tree; at a tag, neither is what the binary links for a
  nested module.

## Decision

1. **From dcrd v2.2.0 on, the pin is a dcrd release tag on the newest
   release line:** `release-v2.2.0`, then each `release-v2.2.N`, then the
   next release line's `.0` tag, and so on. A point release on an older
   line, cut after a newer `.0` tag, is not followed.
2. **Triggers.**
   - Each point release is pinned, at the project owner's timing.
   - A release that changes consensus, or one dcrd calls mandatory, is
     pinned promptly. v2.1.6 was such a release (`docs/PARITY.md:839-840`).
3. **Master is read ahead, not ported.** At each point release, or on the
   project owner's word, `tools/pinbump` runs from the pin to dcrd master's
   head, and the master commits in that range that touch consensus or
   policy packages are recorded in a dated note. A note is not a parity
   claim, and it says so: nothing in it is ported until a release carries
   it. The move to the next `.0` tag starts from the notes. Which packages
   count is this ADR's reading, since the approval named none: those
   `tools/pinbump` resolves to the crates the brief's §7 gates call
   consensus-tagged (`txscript`, `stake`, `standalone`, `blockchain`, `gcs`,
   `dcrec`, `wire`, and `mixing`'s validation paths), to `chaincfg`, which
   defines the agendas, and to the policy crates, `mempool`, `mining` and
   `mixing`'s pool, which carry the limits principle 6 names
   (`docs/dcroxide-project-brief.md:527`).
4. **One dcroxide branch.** master carries the one pin. No second line is
   kept, neither a release branch beside master nor an early-port branch
   for a master agenda; one would need a decision of the project owner's.
5. **"dcrd at the pin" at a tag** is dcrd's root module at the tag plus
   each nested module at the version the tag's `go.mod` requires: the code
   a dcrd built from the tag links. A citation into the root module reads
   at the tag; a citation into a nested module names the module version
   beside the file (`wire` v1.8.0's `msgaddrv2.go`, not
   `release-v2.1.7`'s tree, where that file does not exist).
6. **The move is the mirroring unit.** Each move starts from
   `tools/pinbump`'s review list and gets one PARITY.md section titled by
   its range (the first from the last master pin to `release-v2.2.0`, then
   `release-v2.2.0..release-v2.2.1` and so on) that ports or accounts for
   every upstream commit in it; for a nested module the range runs between
   its required versions at the two ends. Upstream changes are not
   mirrored pull request by pull request.
7. **The watch is the project owner's.** A move or a read-ahead is made at
   a release or on the project owner's word; nothing schedules it yet, and
   whether a scheduled CI job runs `tools/pinbump` is left open (below).
8. **Release-line gaps and defects are reproduced or recorded.** The
   release is the specification, so a fix master has and the release
   lacks is not ported ahead of a release that carries it, and a defect
   only the release line has is reproduced under principle 1's rule or
   recorded in PARITY.md as a divergence.

The approval named two things: following dcrd's official release tags
(v2.2.0, v2.2.1 and so on), and reading ahead through dcrd's in-progress
changes every so often, taking notes, so that the next major step is no
surprise. The rest of items 1 to 8 is this ADR's reading of that
recommendation: in item 1, that a point release on an older line is not
followed; in item 2, when each release is pinned; in item 3, the
read-ahead's cadence, what its notes record and claim, and which packages
count; and items 4 to 8 whole.

This does not supersede ADR-0001. The oracle mechanism is unchanged, and
at a tag its version rule returns to the one ADR-0001 was accepted with.

## Until the tag

The cadence of 2026-10-25 stands: the pin follows master, now `3360ae4d`
(version 2.2.0-pre), moving at upstream milestones and on the project
owner's word, and the oracle and `tools/fullblockgen` keep the split their
`go.mod` headers record, each dcrd module at the pin's pseudo-version or
at a tag byte-identical to the in-tree module (`tools/oracle/go.mod:5-45`,
`tools/fullblockgen/go.mod:5-26`).

## What the first tag move needs

None of this is built. The move to `release-v2.2.0` waits on dcrd tagging
v2.2.0 and on each part below, which lands with that move or before it.

- **The consistency test's tag shape.**
  `the_dcrd_pin_matches_ci_and_the_oracle`
  (`crates/dcroxide-testutil/src/lib.rs:1354-1401`) has to read a header
  that names the tag and its commit in place of "dcrd master commit "
  (`:1385-1391`), and the rule that at least one dcrd module is pinned by
  pseudo-version (`:993-996`) has to go. It already refuses a `replace`
  of a dcrd module (`:985-992`). Inference: at a tag it also refuses any
  pseudo-version, and whether each module sits at the tag's required
  version needs dcrd's `go.mod` at the tag, which the repository does not
  hold, so that half is checked at the move unless a CI job with a dcrd
  clone takes it on.
- **The harness's revision check.** `assert_dcrd_revision`
  (`crates/dcroxide-testutil/src/lib.rs:630-672`) has to accept a dcrd that
  CI built from the tag's commit. Two ways are open, neither chosen
  (inference): read the revision from the binary's Go build information,
  which `-buildvcs=true` records whatever the version string says; or
  build with the linker override `version.go` documents (`:51-54` at
  `release-v2.1.7`) set to the bare `X.Y.Z`, so that `init` stamps the
  revision as it does on master. `DCRD_COMMIT` becomes the tag's commit
  (`.github/workflows/ci.yml:205`), and the comment that a release "is a
  different specification" (`:229-232`) changes with it.
- **ADR-0001's original rule for the oracle and `fullblockgen`.** Every
  dcrd module in `tools/oracle/go.mod` and `tools/fullblockgen/go.mod`
  sits at exactly the version the tag's `go.mod` requires, as ADR-0001's
  Decision put it for `release-v2.1.5`, with no pseudo-version. The split
  re-derived at each master move ends, and with it the `edwards` exception
  (`tools/oracle/go.mod:9-12`). An addendum to ADR-0001 records the return
  when it lands.
- **A module-aware `tools/pinbump`.** Its tree diff
  (`tools/pinbump/main.go:166`) is right for the root module and wrong for
  nested ones: across `release-v2.1.6..release-v2.1.7` it lists 90 files
  under `wire/`, where the linked `wire` v1.7.5..v1.8.0 changes 93. A mode
  that diffs each nested module between its required versions at the two
  ends is needed. At the first move the master end links the in-tree
  directories, through master's replace block.
- **Citations into nested modules name the module version.** Those made
  against a master pin read the in-tree directories, and the first move
  re-reads them at the required versions.
- **Exporters that read a nested module from the checkout** (inference).
  `tools/mixpoolgen` runs as a test inside a dcrd checkout's
  `mixing/mixpool` package (`tools/mixpoolgen/run.sh:9-14`, `:33`), and at
  `release-v2.1.7` that directory is not the `mixing` v0.7.5 the release
  links, 11 files differing. `tools/disapprovalgen` overlays a copy of the
  checkout's `blockchain/chaingen/generator.go`, a file of the nested
  `blockchain` module, on a test in `internal/blockchain`
  (`tools/disapprovalgen/run.sh:9-11`, `:39-40`), which at a tag links
  that module from its required version rather than from the checkout. At
  a tag, such a run needs the module at its required tag.
- **Version constants.** `VERSION` becomes `2.2.0`, with an empty
  pre-release (`crates/dcroxide-node/src/version.rs:21`,
  `crates/dcroxide-rpc/src/version.rs:13-31`), so the user agent drops its
  `(pre)` comment (`PeerTemplate::config` in
  `crates/dcroxide-node/src/runtime.rs`). Which build metadata the
  constants carry, empty or a release form, is chosen at the move.
- **The text that names the pin.** `README.md:6-8`; PARITY.md's opening
  paragraph, its *Oracle pin* paragraph and the paragraph on the Go
  release dcrd's `contrib/docker/Dockerfile` builds with; the brief's
  target statements (`docs/dcroxide-project-brief.md:5`, `:47-54`,
  `:430`, `:528`, as its rule for corrections allows, `:34-37`) and its
  §9 entry for D5; and the ADR index's line for ADR-0001 and its D5
  entry.

Where the read-ahead notes live is settled with the first one. They are
not PARITY.md's range sections, which record what the port claims.

## Consequences

- **The acceptance reference and the specification become the same
  release.** A run against the release binaries no longer has to explain
  differences by master's source at the pin, and differences like the two
  `1668c5a` recorded stop arising from the gap between them.
- **Fewer, larger moves.** v2.1's seven point releases came in about
  eleven months, against seven master moves in fourteen weeks, and the
  largest of them, v2.1.7, was 87 commits.
- **Fixes arrive with the release, not with master.** v2.1.6's backports
  had been on master a mean 84 days before it shipped them. That is parity
  with what operators run, not a regression against it, but it gives up
  the head start following master gave.
- **Release-only gaps and defects come with the pin.** Under this rule the
  pin would have carried v2.1.6 without the testnet3 exception for eight
  weeks and v2.1.4 with a race for four days, each reproduced or recorded.
  Following only the tags leaves no way past one before the release that
  fixes it; taking a backport early would need a decision of the project
  owner's.
- **Backports are handled twice**: once from the release line at a
  point-release move, and again as their master originals at the next
  `.0` move, matched by subject line, since dcrd's cherry-picks carry no
  trailer.
- **The `.0` move is the big step.** It is not a fast-forward and spans a
  whole master cycle, 406 commits so far in the current one. That is the
  shape of the July `release-v2.1.5..452c1a6c` move, which, made before
  `tools/pinbump` existed (`5d2fb82`, 2026-08-07), left release-v2.1.5's
  external-address selection in the tree until `4497397` (2026-09-04),
  unwired throughout. The read-ahead notes slice that step, and a new
  consensus agenda is seen when it lands on master rather than at the
  `.0` tag.
- **No parity claim is made about unreleased dcrd.** A read-ahead note
  says what master does; the port claims only the tag.
- **Each move and each read-ahead needs a fresh fetch of dcrd's
  repository.**
- **Binaries.** [ADR-0014](0014-release-engineering.md) (D7), accepted the
  same day, makes the pin at dcrd's v2.2 release tag one of the conditions
  before any dcroxide binary is published; the first tag move under this
  rule meets it.
- **Left open:** where the read-ahead notes live; whether a point release
  that a newer one supersedes before its move lands is pinned on the way
  or skipped; whether a scheduled CI job runs `tools/pinbump` against
  dcrd's newest tag and master (CI already clones dcrd for the interop
  job, `.github/workflows/ci.yml:236`, and its one scheduled job is the
  nightly fuzz, `:7-9`, `:386-388`); and the harness and build-metadata
  choices above.

## Alternatives

- **Keep following master across releases**, each release a waypoint.
  Rejected: between waypoints the port would claim parity with code no
  release ships, for cycles that have run 11 and 18 months between `.0`
  tags; acceptance against release binaries would keep its adjudication
  step; and the brief's `:430`, R7 and definition of done say otherwise.
  It keeps small, prompt moves and master's head start on fixes, which
  this decision gives up.
- **Two lines, mirroring dcrd's**: dcroxide master on dcrd master, and a
  dcroxide `release-v2.2` branch on dcrd's tags. Rejected: every backport
  is ported and signed twice, PARITY.md keeps two states and CI two pins,
  and CI's push trigger names master alone
  (`.github/workflows/ci.yml:4-5`); for a single maintainer that roughly
  doubles the work of each release (inference).
- **Master until dcroxide ships, then tags.** Rejected: it pays off only
  if no dcroxide binary appears during v2.2.x, and ADR-0014 ties binaries
  to a v2.2 tag pin. Inference: a master pin reaches a point release only
  by undoing master work, so the switch could land only at the next `.0`
  tag.
- **The release branch's head as the pin.** Rejected: between tags it
  names code no release ships, while the version string still reads the
  previous release, and it adds little over the tags, since 141 of
  `release-v2.1`'s 169 commits landed on a tag day.
