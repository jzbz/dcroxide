# Security policy

## Status: pre-alpha — do not expose to the internet, do not use with funds

dcroxide is an in-progress reimplementation of dcrd. It has never been
audited by anyone outside the project, it has never run in production,
and it has no track record on a live network beyond the sync
validations described in the README. **It is not a supported node
implementation. Do not run it where it can be reached from the public
internet, do not point a wallet at it, and do not rely on it to
validate, relay, or hold funds.** Use [dcrd](https://github.com/decred/dcrd)
for anything that matters.

There are no supported versions. Nothing here carries a security
guarantee, and there is no commitment to a fix timeline or to a
coordinated-disclosure window.

## Reporting a vulnerability

Report privately through GitHub's security advisories:

<https://github.com/jzbz/dcroxide/security/advisories/new>

Please do not open a public issue for anything that looks exploitable
against a running node, and please do not file it against dcrd — a bug
in this repository is a bug in this port, not in dcrd, unless you have
reproduced it against dcrd itself.

Useful things to include: the affected file and function, whether the
attacker needs to be an authenticated RPC client / a connected peer /
a local user, and a reproducer or the minimal message or request that
triggers it.

## Scope

**In scope.** Anything that a remote peer, an RPC client, or a local
unprivileged user can do to a dcroxide node that dcrd would not permit:
memory exhaustion or a wedge from unauthenticated P2P input,
authentication or authorization bypass on the JSON-RPC and websocket
surfaces, credential and private-key exposure through file permissions
or logs, panics reachable from untrusted input, and any consensus
divergence from dcrd (a fork is a security bug here even when it looks
like a correctness bug).

**Out of scope.** Behaviour that faithfully reproduces dcrd, including
dcrd's own quirks and limits — those are the specification, and the
deliberate ones are catalogued in [QUIRKS.md](QUIRKS.md). If you think
dcrd itself is wrong, report it to
[dcrd](https://github.com/decred/dcrd/security/policy) instead. Also out
of scope: resource use under a workload dcrd would also struggle with,
and anything requiring an already-privileged local attacker (they can
read the datadir regardless). Throughput is out of scope as well: this
port syncs roughly 2.2x slower than dcrd and spends most of an initial
block download stalled in storage commits. Both are measured and
self-inflicted. That the cost is the storage engine's commit shape
rather than validation is an attribution, not a finding — a matched
replay on the same engine spent 863 s of 4,767 in flushes, 18%, and no
profile exists. But whatever the dominant term turns out to be, it is
work the node does to itself rather than work a peer can add to, so
there is nothing here for a peer to amplify.

## Known gaps

The project runs its own internal security review. A campaign closing
its release-blocking findings landed this cycle — bounds on the peer
message path, authentication and admission on the RPC surface,
owner-only permissions on the files the daemon generates for itself,
OS-seeded CSPRNGs, and the panic policy below. Every fix, the reasoning
behind it, and the divergences from dcrd it introduced are itemized in
[PARITY.md](PARITY.md) under "Deliberate divergences from dcrd" and its
"Known remaining gaps" subsection, rather than being hidden. What
follows is the residue: the standing gaps that matter most for anyone
evaluating this code.

- **A panic aborts the process** (`panic = "abort"` on the release
  profile). Rust mutexes poison and Go's do not, so dcrd recovers per
  goroutine where this port cannot: a panic on one thread poisons every
  lock it held, and each other consumer then dies on
  `.expect("… poisoned")` in turn. Aborting is the deliberate choice for
  a consensus daemon — state a panic left half-mutated cannot be reasoned
  about, so a supervisor restarting a clean node beats continuing on
  unknown state. **Run it under a supervisor that restarts it**
  (`Restart=on-failure` or equivalent): any reachable panic is an outage
  until something restarts the process. The tradeoff is deliberate, and
  loud beats the previous behaviour, where a poisoned lock wedged the node
  while the RPC layer's `catch_unwind` kept it answering canned errors and
  looking healthy.
- **A websocket client that stops reading grows node memory without
  bound.** The notification queues are unbounded, exactly as dcrd's are,
  so nothing is ever dropped and nothing is reordered — the whole cost of
  a slow or stalled subscriber is paid in node memory. Since RPC access
  requires credentials this is not reachable unauthenticated, and adding
  a cap would diverge from dcrd while cutting off honest clients on slow
  links, so it stays. Operators running many subscribers, or exposing the
  websocket to clients they do not control, should bound the process
  (a memory limit plus a supervisor) rather than expect the node to shed.
  One port-specific amplifier: a single long request — a
  multi-thousand-block `rescan` — holds the server lock for its duration
  and stalls notification construction for every other client, where
  dcrd's handlers hold no server-wide lock.
- **Fuzzing reaches the leaf codecs and nothing else.** Eleven
  `cargo-fuzz` targets run for 60 seconds apiece on every push to
  `master` and every pull request, and for ten minutes apiece nightly:
  wire framing, the `tx` and `blockheader` decoders, the script engine,
  `chainhash` parsing, DER signature parsing, public-key parsing, the
  Schnorr and Ed25519 suites, `uint256`, and BLAKE-256. That is six of
  the thirty-two crates, and all six are stateless — decoders,
  cryptographic arithmetic, and a script interpreter that is a pure
  function of its inputs. The stateful surfaces are unfuzzed — the
  JSON-RPC and websocket dispatch, the peer and sync state machines,
  the mempool, the database — and those are where a reachable panic or
  an unbounded allocation is most likely to survive review. No corpus
  is committed (`fuzz/corpus` is ignored), so every run starts cold and
  has to rediscover structure inside its budget. Those jobs are also
  the only sanitized build in CI, since `cargo fuzz` defaults to
  AddressSanitizer; neither the test suite nor a running node is run
  under a sanitizer.
- **Nobody has read the dependencies.** `cargo-deny` does run on every
  push to `master` and every pull request against `deny.toml`, gating
  the RustSec advisory database, a licence allow-list, yanked crates,
  and unknown registries or git sources. That is an automated check
  against a list of problems someone else already found; it is not a
  review. Nothing in the tree has been read, and the tree includes the
  elliptic-curve implementations, the TLS stack, and the storage engine
  that this node's key handling and on-disk consensus state rest on.
  [docs/dependency-ledger.md](docs/dependency-ledger.md) does not close
  this gap, but it bounds it: the twelve crates that are consensus-
  observable or touch key material now carry an explicit decision each,
  so their trust status is stated rather than assumed and a version bump
  of one of them is a decision rather than a silent lockfile change.
  Most of those decisions are still "accepted without a read." The
  storage engine exercised that bound this cycle: redb went 2.6.3 to
  4.1.0 on 2026-08-13, across two majors and a changed on-disk format,
  argued in ADR-0004's upgrade addendum rather than arriving as a
  lockfile change. It is maintenance, not hardening. 4.1.0 carries four
  known open issues, none a regression against 2.6.3 and all concerning
  a file that is already damaged or hostile: #1331 and #1332 abort the
  process on malformed on-disk structures (an unvalidated 5-bit page
  order, and a cyclic branch pointer reached from ordinary reads),
  #1333 leaves a file permanently unopenable when the repair path
  itself panics, and read paths do not verify page checksums until a
  fix that is currently master-only.

## What this project does instead of a guarantee

Every ported package is tested against dcrd itself — differential
tests through a Go oracle binary that links dcrd's published modules,
plus replays of vectors dumped from inside dcrd's own test packages.
That catches divergence, which is the failure mode this port is most
exposed to. It does not catch a design flaw shared with dcrd, and it
does not substitute for review by someone who did not write the code.

It also does not catch a control that is wrong in the other direction.
Four of the security campaign's fixes, as first written, defended
against an attacker by breaking things for legitimate users: a getdata
ban score that would have banned peers doing ordinary early-chain sync,
an RPC admission ceiling that turned a thread flood into a total
outage, a full-queue disconnect that severed honest peers on slow
links, and a write deadline that bounded each send instead of the
message. None of the four was caught by reading the code; each came out
of separately re-deriving what happens to an honest peer under load,
which is now a standing question in the review rather than an
afterthought. In the same campaign, five comments were found asserting
the opposite of what the code beneath them did — including one that
justified a coarse server-wide lock as dcrd's own per-request locking,
where dcrd takes no server-wide lock at all. Comments in this
repository are claims, not evidence. (That lock has since been removed:
the RPC server now carries dcrd's per-field locks, and the handler seams
take `&self`. See PARITY.md's websocket-delivery note.)
