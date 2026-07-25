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
read the datadir regardless).

## Known gaps

The project runs its own internal security review; the current
release-blocking findings and the hardening backlog are tracked in
[PARITY.md](PARITY.md) under the divergence notes rather than being
hidden. The standing gaps that matter most for anyone evaluating this
code:

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
- **No fuzzing or sanitizer coverage in CI** beyond the targeted
  `cargo-fuzz` corpora committed for the wire and script codecs.
- **The dependency set has not been audited** (no `cargo audit` /
  `cargo deny` gate yet).

## What this project does instead of a guarantee

Every ported package is tested against dcrd itself — differential
tests through a Go oracle binary that links dcrd's published modules,
plus replays of vectors dumped from inside dcrd's own test packages.
That catches divergence, which is the failure mode this port is most
exposed to. It does not catch a design flaw shared with dcrd, and it
does not substitute for review by someone who did not write the code.
