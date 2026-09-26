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
port syncs about 1.29x slower than dcrd (measured 2026-08-15; the
2.2x quoted through 2026-07 is superseded) and spends much of an
initial block download stalled in storage commits. Both are measured
and self-inflicted. That the cost is the storage engine's commit shape
rather than validation was measured on 2026-08-15: the port drives
11.7x the kernel-side storage work dcrd does for the same chain, blocks
30x more per GiB written, and is fully stalled on storage for roughly
48% of block-sync wall time against dcrd's 0.9% — 90–98% of that inside
a metadata-flush window. Either way it is work the node does to itself
rather
than work a peer can add to, so there is nothing here for a peer to
amplify.

## Known gaps

The project runs its own internal security review. A campaign closing
its release-blocking findings landed this cycle — bounds on the peer
message path, authentication and admission on the RPC surface,
owner-only permissions on the secret files the daemon generates for itself,
OS-seeded CSPRNGs, and the panic policy below. Every fix, the reasoning
behind it, and the divergences from dcrd it introduced are itemized in
[PARITY.md](PARITY.md) under "Deliberate divergences from dcrd" and its
"Known remaining gaps" subsection, rather than being hidden. What
follows is the residue: the standing gaps that matter most for anyone
evaluating this code.

- **A data directory written before the treasury-commit fix may hold a
  hole.** Until the treasury rows moved into the block connect path's
  single transaction, a crash could leave a durable best state whose
  treasury balance row was not, and `calculate_treasury_balance` reads a
  missing row as zero for that block and every descendant. New writes
  are atomic, but existing directories are not scanned or repaired on
  startup. Re-sync rather than carry one forward.

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
  looking healthy. One latent source of such panics sits on the RPC
  surface. The seam traits in `dcroxide-rpc` (`server.rs`,
  `websocket.rs`) still give 61 methods an `unimplemented!()` default,
  and the public `impl … for ()` stand-ins the tests use inherit them.
  Every adapter the daemon wires in overrides them today, so none is
  reachable, but an adapter that later misses one would still compile,
  and the first RPC to reach that method would abort the node. Making a
  missing override a compile error needs the `()` stand-ins moved behind
  a test-support feature and the test doubles made explicit; that has not
  been done.
- **A websocket client that stops reading grows node memory without
  bound.** The notification queues are unbounded, exactly as dcrd's are,
  so nothing is ever dropped and nothing is reordered — the whole cost of
  a slow or stalled subscriber is paid in node memory. Since RPC access
  requires credentials this is not reachable unauthenticated, and adding
  a cap would diverge from dcrd while cutting off honest clients on slow
  links, so it stays. Operators running many subscribers, or exposing the
  websocket to clients they do not control, should bound the process
  (a memory limit plus a supervisor) rather than expect the node to shed.
  The port-specific amplifier this used to carry — a single long request
  holding a lock that stalled notification construction for every other
  client — is fixed: the server-wide lock is gone, and the per-client
  lock is now taken a field at a time where it is used, as dcrd takes
  its own, rather than across the whole request.
- **Unauthenticated websocket clients can hold every websocket slot.**
  The `/ws` upgrade needs no credentials: a client may authenticate
  in-band later, and nothing makes it do so in time. From its upgrade it
  counts against `rpcmaxwebsockets` (25 by default), and it has no read
  deadline. So that many silent connections from any host that can reach
  the RPC port lock every later websocket client out, dcrwallet included,
  until they close. dcrd behaves identically: `WebsocketHandler` clears
  the read deadline and counts the client before it authenticates
  (`rpcwebsocket.go:109-130`). The port reproduces it rather than add an
  authentication deadline dcrd does not have. The pre-authentication
  admission pool bounds only the HTTP handshake; it releases the
  connection once the upgrade completes. Bind the RPC listeners to
  trusted interfaces, or firewall them, and raise `rpcmaxwebsockets` if
  untrusted hosts can reach them.
- **Any host that can reach the RPC port can drive the
  authentication-failure warning.** `RPC authentication failure from
  <addr>` is logged for every wrong credential, and for every HTTP request
  that carries none, as dcrd's `checkAuthMAC` and `checkAuth` log it, so
  a client without credentials drives that warning at its request rate.
  It is deliberately not rate-limited like the `Max RPC clients exceeded`
  shed line: fail2ban-style filters count these lines, and a limiter
  would hide the attempts they exist to catch. Nothing bounds it beyond
  what bounds the requests themselves, the admission caps
  (`rpcmaxclients` and the pre-authentication pool). Bind the RPC
  listeners to trusted interfaces, or rotate logs, if that volume
  matters.
- **Seeder TLS roots are compiled in.** The HTTPS seeder clients verify
  certificates against the `webpki-roots` snapshot built into the
  binary, not against the operating system's trust store that dcrd's Go
  client uses. A root the OS distrusts after the build stays trusted
  until a rebuild, and a locally installed root, such as an enterprise
  TLS-inspection CA or a private `SSL_CERT_FILE`, is not honoured, so
  behind such a proxy the node cannot seed. Seeders are how a fresh node
  bootstraps its peer list, which makes this trust anchor
  security-relevant; see PARITY.md's open gaps.
- **RPC TLS uses classical key exchange.** dcrd leaves Go's default
  key-exchange preferences in place (`newTLSConfig`,
  `server.go:3685-3688`), which since Go 1.24 put hybrid X25519MLKEM768
  first, so it negotiates that with Go clients such as dcrctl and
  dcrwallet. This daemon negotiates plain X25519, because its rustls
  `ring` provider has no ML-KEM. RPC sessions recorded on a non-local
  `--rpclisten` are therefore exposed to harvest-now-decrypt-later
  attacks that dcrd's resist, including the Basic credentials sent with
  every request. See PARITY.md's open gaps.
- **Descriptor use is several times dcrd's.** The daemon spends several
  descriptors per peer and RPC connection where dcrd spends one, and
  keeps a read handle open for every block file it has touched where
  dcrd caps open block files at 25. It raises its soft `RLIMIT_NOFILE`
  as dcrd does, so this matters only where an operator has set the hard
  limit low, to a few thousand. There, a peer and RPC flood can exhaust
  descriptors sooner than it would against dcrd. A block-file reopen
  failing then latches the database fatal: the node keeps running and
  answering RPC, but stops connecting blocks until it is restarted.
  Details are in PARITY.md's open gaps.
- **Fuzzing reaches the stateless parsers, not the state machines.**
  Seventeen `cargo-fuzz` targets run for 60 seconds apiece on every push
  to `master` and every pull request, and for ten minutes apiece
  nightly: wire framing, decoded at every protocol version a peer can
  negotiate (9 through 12); the `tx` and `blockheader` decoders, with
  stake classification (`DetermineTxType` and the `Check*`/`Is*`
  family) run over every decoded transaction; the script engine;
  everything the RPC server does with a request before it
  authenticates (the HTTP head parser, the mux's routing and redirect,
  the websocket handshake's header and origin checks, and the discard
  of a refused request's body, chunked decoding included); the
  websocket frame reader; the JSON-RPC request path (Go-JSON
  validation, batch splitting, request unmarshalling, the reply
  envelope, and parameter decoding against each registered method's Go
  types, which a mode that writes the envelope around the fuzzer's
  `params` reaches); base58, base58check and address decoding (a mode
  that check-encodes a chosen address ID and payload gets past the
  checksum to the address dispatch); the chain database's stored-row
  decoders; `chainhash` parsing; DER signature parsing; public-key
  parsing; the Schnorr and Ed25519 suites; `uint256`; and BLAKE-256.
  Stateless parsers still unfuzzed: the config-file and command-line
  parser, which takes the operator's input rather than a peer's, GCS
  filter decoding, and the ticket, index and address-manager stores.
  The stateful surfaces are unfuzzed too — the JSON-RPC and websocket
  dispatch, the peer and sync state machines, the mempool, the
  database — and those are where a reachable panic or an unbounded
  allocation is most likely to survive review. The targets build with
  overflow checks on, `cargo fuzz`'s default, so a site where Go wraps
  and the port writes a plain operator fails them even though the
  release build wraps; that is the point, since such a site makes
  debug and test builds disagree with the shipped binary. No corpus is
  committed (`fuzz/corpus` is ignored), so every run starts cold and
  has to rediscover structure inside its budget. Those jobs are also
  the only sanitized build in CI, since `cargo fuzz` defaults to
  AddressSanitizer; neither the test suite nor a running node is run
  under a sanitizer.
- **The Windows build runs unsafe code of the project's own.** Every
  workspace crate forbids `unsafe_code` except `dcroxide-winsvc`, which
  denies it and holds the one audited exception: three Windows-only unsafe
  blocks, each allowed individually and carrying a `SAFETY` comment. One
  registers the console control handler that holds a console close, logoff
  or shutdown until the daemon has shut down. The other two duplicate an
  inherited `--piperx` or `--pipetx` pipe handle and take ownership of the
  duplicate. The handle is duplicated rather than adopted because the number
  comes from the command line: a number that names no open handle, or one
  another part of the process owns, then fails or yields a handle of the
  daemon's own instead of a double close. Non-Windows builds compile none of
  it. CI's Windows job runs the handle adoption and the handler's
  registration. Nothing automated raises a real console close, logoff or
  shutdown event, which needs an interactive Windows console, so the path
  Windows takes through the handler is exercised only by unit tests of its
  logic.
- **Nobody has read the dependencies.** `cargo-deny` does run on every
  push to `master` and every pull request against `deny.toml`, gating
  the RustSec advisory database, a licence allow-list, yanked crates,
  and unknown registries or git sources. That is an automated check
  against a list of problems someone else already found; it is not a
  review. Almost nothing in the tree has been read — one ledger entry
  is marked `reviewed@`, and one more was read in a single respect —
  and the tree includes the elliptic-curve implementations, the TLS
  stack, and the storage engine that this node's key handling and
  on-disk consensus state rest on.
  [docs/dependency-ledger.md](docs/dependency-ledger.md) does not close
  this gap, but it bounds it: the twelve crates that are consensus-
  observable or touch key material now carry an explicit decision each,
  so their trust status is stated rather than assumed and a version bump
  of one of them is a decision rather than a silent lockfile change.
  Most of those decisions are still "accepted without a read." The
  storage engine exercised that bound this cycle: redb went 2.6.3 to
  4.1.0 on 2026-08-13, across two majors and a changed on-disk format,
  argued in ADR-0004's upgrade addendum rather than arriving as a
  lockfile change. It is maintenance, not hardening. 4.1.0 carried four
  known issues, none a regression against 2.6.3 and all concerning a
  file that is already damaged or hostile. The lock now pins 4.3.0, and
  redb 4.2.0 shipped a fix for three of them, each with a regression
  test that names the issue: #1331, an unvalidated 5-bit page order
  that aborted the process, and #1332, a cyclic branch pointer reached
  from ordinary reads, are now reported as corruption — as an error on a
  point read of a UTXO row and on the UTXO stats walk; as absence on
  other point reads, as ffldb's `Get` discards a store error; and on
  other bucket walks by ending the store's side of the walk, as ffldb's
  cursor treats an iterator error (before 2026-09-23 such a walk skipped
  the error and spun forever on redb's repeated `PreviousIo`) — and
  #1333, a repair-path panic that left a file permanently unopenable, now
  returns an error for the corrupt freed-page entry that caused it.
  Read-path checksum verification is not in 4.3.0: reads do not compare
  page checksums, which redb checks only when `check_integrity` or
  repair walks whole trees. Some damage still aborts the process, too —
  a page whose type byte is neither leaf nor branch reaches an
  `unreachable!()` in redb's btree descent, and this workspace builds
  with `panic = "abort"`.

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
the opposite of what the code beneath them did — and a later sweep
retired twelve more — including one that
justified a coarse server-wide lock as dcrd's own per-request locking,
where dcrd takes no server-wide lock at all. Comments in this
repository are claims, not evidence. (That lock has since been removed:
the RPC server now carries dcrd's per-field locks, and the handler seams
take `&self`. See PARITY.md's websocket-delivery note.)
