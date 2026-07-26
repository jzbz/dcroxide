# Quirks ledger

dcrd's behavior at the pinned upstream (master `452c1a6c`, version `2.2.0-pre`)
is the specification — including where it deviates from written documentation
(DCPs, `docs/`). Every intentional reproduction of such a deviation is recorded
here, with a test pinning it so it cannot silently regress; where that test has
since been lost the entry says so. The parity target moved from the
`release-v2.1.5` tag to master during the dcrd 2.2 campaign, and QK-0001 through
QK-0008 were written against the tag; where upstream has changed in that window
the entry keeps its number and records the change rather than being deleted.

Entry format:

```
## QK-NNNN — short title

- **Where:** dcrd package / dcroxide crate + item
- **What:** the behavior, and what the docs/spec say instead
- **Why reproduced:** consensus / wire / RPC compatibility rationale
- **Pinned by:** test name(s)
- **Status:** present only when the entry no longer describes current
  parity, or when nothing pins it any more
```

## QK-0001 — `reject` messages are write-only

- **Where:** dcrd `wire` (v1.7.5) `makeEmptyMessage` / dcroxide-wire
  `message.rs` read-path dispatch
- **What:** dcrd's message reader has no dispatch case for the `reject`
  command, so received reject frames fail with `ErrUnknownCmd` at *every*
  protocol version — yet `MsgReject` still encodes successfully below
  `RemoveRejectVersion` (9). The written docs describe reject as merely
  "removed as of protocol version 9".
- **Why reproduced:** peers that send a reject frame must observe identical
  accept/reject behavior from dcroxide and dcrd (DoS/ban parity, C2).
- **Pinned by:** `reject_frames_are_unknown_to_readers` in
  `crates/dcroxide-wire/tests/frame_differential.rs` (differential against
  the dcrd oracle).

## QK-0002 — mixpool sessions are created with the maximum expiry

- **Where:** dcrd `mixing/mixpool` `acceptKE` / dcroxide-mixing
  `mixpool.rs` `accept_ke`
- **What:** at `release-v2.1.5`, `acceptKE` intends to derive a new
  session's expiry as the minimum expiry of its referenced pair
  requests, but the slice it iterates is never appended to, so every
  session is created with `^uint32(0)`. Sessions therefore never expire
  directly through `ExpireMessages`; they only die when their pair
  requests expire and `removePR` tears the session down.
- **Why reproduced:** relay/expiry behavior must match dcrd's on
  identical message streams (DoS parity), and the session lifetime is
  observable through message retention.
- **Pinned by:** `mixpool_vectors` (the `expire 109`/`expire 110` rows
  show sessions surviving heights below their PR expiries with
  `expiry=4294967295` in the state snapshots)
- **Status:** no longer a reproduction — an outstanding divergence.
  dcrd fixed this in `d11ae7af` ("mixpool: Properly calculate session
  expiry"), which is not in `release-v2.1.5` but is in the current
  parity target: `acceptKE` now folds `pr.Expires()` into the running
  minimum inside the loop over `ke.SeenPRs`. `accept_ke` still creates
  every session with `u32::MAX`, so the port keeps sessions alive past
  the point master retires them, and the pinned vectors pin the
  pre-fix behavior. Tracked; not yet ported.

## QK-0003 — mixpool `Receive` capacity misuse wedges dcrd's pool

- **Where:** dcrd `mixing/mixpool` `Pool.Receive` / dcroxide-mixing
  `mixpool.rs` `receive`
- **What:** dcrd's `Receive` returns its "exactly one Received slice
  must have non-zero capacity" error while still holding the pool's
  read lock, so the next writer deadlocks the pool forever. The
  synchronous port has no lock to leak and simply returns the error;
  the error condition itself (not the deadlock) is the pinned
  behavior.
- **Why reproduced:** the validation order and error identity are
  observable; the deadlock is not reproducible in a synchronous port
  and reproducing it would serve no compatibility purpose.
- **Pinned by:** `mixpool_vectors` (the `receive … twocaps` row, kept
  as the final operation against that pool because generating the
  vectors from dcrd trips the deadlock for any later write)

## QK-0004 — addrmgr never restores serialized address timestamps

- **Where:** dcrd `addrmgr` `deserializePeers` / dcroxide-addrmgr
  `manager.rs` `deserialize_peers`
- **What:** `savePeers` writes each known address's `TimeStamp`, but
  `deserializePeers` builds the loaded address through the string
  parser, which stamps it with the load time, and never applies the
  serialized value. Every address in a loaded `peers.json` therefore
  appears freshly seen, which resets the staleness clock used by
  `isBad`. Go's zero `time.Time` for the attempt/success fields does
  round trip exactly through its `Unix()` encoding.
- **Why reproduced:** address viability and expiry decisions after a
  restart must match dcrd's on identical `peers.json` contents.
- **Pinned by:** `addrmgr_vectors` (the `viability future`/`stale`
  rows show crafted extreme timestamps loading as not-bad because the
  load re-stamps them)

## QK-0005 — the RPC help cacher's usage string ignores the websocket flag

- **Where:** dcrd `internal/rpcserver` `helpCacher.RPCUsage` /
  dcroxide-rpc `help.rs` `HelpCacher::rpc_usage`
- **What:** the cacher stores one usage string and returns it for any
  later call without checking whether it was generated with or
  without the websocket commands. The HTTP `help` handler requests
  the non-websocket form and the websocket `help` handler requests
  the websocket form, so whichever transport asks first fixes the
  usage text both transports serve for the life of the process.
- **Why reproduced:** the `help` RPC output with no arguments must
  match dcrd's under the same request ordering.
- **Pinned by:** `rpchelp_vectors` (the `usage poisoned` row shows a
  websocket-flag request returning the previously cached
  non-websocket text, which differs from the true websocket form)

## QK-0006 — dcrd's ban score decay is platform-dependent

- **Where:** dcrd `internal/connmgr` `decayFactor` (via Go `math.Exp`,
  `dynamicbanscore.go`) / dcroxide-connmgr `banscore.rs` and `goexp.rs`
- **What:** Go dispatches `math.Exp` to assembly on several
  architectures (amd64, arm64, loong64, s390x), and the assembly
  results differ from the portable Go implementation by one ulp on
  276 of the 1801 decay ages the ban score can ever use. The decayed
  component is truncated to a `uint32` after multiplication, so a
  one-ulp difference can change the integer score near boundaries —
  dcrd on amd64 and dcrd built for a portable target can disagree
  with each other. There is therefore no single bit-exact truth; the
  port follows the portable Go source, which is taken as the
  specification here.
- **Why reproduced:** ban thresholds decide peer disconnects and
  bans; the port must have a defined, defensible behavior even
  though dcrd's own is platform-dependent.
- **Pinned by:** nothing, currently.
- **Status:** unpinned. The `connmgr_vectors` test that carried this —
  1801 `decay` rows covering the whole domain bit for bit, plus 21
  `banscore` rows replaying dcrd's own methods on ages where the
  platform assembly agrees with the portable code — was deleted with
  the rest of that file in `5720482`, the rewrite of the crate onto
  dcrd 2.2's `internal/connmgr`. Its replacement,
  `connmgr_v2_vectors`, covers the connection manager and does not
  reach the ban score; `decay_factor_bits` is still exported from
  `dcroxide-connmgr` for the vectors that no longer call it. The
  behavior described above is unchanged in the code and unchanged in
  dcrd at the current target. The rows need regenerating.

## QK-0007 — the Ed25519 certificate generator fails on non-ASCII hostnames

- **Where:** dcrd `certgen` `NewEd25519TLSCertPair` / dcroxide-certgen
  `certgen.rs` `new_ed25519_tls_cert_pair`
- **What:** the ECDSA generator converts a non-ASCII machine hostname
  (and non-ASCII extra hosts) to ASCII with IDNA before placing them
  in the certificate, but the Ed25519 generator was written without
  that handling, so the raw hostname flows into the subject
  alternative name and Go's certificate marshaling rejects it: on a
  machine with a non-ASCII hostname the Ed25519 generator always
  fails with `failed to create certificate: x509: "…" cannot be
  encoded as an IA5String`.
- **Why reproduced:** the generators must succeed and fail on
  identical inputs so a dcroxide daemon behaves like dcrd on the same
  machine.
- **Pinned by:** `certgen_vectors` (the `ed non-ascii-host` row pins
  the exact error text while the `ec idna` row pins the converted
  names in the certificate bytes)

## QK-0008 — an invalid configured user agent is silently discarded

- **Where:** dcrd `peer` `localVersionMsg` / dcroxide-peer `peer.rs`
  `local_version_msg`
- **What:** the local version message is built by appending the
  configured user agent name, version, and comments to the wire
  module's default agent, but dcrd ignores the error returned by
  `AddUserAgent`. When the assembled agent is invalid — over 256
  bytes or containing non-printable characters — the version message
  silently advertises only the default `/dcrwire:1.0.0/` instead of
  failing or truncating.
- **Why reproduced:** the advertised user agent is observable by
  every remote peer and must match dcrd's under identical
  configuration.
- **Pinned by:** `peer_vectors` (the `neg in-ua-overlong` row pins a
  version message carrying only the default agent for a
  configuration with a 300-byte comment)

## QK-0009 — getdata batches of 505 items or fewer cost nothing

- **Where:** dcrd `server.go` `OnGetData` / dcroxide-node `server.rs`
  `getdata_ban_score_increase`
- **What:** the ban score a `getdata` costs its sender is
  `numNewReqs*99/wire.MaxInvPerMsg` in Go integer division, and
  `MaxInvPerMsg` is 50,000. The quotient truncates to zero for every
  batch of 505 items or fewer, so a peer can request 505 items per
  message without limit and never accrue a point; only the size of
  each individual request is ever charged, never the total across
  requests. dcrd's comment on the expression says only that "sustained
  bursts of small requests are not penalized as that would potentially
  ban peers performing the inintial chain sync" — 505 items per
  message, sustained, is not what that describes.
- **Why reproduced:** the score decides disconnects and bans, so it
  must match dcrd's under identical request streams. It is also load
  bearing in the honest direction: at 99 points per full inventory
  message the rate is 0.00198 points per item, and against the 60 s
  half-life and the threshold of 100 the equilibrium sits at ~583
  items per second sustained. Both daemons request blocks in batches
  of `maxInFlightBlocks` (16), which truncates to zero, so dcrd
  charges an honestly syncing peer nothing at all. An earlier revision
  of this port carried the truncated remainder into the next request
  so that repeated 505-item batches were no longer free; that change
  charges an ordinary peer the full per-item rate, and at ~1 KiB
  early-chain blocks 583 blocks/s is ~0.6 MB/s of upload — a peer
  bootstrapping from the node over an unremarkable link would be banned
  partway through the small-block window. It was reverted. What bounds
  this path instead is `MAX_CONCURRENT_GETDATA_REQS`,
  `MAX_PENDING_GETDATA_ITEM_REQS` and `MAX_PENDING_SEND`.
- **Pinned by:** `the_getdata_ban_score_matches_dcrds_truncating_rate`
  in `crates/dcroxide-node/tests/srvgetdata_vectors.rs` (evaluates
  dcrd's expression the way Go does across the domain, pins the 505/506
  boundary at 0 and 1, and drives ten thousand consecutive 16-item
  `getdata` requests through `on_get_data` without the peer ever
  reaching the ban threshold)
