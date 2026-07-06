# Quirks ledger

dcrd's behavior at the pinned tag (`release-v2.1.5`) is the specification —
including where it deviates from written documentation (DCPs, `docs/`). Every
intentional reproduction of such a deviation is recorded here, with a test
pinning it so it cannot silently regress.

Entry format:

```
## QK-NNNN — short title

- **Where:** dcrd package / dcroxide crate + item
- **What:** the behavior, and what the docs/spec say instead
- **Why reproduced:** consensus / wire / RPC compatibility rationale
- **Pinned by:** test name(s)
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
- **What:** `acceptKE` intends to derive a new session's expiry as the
  minimum expiry of its referenced pair requests, but the slice it
  iterates is never appended to, so every session is created with
  `^uint32(0)`. Sessions therefore never expire directly through
  `ExpireMessages`; they only die when their pair requests expire and
  `removePR` tears the session down.
- **Why reproduced:** relay/expiry behavior must match dcrd's on
  identical message streams (DoS parity), and the session lifetime is
  observable through message retention.
- **Pinned by:** `mixpool_vectors` (the `expire 109`/`expire 110` rows
  show sessions surviving heights below their PR expiries with
  `expiry=4294967295` in the state snapshots)

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

- **Where:** dcrd `connmgr` `decayFactor` (via Go `math.Exp`) /
  dcroxide-connmgr `banscore.rs` and `goexp.rs`
- **What:** Go dispatches `math.Exp` to assembly on several
  architectures (amd64, arm64, loong64, s390x), and the assembly
  results differ from the portable Go implementation by one ulp on
  276 of the 1801 decay ages the ban score can ever use. The decayed
  component is truncated to a `uint32` after multiplication, so a
  one-ulp difference can change the integer score near boundaries —
  dcrd on amd64 and dcrd built for a portable target can disagree
  with each other. There is therefore no single bit-exact truth; the
  port follows the portable Go source, which is the specification at
  the tag.
- **Why reproduced:** ban thresholds decide peer disconnects and
  bans; the port must have a defined, defensible behavior even
  though dcrd's own is platform-dependent.
- **Pinned by:** `connmgr_vectors` (the `decay` rows pin the whole
  1801-value domain against the portable algorithm bit for bit, and
  the `banscore` rows replay dcrd's own methods on ages where the
  platform assembly agrees with the portable code, verified at dump
  time)

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
