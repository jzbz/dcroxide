# Quirks ledger

dcrd's behavior at the pinned upstream (master `036b7090`, version `2.2.0-pre`)
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

## QK-0002 — RETIRED: mixpool session expiry (fixed upstream, now ported)

- **Where:** dcrd `mixing/mixpool` `acceptKE` / dcroxide-mixing
  `mixpool.rs` `accept_ke`
- **What it was:** at `release-v2.1.5`, `acceptKE` intended to derive a
  new session's expiry as the minimum expiry of its referenced pair
  requests, but the slice it iterated was allocated and never appended
  to, so the fold ran zero times and every session was created with
  `^uint32(0)`. Sessions therefore never expired directly through
  `ExpireMessages`; they only died when their pair requests expired and
  `removePR` tore the session down. The port reproduced this bug for
  bug, as it does every observable dcrd behaviour.
- **Status:** retired. dcrd fixed it in `d11ae7af` ("mixpool: Properly
  calculate session expiry"), which is not in `release-v2.1.5` but is in
  the `452c1a6c` parity target: the fold moved inside the loop
  over `ke.SeenPRs`, taking the running minimum of `pr.Expires()` over
  the referenced pair requests that are actually known. `accept_ke` now
  does the same, so this is no longer a quirk in either direction — it
  is ordinary agreement with upstream. A KE that references no known
  pair request still yields `u32::MAX`, in both implementations, because
  the fold has nothing to reduce.
- **Pinned by:** `mixpool_vectors`, regenerated from dcrd master so the
  session rows now carry the real minimum expiries rather than
  `4294967295`.

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
- **Pinned by:** `banscore_vectors` (1801 `decay` rows covering ages
  0..1800 bit for bit, plus 21 `banscore` rows replaying dcrd's own
  `Increase`/`int`/`String`/`Reset` on ages where the platform
  assembly agrees with the portable code). The rows carried by
  `connmgr_vectors` were deleted with the rest of that file in
  `5720482`, the rewrite of the crate onto dcrd 2.2's
  `internal/connmgr`; they were regenerated at master `452c1a6c` into
  their own file, since their generator is unrelated to the
  connection-manager exporter's.
- **How the portable values were obtained:** the exporter carries a
  verbatim copy of Go's portable `exp`/`expmulti`/`ldexp`/`normalize`
  from `$GOROOT/src/math` and emits from that, not from `math.Exp`. It
  self-checks two ways: on an assembly arch the copy must disagree
  with `math.Exp` on exactly 276 of the 1801 ages, each by one ulp
  (a run finding zero disagreements would mean the "portable" copy had
  itself been dispatched to assembly); and the same test compiled for
  `GOARCH=386` — which `math/exp_noasm.go` leaves on the portable path
  — must find zero disagreements and write a byte-identical file,
  which checks the transcription against Go's real portable code and
  simultaneously confirms the 21 `banscore` rows land only on
  agreement ages.

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

## QK-0010 — a `mixdcnet` message can decode but not re-encode

- **Where:** dcrd `wire/msgmixdcnet.go` `readMixVects` /
  `writeMessageNoSignature`; dcroxide-wire `msg_mix.rs`
  `read_mix_vects` / `MsgMixDCNet::encode`
- **What:** the two directions disagree about an empty DC-net. On the
  way in, `readMixVects` reads the outer dimension `x`, and when it is
  zero returns immediately with no vectors and no error — the inner
  dimensions are never read and no minimum is enforced. On the way
  out, `writeMessageNoSignature` rejects `mcount == 0` outright with
  `ErrInvalidMsg`. A `mixdcnet` frame declaring zero mix vectors is
  therefore accepted by the decoder and produces a message the encoder
  refuses to serialize, so a node can hold a message it cannot relay.
  The same encoder-side rule guards `MsgMixSlotReserve`
  (`msgmixslotreserve.go:186-190`), but not the asymmetry: its decoder
  enforces `mcount != 0` as well (`:65-68`), so the empty case never
  reaches a message value there.
- **Why reproduced:** decoder acceptance is what decides whether a peer
  is banned for a malformed message, and encoder rejection is what
  decides whether the node relays it. Both are observable to a peer,
  and tightening either one changes behaviour dcrd exhibits: rejecting
  the empty vector at decode would ban a peer dcrd tolerates, and
  accepting it at encode would relay a message dcrd drops.
- **Pinned by:** `qk_0010_empty_mixdcnet_decodes_but_does_not_reencode`
  in `crates/dcroxide-wire/tests/codec_properties.rs`, which asserts
  both halves — the frame decodes to an empty DC-net, and encoding the
  result returns dcrd's `ErrInvalidMsg` identity.
- **Consequence, and the reason it is not only a codec curiosity:**
  dcrd gates those checks on the destination not being a hasher
  (`msgmixdcnet.go:130-145`), and `WriteHash` discards the error it then
  cannot produce (`:113-117`), so dcrd hashes and signs this message and
  pools it. Computing the identity hash through the validating encoder
  instead made the hash fail, and the pool dropped the message at intake
  as an untyped error -- where a bad signature on it is bannable at every
  service level. The port now mirrors dcrd's hashing mode for
  `mixdcnet`; see `an_empty_mixdcnet_hashes_even_though_it_cannot_be_re_encoded`.
  A peer that then requests the pooled message over getdata is
  disconnected on the serve write, because the relay path still refuses
  to encode it -- which is what dcrd does too.
- **How found:** the `wire_frame_structured` fuzz target, within
  seconds of first being run. The older `wire_frame_decode` target
  asserted that every decoded message re-encodes, which is false for
  exactly this case; it never fired because libFuzzer cannot forge the
  BLAKE-256 payload checksum that would let a `mixdcnet` frame reach
  the decoder at all. Both targets now treat an encode failure as an
  acceptable outcome and assert only that a message which *does*
  re-encode decodes back unchanged.

## QK-0011 — dcrd rewrites the tx source's own transactions at height 1

- **Where:** dcrd `internal/mining/mining.go:2185-2221` (the chain-view
  fraud-proof pass) and `:2205-2207` (`dcrutil.NewTxDeepTxIns`);
  dcroxide-mining `generator.rs` `new_block_template`
- **What:** dcrd deep-copies a candidate's inputs before filling in
  their fraud proofs, so the mempool's stored transaction is left
  alone. The height-1 escape is a `break` at the top of that loop's
  body, and it fires *before* the copy — so at height 1 dcrd goes on to
  the second pass holding the tx source's own `*dcrutil.Tx` and writes
  `ValueIn`, `BlockHeight`, and `BlockIndex` straight into it. The
  mempool's copy is mutated by template generation, and its cached
  transaction hash no longer agrees with its bytes, because the fraud
  proof fields are not covered by the hash.
- **Why it does not matter to dcrd:** height 1 is unreachable on any
  live network. Genesis pays a single zero-value output,
  `createChainState` records no utxo entries for it, and zero-value
  spends are rejected (`internal/blockchain/validate.go:3349-3354`), so
  no chain arrives at height 1 with a spendable parent to chain from.
- **What this port does:** clones unconditionally
  (`generator.rs`'s copy ahead of both passes), so the source's
  transactions are never written through. Reproducing dcrd's mutation
  would be reproducing a bug, and one whose only effect is on state
  dcrd itself never reaches.
- **Pinned by:** `the_in_block_fraud_proof_pass_runs_at_height_one` and
  `the_pair_still_resolves_above_height_one` in
  `crates/dcroxide-mining/tests/newtemplate_vectors.rs`, which assert
  the emitted template's inputs while leaving the source untouched.
- **How found:** reviewing the height-1 guard, which wrapped both
  fraud-proof passes here where dcrd guards only the first.

## QK-0012 — `crypto/rand`'s `Read` XORs where its documentation says it fills

- **Where:** dcrd `crypto/rand` `PRNG.Read` (`prng.go:83-105`) /
  `dcroxide-crypto` `rand.rs` `Prng::read`, reached through
  `dcroxide_addrmgr::AddrRng::read`
- **What:** the doc comment is "Read fills s with len(s) of
  cryptographically-secure random bytes" (`prng.go:83`), and the code is
  `p.cipher.XORKeyStream(s, s)` (`:105`) — it XORs the keystream into
  whatever the caller already had. For a zeroed buffer the two are the
  same thing, which is why the difference is invisible at every dcrd
  call site but one.
- **Why reproduced:** that one site decides the address manager's bucket
  key on the reload-after-malformed-peers-file path. `deserializePeers`
  copies the file's key into `a.key` (`addrmgr/addrmanager.go:614`), a
  later
  address entry can still fail, and the fallthrough `a.reset()` (`:586`)
  re-randomizes a key that is no longer zero at `:809`. dcrd's
  replacement key is therefore `file_key XOR keystream`, where a fill
  would give `keystream` alone. Both are uniform to any observer — the
  point is not strength but that the port computes what dcrd computes,
  since the bucket key decides which buckets an address lands in.
- **Pinned by:** `a_second_reset_xors_into_the_key_the_file_supplied` in
  `crates/dcroxide-addrmgr/tests/addrrng_bound.rs`, which drives the
  real reload-failure path, and `read_xors_in_place_as_go_does` in
  `crates/dcroxide-crypto/tests/rand_prng.rs`, which pins the primitive.
- **How found:** porting `crypto/rand` once for both randomness sources,
  where the fill-versus-XOR difference between the port and upstream
  stopped being a detail of two separate implementations.

## QK-0013 — an inbound peer can never corroborate an external address candidate

- **Where:** dcrd `server.go:2591-2614` (`considerReportedAddr`) against
  `server.go:2557-2558` (`considerReportedAddrOutbound`) / dcroxide-node
  `server.rs` `consider_reported_addr`
- **What:** the outbound path stores a candidate under the bare IP
  (`addr.IP.String()`, e.g. `8.8.8.8`), while the inbound path looks one up
  under `net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))`
  (e.g. `8.8.8.8:9108`, `[2001:4860:4860::8888]:9108`). The two key spaces are
  disjoint — the joined form always carries `:<port>` and brackets IPv6, the
  bare form never does — so the lookup always misses and an inbound peer can
  never increment a score. The cache's own doc comment says the opposite:
  "inbound peers can only corroborate addresses that have otherwise already
  been discovered", describing a corroboration path that cannot fire. The miss
  is not entirely silent: because the code calls `Get` rather than `Peek`, it
  still ticks the LRU's miss counter and moves its hit ratio, so the port uses
  `get` there too.
- **Why reproduced:** it sets how many reports it takes to move an address over
  the 60% majority in `considerReportedAddrOutbound`. Making the inbound lookup
  work would let inbound peers — who choose to connect to us, and are therefore
  the cheap ones for an attacker to supply in bulk — corroborate an
  attacker-chosen external address that dcrd would require outbound peers to
  agree on. dcroxide must be neither stronger nor weaker than dcrd here; the
  dead path is the specification. The port previously keyed the inbound lookup
  on the bare IP, so its corroboration worked and it was accidentally stronger
  than upstream.
- **Pinned by:** `server_external_addresses_match_dcrd` in
  `crates/dcroxide-node/tests/srvextaddr_vectors.rs` — rows `ecra|beforeinbound`
  and `ecra|afterinbound` (inbound reports leave the score untouched) and
  `ecrakey|v4`/`ecrakey|v6` (the two key forms). Keying the inbound lookup on
  the bare IP fails `ecra|afterinbound`, verified by reverting it.
- **How found:** re-porting the subsystem from `release-v2.1.5`'s shape to the
  parity pin, where the two key forms sit four lines apart.
