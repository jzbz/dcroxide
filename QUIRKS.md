# Quirks ledger

dcrd's behavior at the pinned upstream (master `b9634e01`, version `2.2.0-pre`)
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
  non-websocket text, which differs from the true websocket form);
  `racing_callers_on_a_cold_cache_agree_on_one_usage_text` in
  `crates/dcroxide-rpc/tests/review_help_usage_race.rs` (an HTTP-flag
  and a websocket-flag caller racing a cold cache both receive the
  variant the first to take the lock generated, as dcrd's mutex held
  across `RPCUsage` guarantees)

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
  (and non-ASCII extra hosts) to ASCII with Go's `idna.ToASCII` (the
  bare Punycode profile, which keeps ASCII case) before placing them
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
  names in the certificate bytes; the `ec idna-case`, `ec idna-bidi`
  and `ec idna-badpuny` rows pin the Punycode profile: ASCII case
  kept, names UTS-46 refuses converted, and an invalid `xn--` label
  as an error)

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
  spends are rejected (`internal/blockchain/validate.go:3399-3402`), so
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
  `ecrakey|v4`/`ecrakey|v6` (the two key forms), and at the live-path level by
  `an_inbound_peers_reported_address_corroborates_nothing` in
  `crates/dcroxide-node/tests/srvextaddr_wired.rs`. Keying the inbound lookup
  on the bare IP fails both, verified by reverting it.
- **How found:** re-porting the subsystem from `release-v2.1.5`'s shape to the
  parity pin, where the two key forms sit four lines apart.

## QK-0014 — `--maxpeers` yields two different outbound targets, which disagree

- **Where:** dcrd `server.go:4132-4142` (the netsync target) against
  `server.go:3927` / `:4273-4274` (the server field), both downstream of
  `server.go:3931-3932` / dcroxide-node `server.rs`
  `netsync_max_outbound_peers` and `server_target_outbound`
- **What:** `newServer` derives an outbound target from `cfg.MaxPeers` twice,
  140 lines apart, and the two are not the same computation written twice. The
  netsync target compares in signed space and widens afterwards (`if
  cfg.MaxPeers < targetOutbound`, then `uint64(targetOutbound)`); the server
  field converts first and compares unsigned (`if uint32(cfg.MaxPeers) <
  s.targetOutbound`). Nothing validates `--maxpeers`, and the two disagree in
  *opposite* directions:

  | `--maxpeers` | server field | netsync target |
  | --- | --- | --- |
  | `-1` | 8 | 18446744073709551615 |
  | `4294967296` | 0 | 8 |

  The catch, and the reason this is a quirk rather than a live divergence, is
  that **dcrd cannot reach either line for any input where they disagree.**
  Two hundred lines earlier `newServer` builds its relay and broadcast queues
  as `make(chan relayMsg, cfg.MaxPeers)` and `make(chan broadcastMsg,
  cfg.MaxPeers)` (`server.go:3931-3932`), and Go's `make` takes the capacity
  as a signed `int`: every negative value raises `panic: makechan: size out of
  range`, and every value large enough to matter dies as `fatal error:
  runtime: out of memory`. Nothing on dcrd's startup path recovers either. So
  upstream the two targets agree wherever dcrd survives to compute them, and
  where they disagree the process is already gone.
- **Why reproduced:** dcroxide has no such queues — relay and broadcast are
  synchronous fan-outs over the peer registry — so unlike dcrd it *does* reach
  both computations for every input, and cannot dodge the question of which
  one is right by dying first. Reproducing both is the only option that is
  correct for whichever value the port ends up observing: the server field
  reaches `connmgr.Config.TargetOutbound` and the version handler's
  mix-capable rejection at `server.go:1016`, while the netsync target only
  gates a "no sync peer candidates" warning
  (`internal/netsync/manager.go:632`). Collapsing the two into one shared
  value is the obvious tidy-up and is wrong: it silently changes one of them.
  What the port should do about surviving inputs that kill dcrd outright is a
  separate question, tracked in PARITY.
- **Pinned by:** `target_outbound_arithmetic_matches_dcrd` and
  `the_two_targets_disagree_in_both_directions` in
  `crates/dcroxide-node/tests/srvtargetout_vectors.rs`, against rows dumped
  from in-package Go tests at the pin whose expressions are copied verbatim
  from `server.go`. Rewriting either helper to the other's shape fails the
  replay, verified by doing it. The `mpchan|` rows record what dcrd's
  `newServer` actually does with each `--maxpeers` — which of them panic,
  which exhaust memory, and which allocate — measured by running the real
  `make` calls with the real element types, each in its own subprocess because
  the out-of-memory death is not recoverable.
- **How found:** auditing the three `target_outbound` computations left
  inconsistent by `39d4f16`, which fixed one of them without asking why the
  others differed. The channel allocation turned up only on a sweep for
  consumers nobody had accounted for, and inverted the reading: the arithmetic
  the audit set out to fix is arithmetic dcrd never executes.

## QK-0015 — a block linked by a fast-added parent skips the full context checks

- **Where:** dcrd `internal/blockchain/process.go:366-396`
  (`maybeAcceptBlocks`), `validate.go:1937-1940` (`checkBlockContext`'s
  cache short circuit) and `chain.go:1219-1230` (the reorganization attach
  loop) / dcroxide-blockchain `process.rs` `maybe_accept_blocks`,
  `reorganize_chain_internal`, `RecentContextChecks`
- **What:** `ProcessBlock` sets `BFFastAdd` when the processed block is an
  assumed-valid ancestor or arrives in bulk import mode
  (`process.go:518-522`), and passes the same flags to `maybeAcceptBlocks`
  for every block the new data links, including stored descendants that
  are not assumed-valid ancestors themselves. Each of them is
  context-checked with `BFFastAdd`, which skips transaction finality, vote
  and revocation eligibility, and the treasury spend interval and expiry
  checks, and its hash goes into `recentContextChecks`. The descendant is
  never marked validated, so the attach loop calls `checkBlockContext` with
  `BFNone` for it, but that call returns early on the cache hit. The
  full-flag context checks therefore never run for such a block;
  `checkConnectBlock` still does.
- **Why reproduced:** consensus verdict parity. Without the cache the port
  ran the full-flag checks on attach and could reject a block dcrd
  accepts: a block right after the assume-valid block, stored before that
  block arrived.
- **Pinned by:** `process::tests::recent_context_checks_is_a_bounded_lru_set`
  and `process::tests::accepted_blocks_are_recorded_and_invalidation_forgets_them`
  in `crates/dcroxide-blockchain/src/process.rs`, which pin the cache and
  its wiring. The fast-add interaction itself has no crafted-block test.

## QK-0016 — the new-rules unmarking of failed blocks never reaches disk

- **Where:** dcrd `internal/blockchain/chainio.go:1494-1502`
  (`loadBlockIndex`) and `:1776-1793` (`initChainState`),
  `blockindex.go:733-751` (`addNodeFromDB`) and `:1411` (`Flush`) /
  dcroxide-blockchain `process.rs` `load_chain_state`,
  `Chain::open_with_config`
- **What:** when new consensus rules are detected, `loadBlockIndex` clears
  `statusValidateFailed`/`statusInvalidAncestor` on blocks whose median
  time is at or after the new rules' start time. `initChainState` then
  flushes the block index "since blocks may have been unmarked" before it
  advances the deployment version. The nodes go in through
  `addNodeFromDB`, which never marks them modified, so that flush finds an
  empty modified set and writes nothing: the cleared statuses live in
  memory only, although dcrd's comment says the flush saves them. After
  the version advances, a second restart reloads the block as failed,
  unless it was revalidated or had its ticket info reloaded (which marks
  it modified) in the meantime.
- **Why reproduced:** consensus and RPC parity. After the second restart
  the block's stored status bytes, its `getchaintips` status, the
  `ErrKnownInvalidBlock`/`ErrInvalidAncestorBlock` verdicts and its
  eligibility for chain selection all follow the on-disk status, so
  persisting the unmark would make the port accept and select blocks a
  restarted dcrd refuses.
- **Pinned by:** `the_new_rules_unmark_stays_in_memory_as_in_dcrd` in
  `crates/dcroxide-blockchain/tests/blockindex_restart.rs`, which fails a
  block, rewinds the stored deployment version, and checks that the open
  running the pass clears the flag in memory while the next open reloads
  it as failed.

## QK-0017 — a tx-index drop interrupted between its last two commits can never finish

- **Where:** dcrd `internal/blockchain/indexers/txindex.go:616-679`
  (`dropBlockIDIndex`, `DropTxIndex`) / dcroxide-indexers `txindex.rs`
  `drop_tx_index`, `drop_block_id_index`
- **What:** the drop runs three write transactions: the batched flat drop
  of `txbyhashidx`, then `dropBlockIDIndex`, which deletes `idbyhashidx`
  and `hashbyididx`, then `dropIndexMetadata` (tip, version, drop marker).
  `dropBlockIDIndex` fails with ffldb's `ErrBucketNotFound` when either
  bucket is already gone, while `dropIndexMetadata` tolerates a missing
  main bucket (`common.go:278-279`). A crash after the block-ID deletion
  is durable and before the metadata removal is leaves the drop marker
  behind, and every later resumed drop (`finishDrop` on a `--txindex`
  start, or `--droptxindex`) then fails at `dropBlockIDIndex`. The
  transaction index can then be neither dropped nor rebuilt without
  editing the database by hand. The window is real: the block-ID deletion
  removes two rows per indexed block (one in each bucket, about 2.2M on
  mainnet) in one commit, which is likely to trip a cache flush, while the
  small metadata commit right after it may not.
- **Why reproduced:** tolerating the missing buckets would change only how
  an otherwise permanent local failure resolves, and nothing a peer or RPC
  client sees. It is still a change to dcrd's drop state machine, so it is
  left as an explicit decision rather than taken silently.
- **Pinned by:** `a_drop_resumed_after_the_block_id_buckets_went_fails_as_in_dcrd`
  in `crates/dcroxide-indexers/src/txindex.rs` (two resumed drops both fail
  with `BucketNotFound`, and the drop marker survives each).

## QK-0018 — a template build keeps the pre-reorganization best snapshot

- **Where:** dcrd `internal/mining/mining.go` `NewBlockTemplate`
  (`best := g.cfg.BestSnapshot()` at `:1200`; the eligible-parents loop at
  `:1265-1290`, which calls `ForceHeadReorganization` at `:1271` and then
  sets only `prevHash = *newHead` at `:1288`) / dcroxide-mining
  `generator.rs` `BlkTmplGenerator::new_block_template`
- **What:** the best chain snapshot is taken once, before the
  eligible-parents loop that may reorganize to a sibling tip with more
  votes. After the reorganization only `prevHash` changes; vote
  eligibility (`best.NextWinningTickets`, `:1723`), the ticket price filter
  (`best.NextStakeDiff`, `:1629`) and the header's `FinalState`,
  `PoolSize` and `SBits` (`:2274-2280`) all keep reading the old tip's
  snapshot. The sibling's lottery winners differ from the old tip's, so
  every vote on the new head fails the eligibility check, the build ends
  with too few voters, and `handleTooFewVoters` (`:2178`) recycles the new
  tip from a fresh snapshot.
- **Why reproduced:** refreshing the snapshot after the reorganization
  would accept the sibling's votes and build on it at the next height,
  changing which templates the node produces in exactly the case dcrd
  recycles.
- **Pinned by:** `a_reorganized_build_keeps_the_old_snapshot_and_recycles_the_new_tip`
  in `crates/dcroxide-mining/tests/review_template_queue.rs`, which fails
  with a height-5001 template if `best` is re-read after the loop.

## QK-0019 — the network time offset stops moving once 200 peers have reported

- **Where:** dcrd `internal/blockchain/mediantime.go:141-155`
  (`AddTimeSample`) / dcroxide-node `mediantime.rs`
  `MedianTime::add_time_sample`
- **What:** the median offset is recomputed only when the sample count is
  odd and at least five, but the cap is 200, an even number. Once the cap
  is reached, each new sample evicts the oldest and leaves the count at
  200, so the offset never changes again for the life of the process. Each
  source address (port included) contributes at most once. dcrd's own
  comment calls this the buggy behaviour of Bitcoin Core, kept on purpose.
- **Why reproduced:** the adjusted time feeds consensus (the +2 h
  `ErrTimeTooNew` header limit) and the is-current latch. A node deriving
  the offset differently would accept or reject near-future headers at a
  different moment than its dcrd peers.
- **Pinned by:** `median_time_matches_dcrd` in
  `crates/dcroxide-node/src/mediantime.rs` (dcrd's `TestMedianTime` table,
  including its capped-at-ten rows).

## QK-0020 — dcrd never logs a failed peer write

- **Where:** dcrd `peer` `outHandler` (`peer/peer.go:1786-1797`) and
  `shouldLogWriteError` (`:1742-1758`) / dcroxide-node `peerloop.rs`
  `run_peer_connection_with_stall` (the output thread)
- **What:** on a failed write, `outHandler` calls `p.Disconnect()` and only
  then asks `p.shouldLogWriteError(err)`. `shouldLogWriteError` returns
  false whenever the disconnect flag is set, so "Failed to send message to
  %s: %v" is dead code: no write failure is ever logged, including one
  from the write deadline `writeMessage` sets (`:1037`). The code reads as
  though temporary, non-EOF errors were meant to be logged.
- **Why reproduced:** operator-visible log parity. A port that added the
  line would log where dcrd is silent.
- **Pinned by:** nothing. The absence of a log line is not observable to
  the test suite, which has no log capture seam. The reasoning is recorded
  in a comment at the output thread.

## QK-0021 — dcrd never logs a failed socket read, and its idle-peer warning is dead

- **Where:** dcrd `wire.ReadMessageN` (`wire/message.go:375-377`,
  `:457-459`), `peer` `inHandler` (`peer/peer.go:1556-1567`) and
  `shouldHandleReadError` (`:1054`) / dcroxide-node `peerloop.rs`
  `read_error_to_log`
- **What:** since `04fef0bf` ("wire: Optimize message reads"),
  `ReadMessageN` reads the header and the payload through an
  `io.LimitedReader` and replaces the error with `io.EOF` whenever the read
  came up short (`if lr.N > 0 { err = io.EOF }`). A read deadline
  expiring, a reset, a local close and a remote close mid-message all
  reach `inHandler` as `io.EOF`. `shouldHandleReadError` declines
  `io.EOF`, so "Can't read message from %s: %v" is never logged for a
  socket failure. The "Peer %s no answer for %s -- disconnecting" warning,
  which tests the error for a `net.Error` timeout, can never fire, so an
  idle peer is dropped without a word. The `inHandler` code reads as though
  timeouts and non-EOF socket errors were meant to be reported. "Can't read
  message" remains only for codec failures, and not even for those when the
  server's `OnRead` ban has already disconnected the peer (`BanPeer` calls
  `Disconnect` inside `readMessage`), or when a payload ends on a field
  boundary, since `BtcDecode` then returns `io.EOF` itself (the port still
  logs that case; see PARITY.md's open gaps).
- **Why reproduced:** operator-visible log parity. Porting the warning
  would log a line on every idle disconnect, where dcrd is silent.
- **Pinned by:** `read_failures_are_logged_as_dcrd_logs_them` (a real
  transport timeout, a closed stream and an OS socket error log nothing; a
  codec failure logs unless the teardown flag is up) and
  `a_banned_wire_violation_is_not_logged_as_a_failed_read`, both in
  `crates/dcroxide-node/src/peerloop.rs`.

## QK-0022 — a banned onion peer is never refused before its handshake

- **Where:** dcrd `server.go:2187-2205` (`handleBannedConn`) and
  `:2752-2765` (`BanPeer`) / dcroxide-node `runtime.rs` `banned_conn_host`
  (the outbound pre-handshake ban check in `serve_outbound_peer`)
- **What:** dcrd keys the pre-handshake ban check on
  `net.IP(remoteAddr.IP).String()`. For a Tor v3 address the IP field is
  the 32-byte public key, which is neither IP length, and Go renders it as
  `?` followed by its hex. `BanPeer` records the ban under the host of the
  peer's `Addr()`, which is the `.onion` name. The two keys never match, so
  a banned onion peer is dialed, handshaken and served again.
- **Why reproduced:** P2P parity: dcroxide refuses and serves onion peers
  exactly when dcrd does.
- **Pinned by:** `an_onion_peer_gets_dcrds_address_forms` in
  `crates/dcroxide-node/src/runtime.rs`.

## QK-0023 — a failed `peers.json` load keeps the address counts it had reached

- **Where:** dcrd `addrmgr/addrmanager.go:805-829` (`reset`) on
  `loadPeers`' failure path (`:577-587`), with the counters raised in
  `deserializePeers` (`:647` `a.nNew++`, `:663` `a.nTried++`) /
  dcroxide-addrmgr `manager.rs` `AddrManager::reset`, `load_peers`
- **What:** `reset` rebuilds the address index, the bucket maps and their
  per-type statistics, and re-keys the manager, but it never touches `nNew`
  or `nTried`. `deserializePeers` raises both while it walks the bucket
  lists, and it can still fail afterwards: on a later bucket entry naming
  an unknown address (`:642`, `:658`), or at the sanity checks for an
  address with no references or one in both a new and a tried bucket
  (`:669-680`). `loadPeers` then removes the file and calls `reset`, so the
  process runs on the counts of a file it threw away, over an empty index.
  `numAddresses()` (`nTried + nNew`) is the value `NeedMoreAddresses`
  compares against 1000. That comparison gates dcrd's getaddr on every
  outbound handshake (`server.go:2657`) and its seeder retry loop
  (`server.go:3405`). `GetAddress` is unaffected because the bucket
  statistics are reset.
- **Why reproduced:** the counts decide whether dcrd asks peers and seeders
  for addresses for the rest of the run, which peers can observe. With
  1000 or more addresses counted before the failure, dcrd stops asking
  entirely. The port zeroed both counters in `reset` and kept asking.
  QK-0012 already reproduces this path's key derivation bit for bit.
- **Pinned by:** `a_failed_load_keeps_the_counts_dcrd_keeps` in
  `crates/dcroxide-addrmgr/tests/review_peers_load.rs`. The file has 1000
  new addresses, one of them also tried. The load fails, the index is
  empty, `n_new`/`n_tried` stay at 1000/1, and `need_more_addresses` is
  false.
- **How found:** the 2026-09-23 review.

## QK-0024 — a batch reply that fails to marshal stops dcrd reading the websocket client, which stays connected

- **Where:** dcrd `internal/rpcserver` `wsClient.inHandler` batch arm
  (`rpcwebsocket.go:1753-1758`) / dcroxide-node `websocket.rs`
  `handle_ws_batch_entry`, `handle_ws_batch`, `serve_ws_reads`
  (`WsOutcome::StopReading`) and `park_without_reading`
- **What:** every other marshal failure in `inHandler` logs and
  `continue`s, but the one after a batch entry's command has run is a bare
  `return` out of `inHandler` itself. The replies already collected for the
  batch are never sent and the entries after it never run. Nothing reads
  the client again, and because the `return` skips the trailing
  `c.Disconnect()` (`:1800`), the connection stays open and registered: its
  subscriptions stay in place, `outHandler` keeps delivering
  notifications, and it keeps its `rpcmaxwebsockets` slot until a write
  fails or the server shuts down (`Run`'s select, `:2019-2023`). The
  single-request arm's `serviceRequest` only logs and drops such a reply
  (`:1821-1826`). Two things make `MarshalResponse` fail there: an id of
  `true`, `[]` or `{}`, which `dcrjson.Request` accepts into its
  `interface{}` ID and `NewResponse` refuses (`IsValidIDType`), open to any
  authenticated client; and a result `json.Marshal` refuses, such as
  getvoteinfo's `0/0` choice progress.
- **Why reproduced:** RPC wire parity. A client that batches requests must
  see the same thing from both daemons: no reply to the batch and none to
  anything sent after it, while notifications keep arriving; replying to
  the other entries would be a visible divergence. The cost is dcrd's own
  and no more than an idle client's: dcrd sets no read deadline on
  websocket connections, so an authenticated client can hold one open
  indefinitely anyway, and a parked client holds the same websocket slot
  and the same two threads an idle one does.
- **Pinned by:** `a_batch_reply_that_fails_to_marshal_stops_reading_the_client`
  and `a_single_reply_that_fails_to_marshal_is_only_dropped` in
  `crates/dcroxide-node/tests/review_ws_batch_marshal.rs`.

## QK-0025 — a websocket client that authenticates in a batch keeps the 4 KiB read limit

- **Where:** dcrd `internal/rpcserver` `wsClient.inHandler`
  (`rpcwebsocket.go:1488-1497` single arm, `:1698-1716` batch arm) /
  dcroxide-node `websocket.rs` `serve_ws_reads`, `handle_ws_single`
- **What:** dcrd raises the gorilla read limit from
  `websocketReadLimitUnauthenticated` (4 KiB) to
  `websocketReadLimitAuthenticated` (16 MiB) only in the single-request
  `authenticate` arm. The batch arm checks the same credentials and sets
  `authenticated`/`isAdmin`, but never calls `SetReadLimit`. A client that
  authenticates inside a batch therefore keeps the 4 KiB limit for the
  rest of the connection: its first message over 4 KiB draws a 1009 close
  and a disconnect. The code's own comment ("Increase the read limits for
  authenticated connections") states the intent the batch arm misses.
- **Why reproduced:** RPC wire parity. Which messages a batch-authenticated
  client may send before being dropped is observable. Standard clients
  authenticate with a Basic header or the single-request form and never
  meet it.
- **Pinned by:** `a_batch_authenticate_keeps_the_unauthenticated_read_limit`
  in `crates/dcroxide-node/tests/review_ws_conn.rs`.

## QK-0026 — a disconnected websocket client stays in the mix-message subscriptions

- **Where:** dcrd `internal/rpcserver`
  `wsNotificationManager.notificationHandler`, `notificationUnregisterClient`
  case (`rpcwebsocket.go:563-573`) / dcroxide-node `websocket.rs`
  `NodeNtfnMgr::remove_client`
- **What:** when a client disconnects, dcrd deletes it from the block,
  work, tspend, tx, winning-ticket and new-ticket maps and from `clients`,
  but not from `mixNotifications`, which is cleared only by an explicit
  `stopnotifymixmessages` (`:514-516`). Each client that ever ran
  `notifymixmessages` therefore stays in that map for the life of the
  process, and every mix message iterates it. dcrd's `QueueNotification`
  refuses a disconnected client, so the stale entry is never observable.
- **Why reproduced:** nothing observable changes either way, and the port
  keeps dcrd's map shape rather than carry a divergence of its own, however
  harmless. The port's stale entry is a `u64` session id; dcrd's keeps the
  whole `*wsClient` alive.
- **Pinned by:** `removing_a_client_clears_every_subscription_except_mix`
  in `crates/dcroxide-node/src/websocket.rs`.

## QK-0027 — an Ed25519 public key address has two string forms

- **Where:** dcrd `txscript/stdaddr` `DecodeAddressV0`
  (`addressv0.go:1165`) and `AddressPubKeyEd25519V0.String` /
  dcroxide-txscript `stdaddr.rs` `decode_address_v0`
- **What:** a version 0 public key address starts with an identifier byte
  whose low bits name the signature type and whose high bit is the
  secp256k1 Y-oddness flag. `DecodeAddressV0` masks the flag off before
  testing the type (`sigType := decoded[0] & ^sigTypeSecp256k1PubKeyCompOddFlag`),
  so an Ed25519 key, which has no oddness, is accepted with identifier
  `0x81` as well as `0x01`, while `String` always writes `0x01`. Two
  strings decode to one address, and the `0x81` form does not round-trip.
  The secp256k1 forms (ECDSA and Schnorr) write the flag back, so each of
  those has one string.
- **Why reproduced:** `validateaddress` and every other RPC or option that
  takes an address must accept exactly the strings dcrd accepts and print
  the same canonical form.
- **Pinned by:** `ed25519_pubkey_address_ignores_the_odd_flag` in
  `crates/dcroxide-txscript/tests/review_ed25519_addr_odd_flag.rs`, whose
  strings come from dcrd's `stdaddr` at the pin. The `address_decode` fuzz
  target's round-trip assertion allows exactly this case.
- **How found:** the `address_decode` fuzz target, within seconds of its
  mode that builds well-formed base58check strings being added.
