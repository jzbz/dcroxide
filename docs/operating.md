# Operating dcroxide

Read [SECURITY.md](../SECURITY.md) first. **This node is pre-alpha: do
not expose it to the internet and do not use it with funds.** Use
[dcrd](https://github.com/decred/dcrd) for anything that matters. What
follows is for people running it deliberately anyway — on a private
network, against testnet or simnet, or to reproduce a measurement.

The operator-facing requirements are collected here because two of them
are traps: the node **must** run under a supervisor, and it **cannot**
adopt a dcrd data directory.

## A supervisor is required, not recommended

Release builds set `panic = "abort"`. A panic terminates the process
instead of unwinding, so **any reachable panic is an outage until
something restarts the node**. This is deliberate — Rust mutexes poison
on panic where Go's do not, so a panic that unwound would leave the
daemon wedged behind poisoned locks while the RPC layer kept answering
canned errors and looking healthy. Aborting is loud instead of silent,
and loud is what a consensus daemon wants. The full reasoning is in
`[profile.release]` in the workspace `Cargo.toml`, and a test fails if
the setting is dropped.

The consequence is an operational requirement: run it under something
that restarts it. A systemd unit needs at least

```ini
Restart=on-failure
RestartSec=5s
```

Anything equivalent works — a supervisor, a container restart policy,
runit. A node run by hand from a shell will simply stop on the first
panic.

A storage failure now stops the node rather than being retried. If a
durable write to the metadata store fails — a full disk, an I/O error — the
store refuses every later write, so the node makes no further progress until
it is restarted. Reads keep working, so RPC still answers. This trades
availability for integrity deliberately: the alternative is retrying a write
whose failure may have left the store in a state that a restart silently
rolls back, which is worse for a consensus daemon than stopping. Two things
follow for an operator. A node that has stopped making progress with
`ErrFatal` in its log has a storage problem, not a network one. And **a
non-zero exit after "Flushing the block database to disk..." means the
shutdown flush failed** — the on-disk chain state is behind what the node
was running with, and the next start may refuse to make progress, so
investigate the storage before restarting rather than restarting into the
same fault.

Pair it with a memory limit. A websocket client that subscribes and then
stops reading grows node memory without bound; the notification queues
are unbounded exactly as dcrd's are, so nothing is dropped or reordered
and the whole cost is paid in memory. That is not reachable without RPC
credentials, but a `MemoryMax=` (or the container equivalent) plus the
restart policy above bounds the damage from a subscriber you do not
control.

## Fresh sync only — a dcrd data directory will not work

dcroxide does not read dcrd's on-disk format. There is no migration from
an existing dcrd data directory, and pointing it at one is not a
supported configuration. Syncing from genesis is the accepted default
(ADR-0004's C6 stance); `addblock`-format import is the bulk path when
you already have the blocks.

**A data directory written before 2026-08-13 also has to be re-synced.**
The metadata store moved from redb 2.x to 4.x, which changed the on-disk
format. There is no in-place upgrade. An old directory is *refused*, not
misread — the node stops with a message naming redb 2.x and telling you to
sync again, and it says the chain is not damaged, because "this predates
the upgrade" and "your disk is failing" want opposite reactions from you.
Delete the data directory and sync from genesis, or re-import with
`addblock`. Nothing else about operating the node changes.

Budget for it: initial block download runs about **1.29x slower than
dcrd** — roughly 1.15 hours against dcrd's 0.9 for mainnet from genesis
on the machine in [bench-ledger.md](bench-ledger.md) — and the chain
costs more on disk, 33.58 GiB against dcrd's 23.69 GiB at the same tip.
Both were measured 2026-08-15 under redb 4.1.0, with both daemons
syncing from one shared dcrd server and the index composition verified
on each side. They replace 2026-07 figures of 2.2x and 32.06 GiB against
23.73, taken under redb 2.6.3 with the two nodes syncing from each other
on one machine — a setup that inflated both arms.

Treat 1.29x as an upper bound on the gap rather than a precise ratio:
the two arms ran about 12 hours apart under different background load,
once each. What is not in doubt is the direction — the port has roughly
halved its distance to dcrd since 2026-07 — and that it does the work at
about half dcrd's CPU, 0.76 cores against 1.50. If your host is busy
with other work, expect the sync to stretch more than dcrd's would.
See [ADR-0004](adr/0004-storage-backend.md).

The two have different explanations, and only one of them is settled. The
**disk** difference is the storage engine and nothing else: as of
2026-08-11 both nodes have been measured to store the same payload for the
same chain at the same index composition — fifteen buckets equal to the
byte — so the extra space is how redb lays those bytes out, not extra data
dcroxide keeps. Block files match to within a mebibyte. The **time**
difference is commit shape, and as of 2026-08-15 that is measured rather
than attributed: the node is fully stalled on storage — nothing runnable at
all — for **48% of block-sync wall time**, against dcrd's 0.9%. A
2026-08-16 run with the flush observer enabled puts **90–98% of that inside
a metadata-flush window**, so it is the commit specifically rather than
storage in general. (An earlier figure of 34.6% for the same runs was
count-weighted; the sampler is starved during the stalls it measures, and
weighting by represented time raises it to 48–51%.) How much of it is
*recoverable* was settled on 2026-08-16: moving the metadata commit off
the block-connection thread was built, measured at 9.5% slower (232.1 to
210.0 blk/s, with the stalled share rising from 48.1% to 53.7%), and
reverted. The stall is real and it is the commit, but it is not
recoverable by rescheduling *when* the commit runs — the remaining lever
is what a commit costs. The earlier 18%
figure came from a replay, which validates every block where a syncing
daemon skips ~93% under assume-valid, so it understated the daemon's share.

## Storage tuning: two knobs help, one hurts, one is untested

Four settings change how the metadata store behaves. Three are measured and
one is not; the numbers are in [bench-ledger.md](bench-ledger.md) and the
reasoning in [ADR-0004](adr/0004-storage-backend.md).

The two that help are the two flush triggers, and they are worth understanding
together: a durable metadata commit is forced when **either** the UTXO cache
fills or the metadata overlay fills. Each ceiling governs one of them, raising
either reduces how often the node commits, and each measured ~12% on its own.

**`--utxocachemaxsize` (default 150 MiB) is one of the two.**
Connecting a block flushes the UTXO cache when it fills, and that flush
forces a durable metadata commit — so the ceiling governs how often the node
commits. Raising it on its own measured **12% faster** over a full chain at
1200 MiB, and 7% at 600 MiB, across three repetitions each with ranges that
do not overlap the baseline's. dcrd has the same flag and the same 150 MiB
default; the ceiling here is 32 GiB.

One caveat before you turn it up: a larger cache means more work redone
after an unclean stop. Nothing is corrupted — the flush ordering holds —
but more of the recent window has to be replayed, so pair a large value with
the supervisor above rather than treating it as free.

**`DCROXIDE_DB_CACHE` is the one to leave alone.** It sets redb's page cache
in MiB, defaulting to 1024. Raising it to 8192 made a full-chain replay
**50% slower** — 5125-6294 s against the same 3866-3888 s baseline, again
with non-overlapping ranges. That is the opposite of what the setting
suggests, and the opposite of what a 500,000-key microbenchmark predicted
when the knob was added. There is no fixed split to reason from: redb 4.1.0
keeps a single cache figure and partitions it on demand, capping the write
buffer at half of it and letting the read cache grow into all of it. The
advice rests on the full-chain measurement, not on a mechanism.

Lowering it does not help either: 256 MiB and 512 MiB both measured
indistinguishable from the 1024 MiB default, with ranges overlapping it.
The default is the right value — the only thing that matters is not raising
it, so leave the variable unset.

**`DCROXIDE_DB_OVERLAY` and `DCROXIDE_DB_FLUSH_SECS` reach the other flush
trigger.** Connecting a block forces a durable commit when *either* the UTXO
cache fills or the metadata overlay does — and until now only the first was
reachable. The overlay has its own ceiling, 100 MiB, and its own interval,
300 seconds; both were fixed at compile time, so half the cadence lever could
not be pulled. `DCROXIDE_DB_OVERLAY` sets the ceiling in MiB and
`DCROXIDE_DB_FLUSH_SECS` the interval in seconds. Unset, both keep the
compiled defaults, so an untouched node behaves exactly as before.

**`DCROXIDE_DB_OVERLAY=800` measured 12.7% faster**, which makes it the
second knob worth raising. Four alternating full-mainnet syncs, 256.1 and
272.7 blk/s at the default against 288.4 and 307.5 at 800 MiB — ranges
disjoint, and both adjacent pairs agreeing to 0.2 points. The mechanism is
visible in the flush count, which drops 130 to 119.

Why it works: the node is *fully stalled* — nothing runnable at all — for
**48% of block-sync wall time**, and **90–98% of that is inside a
metadata-flush window**. Flushes are large, a median of 26.9 s and a longest
of 79.5 s. Cadence decides how many there are, and a durable commit is forced
by *either* the UTXO cache filling or the overlay filling. Raising one ceiling
leaves the other still firing, which is why both knobs matter.

Whether the two **compose** is untested. `--utxocachemaxsize` measures 12% and
this measures 12.7%, on independent triggers of the same commit; they may
stack toward ~25% or may both be nearing one ceiling. Raising both is
reasonable and unmeasured.

`DCROXIDE_DB_FLUSH_SECS` (the time trigger, default 300) remains untuned — no
value has been measured, and on a syncing node the size trigger fires long
before the interval does.

Pair any raised value with the supervisor above: as with the UTXO cache, a
larger overlay means more of the recent window replays after an unclean stop.

**Neither page-cache knob changes how densely the store packs.** Page fill sits at
0.62-0.65 regardless of either setting, so neither shrinks the data
directory. They are throughput settings. The size gap against dcrd is
settled in cause — the engine's page layout, not extra data dcroxide keeps
— and nothing above the engine reaches it: all four of ADR-0004's levers
have now been measured and closed. The engine choice itself was the last
thing open and is now settled: [ADR-0009](adr/0009-storage-shape.md)
closed on 2026-08-17 with redb staying. The candidate won on density and
on write shape and lost on crash safety, so the disk and commit costs
above are accepted rather than retracted.

## Identity: paths, files, and environment

dcroxide uses its own identity throughout. Nothing falls back to a
`dcrd` path or a `DCRD_*` variable — if you are migrating a
configuration, every name changes.

| | dcroxide | dcrd |
|---|---|---|
| application home directory (Linux) | `~/.dcroxide` | `~/.dcrd` |
| application home directory (macOS) | `~/Library/Application Support/Dcroxide` | `…/Dcrd` |
| application home directory (Windows) | `%LOCALAPPDATA%\Dcroxide` | `…\Dcrd` |
| configuration file | `dcroxide.conf` | `dcrd.conf` |
| home directory override | `--appdata`, `DCROXIDE_APPDATA` | `DCRD_APPDATA` |
| data directory override | `--datadir` | `--datadir` |
| extra TLS DNS names | `DCROXIDE_ALT_DNSNAMES` | `DCRD_ALT_DNSNAMES` |
| metadata page cache | `DCROXIDE_DB_CACHE` (MiB, default 1024) | — |
| metadata overlay flush size | `DCROXIDE_DB_OVERLAY` (MiB, default 100) | — |
| metadata overlay flush interval | `DCROXIDE_DB_FLUSH_SECS` (s, default 300) | — |
| metadata flush log (JSONL path) | `DCROXIDE_DB_FLUSHLOG` (unset = off) | — |

The chain itself lives under the home directory, not at it: `--datadir`
defaults to `<home>/data` with the network appended, so on Linux the
blocks are in `~/.dcroxide/data/mainnet` while `dcroxide.conf`,
`rpc.cert`, `rpc.key` and `logs/` sit in `~/.dcroxide` itself.

Those six are the only `DCROXIDE_*` variables read; only the first
two have dcrd counterparts, since the page cache, the overlay and the
flush log are properties of redb, which dcrd does not use. Of the four
storage variables, `DCROXIDE_DB_CACHE` is the one to leave unset, the
next two are untuned instruments — see the storage tuning above — and
`DCROXIDE_DB_FLUSHLOG` is diagnostic: it appends one JSON object per
metadata flush (sequence, end instant, duration, entries, bytes), which
is how the 90–98% attribution above was measured. Leave it unset in
normal operation; it writes a line inside each flush. A malformed or
zero value in any of the tuning variables warns and falls back to the
default rather than refusing to start, since they are hints. Everything
else is a command-line flag or a `dcroxide.conf` entry, and the flag set
is a verbatim port of dcrd's — same names, same semantics, and the same
help text apart from the two environment annotations, which name
`DCROXIDE_APPDATA` and `DCROXIDE_ALT_DNSNAMES` where dcrd's name
`DCRD_APPDATA` and `DCRD_ALT_DNSNAMES`.

The daemon generates `rpc.cert` and `rpc.key` in the application home
directory — alongside `dcroxide.conf`, not under `data/` — on first
start, and only when *both* are absent: one present with the other
missing is an error naming the missing half rather than a regeneration
over the key that is still there. The modes are dcrd's, the certificate
`0644` and the key `0600`. Back up or replace
them the way you would dcrd's; a client that pinned dcrd's certificate
needs the new one. Replacing them is not live, though: dcrd re-reads the
pair on the first connection after a change, checking at most once every
five seconds, while this daemon loads `rpc.cert`, `rpc.key`, and (under
`--authtype=clientcert`) the `--clientcafile` bundle once at startup, so
a new certificate, a replaced key, or an edit to `clients.pem` that adds
or revokes a client takes effect only after a restart. `SIGHUP` will not
do it: it stops the daemon, exactly as it does in dcrd.

Default ports are dcrd's, unchanged: mainnet 9108 (P2P) and 9109 (RPC).

## Running it

Build from source. Binaries are not published, and the release process —
signing, platform tiers, reproducibility — is an open decision (D7 in
[the ADR index](adr/README.md)); it is a hard gate before anything ships
as a binary.

```bash
cargo build --release
```

The release profile is deliberate: one codegen unit, thin LTO, line
tables kept for profiling, and the `panic = "abort"` discussed above.
The toolchain is pinned in `rust-toolchain.toml` so artifacts are
reproducible from the same source.

Start it against simnet or testnet rather than mainnet while evaluating:

```bash
./target/release/dcroxide --testnet --appdata=/path/outside/the/repo
```

`--norpc` disables the RPC and websocket surfaces entirely, which is the
right default if you only want a syncing node — it removes the entire
authenticated surface from the process.

## Status of what you are running

Per-package parity status is in [PARITY.md](../PARITY.md), which also
records every deliberate divergence from dcrd and the known remaining
gaps. Bug-for-bug reproductions of dcrd behavior — the ones that look
like defects and are not — are catalogued in [QUIRKS.md](../QUIRKS.md).

There is no per-RPC-method status ledger yet. It is planned alongside
the ecosystem-acceptance work (the `dcrdtest` harness, a `dcrctl`
sweep, dcrwallet integration), none of which has been run; the project
brief tracks that as unmet.
