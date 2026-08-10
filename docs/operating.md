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

Budget for it: initial block download runs about **2.2x slower than
dcrd** — roughly 2.5 hours against dcrd's 1.1 for mainnet from genesis on
the machine in [bench-ledger.md](bench-ledger.md) — and the chain costs
more on disk, 32.06 GiB against dcrd's 23.73 GiB at the same tip. Both
numbers are measured, tracked, and attributed to the storage engine's
commit shape rather than to validation; see
[ADR-0004](adr/0004-storage-backend.md).

## Storage tuning: one knob helps, one hurts

Two settings change how the metadata store behaves. Both have been measured
over full mainnet replays; the numbers are in
[bench-ledger.md](bench-ledger.md) and the reasoning in
[ADR-0004](adr/0004-storage-backend.md).

**`--utxocachemaxsize` (default 150 MiB) is the one worth raising.**
Connecting a block flushes the UTXO cache when it fills, and that flush
forces a durable metadata commit — so the ceiling governs how often the node
commits. Raising it, together with the metadata overlay, measured **11%
faster** over a full chain: 3424-3467 s against a baseline of 3866-3888 s,
across three repetitions with non-overlapping ranges. dcrd has the same flag
and the same 150 MiB default; the ceiling here is 32 GiB.

Two caveats before you turn it up. The measured arm moved the UTXO cache
*and* the metadata overlay, and only the former is reachable from the command
line, so the share belonging to `--utxocachemaxsize` alone is being measured
separately. And a larger cache means more work lost on an unclean stop:
nothing is corrupted — the flush ordering holds — but more of the recent
window has to be redone.

**`DCROXIDE_DB_CACHE` is the one to leave alone.** It sets redb's page cache
in MiB, defaulting to 1024. Raising it to 8192 made a full-chain replay
**50% slower** — 5125-6294 s against the same 3866-3888 s baseline, again
with non-overlapping ranges. That is the opposite of what the setting
suggests, and the opposite of what a 500,000-key microbenchmark predicted
when the knob was added. redb splits the figure 90/10 into read cache and
write buffer, so most of an increase buys read cache that a sequential sync
never reuses, while the cache's own accounting grows with it.

Whether the 1024 MiB default is itself too large is open, and being
measured. Until that lands, the safe advice is to leave it unset.

**Neither knob changes how densely the store packs.** Page fill sits at
0.62-0.65 regardless of either setting, so neither shrinks the data
directory. They are throughput settings, and the storage size gap against
dcrd is a separate, unresolved matter recorded in ADR-0004.

## Identity: paths, files, and environment

dcroxide uses its own identity throughout. Nothing falls back to a
`dcrd` path or a `DCRD_*` variable — if you are migrating a
configuration, every name changes.

| | dcroxide | dcrd |
|---|---|---|
| data directory (Linux) | `~/.dcroxide` | `~/.dcrd` |
| data directory (macOS) | `~/Library/Application Support/Dcroxide` | `…/Dcrd` |
| data directory (Windows) | `%LOCALAPPDATA%\Dcroxide` | `…\Dcrd` |
| configuration file | `dcroxide.conf` | `dcrd.conf` |
| data directory override | `--appdata`, `DCROXIDE_APPDATA` | `DCRD_APPDATA` |
| extra TLS DNS names | `DCROXIDE_ALT_DNSNAMES` | `DCRD_ALT_DNSNAMES` |

Those two environment variables are the only ones read. Everything else
is a command-line flag or a `dcroxide.conf` entry, and the flag set is a
verbatim port of dcrd's — same names, same semantics, same help text.

The daemon generates `rpc.cert` and `rpc.key` in the data directory on
first start if they are absent, owner-readable only. Back up or replace
them the way you would dcrd's; a client that pinned dcrd's certificate
needs the new one.

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
