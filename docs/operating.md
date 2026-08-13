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

Budget for it: initial block download runs about **2.2x slower than
dcrd** — roughly 2.5 hours against dcrd's 1.1 for mainnet from genesis on
the machine in [bench-ledger.md](bench-ledger.md) — and the chain costs
more on disk, 32.06 GiB against dcrd's 23.73 GiB at the same tip. Both
were measured in 2026-07 under redb 2.6.3 and have not been re-run since
the 4.1.0 upgrade, which holds identical content in 9.4% less space
(15,568,752,640 B against 17,182,003,200 on the same journal) and loaded
21% faster. That 9.4% is free-page retention rather than denser packing,
and free pages are the one quantity this investigation withdrew as
non-reproducible, so it does not license a projection of what a fresh
sync costs today — that number wants re-measuring, not arithmetic. The
2.2x has the same provenance and is likewise unverified against 4.1.0.
See [ADR-0004](adr/0004-storage-backend.md).

The two have different explanations, and only one of them is settled. The
**disk** difference is the storage engine and nothing else: as of
2026-08-11 both nodes have been measured to store the same payload for the
same chain at the same index composition — fifteen buckets equal to the
byte — so the extra space is how redb lays those bytes out, not extra data
dcroxide keeps. Block files match to within a mebibyte. The **time**
difference is attributed to commit shape but not yet demonstrated to be
dominated by it; storage accounts for 18% of a full replay's wall time, so
something outside the storage path is the larger term.

## Storage tuning: one knob helps, one hurts

Two settings change how the metadata store behaves. Both have been measured
over full mainnet replays; the numbers are in
[bench-ledger.md](bench-ledger.md) and the reasoning in
[ADR-0004](adr/0004-storage-backend.md).

**`--utxocachemaxsize` (default 150 MiB) is the one worth raising.**
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

**Neither knob changes how densely the store packs.** Page fill sits at
0.62-0.65 regardless of either setting, so neither shrinks the data
directory. They are throughput settings. The size gap against dcrd is
settled in cause — the engine's page layout, not extra data dcroxide keeps
— and nothing above the engine reaches it: all four of ADR-0004's levers
have now been measured and closed. What is still open is the engine choice
itself, in [ADR-0009](adr/0009-storage-shape.md).

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
| metadata page cache | `DCROXIDE_DB_CACHE` (MiB, default 1024) | — |

Those three environment variables are the only ones read; only the first
two have dcrd counterparts, since the page cache is a property of redb,
which dcrd does not use, and it is the one to leave unset — see the
storage tuning above. Everything else is a command-line flag or a
`dcroxide.conf` entry, and the flag set is a verbatim port of dcrd's —
same names, same semantics, same help text.

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
