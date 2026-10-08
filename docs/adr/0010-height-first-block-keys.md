# ADR-0010 — Height-first keys for the per-block buckets (chain database version 15)

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Initial sync is bound by the metadata flush. ADR-0004 and ADR-0009 measured
the node fully stalled on storage for about half of block-sync wall time,
90–98% of it inside a metadata-flush window, and closed every lever above
the engine that was meant to make the store *smaller*. ADR-0009 kept redb.
What a flush costs in redb is the leaves it touches: the B-tree is
copy-on-write, so every leaf a flush changes is copied, with its branch
path, and a leaf that is not cached is read first.

Seven buckets gain one row per block, and dcrd keys none of them in block
order:

| bucket | dcrd key | where |
|---|---|---|
| `spendjournalv3` | block hash | `internal/blockchain/chainio.go:767`, `:814`, `:821` |
| `gcsfilters` | block hash | `chainio.go:851`, `:877`, `:885` |
| `hdrcmts` | block hash | `chainio.go:980`, `:997` |
| `treasury` | block hash | `internal/blockchain/treasury.go:235`, `:244` |
| `stakeblockundo` | height, little-endian | `blockchain/stake/internal/ticketdb/chainio.go:483`, `:498`, `:509` |
| `ticketsinblock` | height, little-endian | `blockchain/stake/internal/ticketdb/chainio.go:572`, `:588`, `:599` |
| `ffldb-blockidx` (ffldb's internal block index) | block hash | `database/ffldb/db.go:1142`, `:1239`, `:1717` |

A hash scatters consecutive blocks over the whole key range, and so does a
little-endian height, whose first byte changes with every block. During
initial sync one flush covers about 3,000 blocks, so each of these buckets
pays about one cold leaf, and its branch path, per block. dcrd's own
`blockidxv3` already keys by big-endian height and then hash
(`blockIndexKey`, `chainio.go:311`), and ADR-0009's guardrails ask for
big-endian range keys.

This is not the re-keying ADR-0004's 2026-08-12 addendum closed. That one
asked whether splitting `spendjournalv3`'s rows would reduce intra-page
slack, which is a question about size; every layout tried made the tree
larger. This one is about how many leaves a flush writes.

dcroxide has not been released. ADR-0004's fresh-sync stance already rules
out reading another implementation's data directory, so the only
directories written in the old layout are the project's own development and
benchmark ones.

## Decision

- **Key all seven buckets by big-endian height first.** The four hash-keyed
  chain buckets and ffldb's block index take the big-endian height followed
  by the hash, the hash keeping apart blocks at one height (side chains keep
  their filters, commitments and stored bodies). The two stake buckets take
  the big-endian height alone, as dcrd's take the height alone. Row values
  are unchanged, byte for byte. Each crate has one encoder:
  `chaindb::block_row_key` for the four chain buckets (the `blockidxv3`
  key), `stakedb::height_key` for the stake buckets, and `block_idx_key` in
  `dcroxide-database` for the block index.
- **Lookups take the height beside the hash.** `has_block`, `fetch_block`,
  `fetch_block_header`, `fetch_block_region` and their plural forms, and the
  chain's row readers and writers, take the block's height. Every caller has
  the block's index node or the block, and a node's height is its header's.
  The RPC transaction lookup, whose index entry names only the block hash,
  takes the height from the block index. A lookup under the wrong height
  misses; it never reads another block's row.
- **The chain database version is 15**: dcrd's 14 plus this layout. One
  version gates all seven buckets, since they live in one store and the
  chain checks the version before it reads any of them. A database at an
  older version is refused once its version row is read, before any other
  row is read and without changing one, with a message that names the
  block database directory to delete and says the chain is not damaged. There is no in-place upgrade. A build from before
  the change refuses a version-15 directory through the newer-version check
  every build already has. Bumping the version, rather than recording the
  layout in a row of its own, is what makes that second refusal work: an
  old build knows nothing of a new row.
- **The number is the port's own from here on.** If dcrd ships a version 15
  of its own, port its row change and take the next free number here, 16,
  keeping the refusal of every older version. dcrd's `upgradeDB` step for it
  is not ported, as none is.

## Consequences

- **Measured gain.** On an x86_64 Linux machine with a ZFS mirror of QLC
  NVMe drives, the node in a container restricted to four cores and syncing
  over loopback from a local dcrd: **+26%** over a 200,000-block mainnet tail
  (a median of 98.5 against 78.1 blk/s; all four runs faster than all five
  base runs, where base runs on that storage vary by about 7% run to run)
  and **1.74x** from genesis to block 916,000 (336.6 against 193.0 blk/s, one
  run each). The node wrote about 10% fewer bytes on the tail and used about
  8% less CPU time. The data directory did not grow: 24.98 against 24.96 GB
  at block 916,000, and within 0.2% at the tip. The rows are in
  [bench-ledger.md](../bench-ledger.md), "Height-first per-block keys".
- **A divergence from dcrd's schema**, recorded in PARITY.md: the key
  formats, a block store interface whose lookups take a height, a payload
  four bytes per key larger in five buckets (at most about 22 MB at the
  mainnet tip), and the startup line "Blockchain database version info:
  chain: 15, ..." where dcrd prints 14. The format is internal to the store:
  nothing outside dcroxide reads it.
- **Development data directories must be re-synced.** The refusal and the
  remedy are in [operating.md](../operating.md). Snapshots taken in the old
  layout, including the benchmark campaign's, cannot be reused.
- **A tool that opens the store directly must open the chain first.** The
  database crate has no version of its own, as ffldb has none, so a raw
  `fetch_block` on a version-14 store misses rather than refusing. Every
  tool in the workspace opens the chain before reading blocks.
- **No code depended on the old order.** Nothing walks any of the seven
  buckets in key order; every access is a point lookup by block or height.
  The layout tests pin the new order anyway, so a later walk can rely on it.

## Alternatives

- **Keep dcrd's keys.** Rejected: it forgoes the largest single gain the
  flush campaign measured, for byte-compatibility with a schema nothing
  outside dcroxide reads.
- **Height alone for the hash-keyed buckets.** Rejected: filters, header
  commitments and stored blocks are kept for side chains too, so two blocks
  at one height must not share a key.
- **Record the layout in a row of its own and keep version 14.** Rejected:
  a build from before the change would not know to look for the row, and
  would open a new directory and miss every per-block row.
- **Migrate old directories in place.** Rejected: there is no released
  directory to migrate, and ADR-0004 makes a fresh sync the upgrade path.
