#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Apply a power-loss undo log: rewind the tree to its last successful sync.

Reads the log the shim wrote while the target ran, and undoes every write
that was never followed by an fsync/fdatasync of its file. What remains on
disk is then exactly what a power cut at kill time would have left.

Record layout, as emitted by shim.c:
    [type u8][pathlen u16][path][off u64][len u32][prevlen u64][data]

    W  a write: `data` is what it overwrote, `prevlen` the file's length
       before it. Undone by restoring the bytes and the length.
    T  an ftruncate: `prevlen` is the length before it.
    C  a file that did not exist. Undone by deleting it.
    S  a successful sync: everything pending for that file is now durable
       and must NOT be undone.
"""
import os
import struct
import sys


def records(path):
    with open(path, "rb") as f:
        blob = f.read()
    i, n = 0, len(blob)
    while i + 11 <= n:
        t = blob[i : i + 1]
        (pl,) = struct.unpack_from("<H", blob, i + 1)
        j = i + 3 + pl
        if j + 20 > n:
            break  # torn tail: the process died mid-record
        p = blob[i + 3 : j].decode("utf-8", "replace")
        off, ln, prev = struct.unpack_from("<QIQ", blob, j)
        k = j + 20
        data = blob[k : k + ln]
        if len(data) < ln:
            break
        yield t.decode(), p, off, prev, data
        i = k + ln


def main():
    log = sys.argv[1]
    # Per file, the undo actions still pending (not yet made durable).
    pending = {}
    created = set()
    for t, path, off, prev, data in records(log):
        if t == "S":
            # Durable: nothing before this sync can be taken back.
            pending.pop(path, None)
            created.discard(path)
        elif t == "C":
            created.add(path)
            pending.setdefault(path, [])
        elif t in ("W", "T"):
            pending.setdefault(path, []).append((off, prev, data))

    restored = truncated = removed = 0
    # Per path, so a run can say WHICH durability domain it exercised
    # rather than leaving it to be inferred from the shape of the totals.
    per_path = {}
    for path, actions in pending.items():
        stats = per_path.setdefault(path, {"restored": 0, "rewound": 0, "removed": 0, "bytes": 0})
        if path in created:
            # The file itself is not durable: a power cut leaves no trace.
            try:
                os.unlink(path)
                removed += 1
                stats["removed"] = 1
            except FileNotFoundError:
                pass
            continue
        try:
            fd = os.open(path, os.O_RDWR)
        except FileNotFoundError:
            continue
        try:
            before = os.fstat(fd).st_size
            # Reverse order: a region written twice must end up holding what
            # it held before the FIRST of those writes.
            for off, prev, data in reversed(actions):
                if data:
                    keep = max(0, min(len(data), prev - off))
                    if keep:
                        os.pwrite(fd, data[:keep], off)
                        restored += 1
                        stats["restored"] += 1
                        stats["bytes"] += keep
                os.ftruncate(fd, prev)
                truncated += 1
                stats["rewound"] += 1
            after = os.fstat(fd).st_size
            stats["shrank"] = before - after
            os.fsync(fd)
        finally:
            os.close(fd)
    print(
        f"power loss applied: {restored} regions restored, "
        f"{truncated} lengths rewound, {removed} files removed, "
        f"{len(pending)} files touched"
    )
    # Busiest first: the file that lost the most is the one that says which
    # durability domain the kill actually landed in.
    for path, s in sorted(
        per_path.items(), key=lambda kv: -(kv[1]["restored"] + kv[1]["rewound"])
    ):
        if s["removed"]:
            print(f"    {path}: removed (was never durable)")
            continue
        shrank = s.get("shrank", 0)
        print(
            f"    {path}: {s['restored']} regions ({s['bytes']} B) restored, "
            f"{s['rewound']} lengths rewound, shrank {shrank} B"
        )


if __name__ == "__main__":
    main()
