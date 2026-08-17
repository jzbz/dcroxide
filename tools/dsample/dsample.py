#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Sample a process's per-thread scheduler states against the whole system's.

In the tree rather than the bench artifacts because ADR-0004's
commit-shape attribution rests on what it measured: the node fully
stalled for 48% of block-sync wall time, 90-98% of that inside a
metadata-flush window (docs/bench-ledger.md, 2026-08-15 and 2026-08-16).

Two traps this instrument has already sprung, recorded so the next
reader does not re-learn them. It records kernel wait channels, NOT user
stacks, so "storage-blocked" means a thread is parked on a filesystem
symbol and not that it is inside any particular call -- attributing the
stall to a call site needs the flush observer alongside it
(DCROXIDE_DB_FLUSHLOG). And counting samples under-weights the stalls it
is measuring, because the sampler is starved during them: weight each
sample by the interval it represents, or a 48% stall reads as 19%.

The question: a load average of 4.62 at 0.76 cores of CPU is either other
tenants on the box or the target's own threads parked in uninterruptible
sleep on storage. Linux's load average counts BOTH runnable (R) and
uninterruptible (D) tasks, so splitting those counts into "the target's
threads", "other userspace", and "kernel workers" answers it directly.

WHY NOT /proc/stat's procs_blocked: measured on this machine, three threads
in a write+fsync loop show D=2.93 in a /proc/<pid>/task walk while
procs_blocked reads 1.54 -- LOWER than the target's own count. procs_blocked
counts only tasks parked in io_schedule() (iowait); a thread blocked on
btrfs_inode_lock is TASK_UNINTERRUPTIBLE, counted by the load average, and
absent from procs_blocked. So "ambient = procs_blocked - target" is invalid
and goes negative. The ambient term must come from an actual system-wide
task walk, which is what this does. procs_blocked is still recorded, as the
narrower iowait-only signal.

Cadence: the target's own threads at 10 Hz (cheap, tens of threads); the
full system walk at 1 Hz (thousands of tasks, so it is not free).
"""
import json
import os
import re
import sys
import time

HZ = os.sysconf("SC_CLK_TCK")
HEIGHT_RE = re.compile(rb"height (\d+), progress")
PF_KTHREAD = 0x00200000


def read_stat(path):
    """-> (state_char, fields_after_comm) or None. comm may contain ')' and
    spaces, so the only safe anchor is the LAST ')'."""
    try:
        with open(path, "rb") as f:
            line = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None  # task exited between listdir and open -- normal here
    close = line.rfind(b")")
    if close < 0 or close + 2 >= len(line):
        return None
    rest = line[close + 2 :].split()
    if not rest:
        return None
    # rest[0] is stat field 3 (state), so field N is rest[N-3].
    return chr(line[close + 2]), rest


def target_states(pid):
    """Per-thread state chars for the target."""
    out = []
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except (FileNotFoundError, ProcessLookupError):
        return None
    for tid in tids:
        s = read_stat(f"/proc/{pid}/task/{tid}/stat")
        if s:
            out.append((tid, s[0]))
    return out


def system_walk(target_pid, server_pid=None):
    """Every task on the box, classified. This is the ambient term, measured
    rather than inferred.

    The feeding dcrd server gets its OWN bucket. Its work scales with how fast
    the client pulls, so it is arm-correlated: leaving it inside "ambient"
    would charge the faster arm a larger ambient term and corrupt exactly the
    comparison being made.

    Kernel threads also get their own bucket, and are NOT ambient. On
    btrfs-over-LUKS much of a write's kernel-side work runs in kernel threads
    with their own PIDs (kcryptd, btrfs endio/transaction workers), so
    target-CAUSED blocking can appear outside the target's task list. Counting
    it as another tenant would make both hypotheses produce the same numbers.
    """
    tot = {
        "sysw_R": 0, "sysw_D": 0,          # whole system
        "kern_R": 0, "kern_D": 0,          # kernel threads (PF_KTHREAD)
        "srv_R": 0, "srv_D": 0,            # the feeding dcrd server
        "othr_R": 0, "othr_D": 0,          # other userspace = true ambient
        "tgt_R": 0, "tgt_D": 0,            # the target, from the same walk
        "tasks": 0,
    }
    kern_d_comm = {}
    othr_d_comm = {}
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            tids = os.listdir(f"/proc/{p}/task")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        for tid in tids:
            r = read_stat(f"/proc/{p}/task/{tid}/stat")
            if not r:
                continue
            state, rest = r
            tot["tasks"] += 1
            if state not in ("R", "D"):
                continue
            k = "R" if state == "R" else "D"
            tot["sysw_" + k] += 1
            try:
                flags = int(rest[6])  # stat field 9
            except (IndexError, ValueError):
                flags = 0
            if flags & PF_KTHREAD:
                tot["kern_" + k] += 1
                if state == "D":
                    try:
                        with open(f"/proc/{p}/comm", "rb") as f:
                            c = f.read().strip().decode("ascii", "replace")
                        kern_d_comm[c] = kern_d_comm.get(c, 0) + 1
                    except OSError:
                        pass
            elif p == str(target_pid):
                tot["tgt_" + k] += 1
            elif server_pid and p == str(server_pid):
                tot["srv_" + k] += 1
            else:
                tot["othr_" + k] += 1
                # Name the other-tenant blockers. A dry run of this sampler
                # caught 24 userspace threads sitting in D under one comm;
                # an unattributed ambient term would have been a number with
                # no way to check it.
                if state == "D":
                    try:
                        with open(f"/proc/{p}/task/{tid}/comm", "rb") as f:
                            c = f.read().strip().decode("ascii", "replace")
                        othr_d_comm[c] = othr_d_comm.get(c, 0) + 1
                    except OSError:
                        pass
    if kern_d_comm:
        tot["kern_D_comm"] = kern_d_comm
    if othr_d_comm:
        tot["othr_D_comm"] = othr_d_comm
    return tot


def proc_cpu(pid):
    r = read_stat(f"/proc/{pid}/stat")
    if not r:
        return None
    rest = r[1]
    out = {
        "cpu_ticks": int(rest[11]) + int(rest[12]),  # utime + stime
        "majflt": int(rest[9]),                       # field 12
    }
    # Field 42, delayacct_blkio_ticks: EXACT cumulative block-I/O wait, with
    # no sampling error at all. Reads a constant 0 unless
    # kernel.task_delayacct=1, so it is recorded opportunistically -- if the
    # sysctl gets enabled this becomes the primary instrument and the 10 Hz
    # state sampling becomes the cross-check.
    if len(rest) > 39:
        try:
            out["blkio_ticks"] = int(rest[39])
        except ValueError:
            pass
    return out


def proc_io(pid):
    try:
        with open(f"/proc/{pid}/io", "rb") as f:
            io = dict(l.split(b": ") for l in f.read().splitlines() if b": " in l)
        return {
            "read_bytes": int(io[b"read_bytes"]),
            "write_bytes": int(io[b"write_bytes"]),
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError, KeyError, OSError):
        return {}


def procs_blocked():
    """The narrower iowait-only counter, kept for contrast."""
    r = d = 0
    try:
        with open("/proc/stat", "rb") as f:
            for line in f:
                if line.startswith(b"procs_running"):
                    r = int(line.split()[1])
                elif line.startswith(b"procs_blocked"):
                    d = int(line.split()[1])
                    break
    except OSError:
        pass
    return r, d


def wchans(pid, tids):
    """Kernel symbol each blocked thread is parked in -- the mechanism."""
    seen = {}
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/wchan", "rb") as f:
                w = f.read().decode("ascii", "replace").strip()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        if w and w != "0":
            seen[w] = seen.get(w, 0) + 1
    return seen


def tail_height(path, tail=65536):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - tail))
            hits = HEIGHT_RE.findall(f.read())
        return int(hits[-1]) if hits else 0
    except (FileNotFoundError, OSError):
        return 0


def main():
    pid = int(sys.argv[1])
    label = sys.argv[2]
    logpath = sys.argv[3]
    outpath = sys.argv[4]
    period = float(sys.argv[5]) if len(sys.argv) > 5 else 0.1
    server_pid = sys.argv[6] if len(sys.argv) > 6 else None
    slow_every = max(1, int(round(1.0 / period)))

    prev_cpu = proc_cpu(pid)
    prev_t = time.time()
    t_start = prev_t
    n = 0
    cpu0 = time.process_time()

    with open(outpath, "w", buffering=1) as out:
        while True:
            t0 = time.time()
            states = target_states(pid)
            if states is None:
                break  # target gone
            counts = {}
            for _, s in states:
                counts[s] = counts.get(s, 0) + 1

            rec = {
                "t": round(t0 - t_start, 3),
                # Absolute clock too, so samples can be aligned against
                # the flush log's own timestamps and the stall attributed
                # to flush windows rather than inferred from totals.
                "wall": round(t0, 3),
                "label": label,
                "threads": len(states),
                "tgt_R": counts.get("R", 0),
                "tgt_D": counts.get("D", 0),
                "tgt_S": counts.get("S", 0),
            }

            cpu = proc_cpu(pid)
            if cpu and prev_cpu:
                dt = t0 - prev_t
                if dt > 0:
                    rec["cores"] = round(
                        (cpu["cpu_ticks"] - prev_cpu["cpu_ticks"]) / HZ / dt, 3
                    )
                rec["majflt_d"] = cpu["majflt"] - prev_cpu["majflt"]
                if "blkio_ticks" in cpu and "blkio_ticks" in prev_cpu:
                    rec["blkio_d"] = cpu["blkio_ticks"] - prev_cpu["blkio_ticks"]
            if cpu:
                prev_cpu, prev_t = cpu, t0

            if n % slow_every == 0:
                try:
                    with open("/proc/loadavg", "rb") as f:
                        rec["load"] = float(f.read().split()[0])
                except OSError:
                    pass
                rec["height"] = tail_height(logpath)
                rec.update(proc_io(pid))
                pr, pb = procs_blocked()
                rec["procs_running"] = pr
                rec["procs_blocked"] = pb
                blocked = [t for t, s in states if s == "D"]
                if blocked:
                    rec["wchan"] = wchans(pid, blocked)
                w0 = time.time()
                rec.update(system_walk(pid, server_pid))
                rec["walk_ms"] = round((time.time() - w0) * 1000, 1)
                rec["sampler_cpu_s"] = round(time.process_time() - cpu0, 2)

            out.write(json.dumps(rec) + "\n")
            n += 1
            slack = period - (time.time() - t0)
            if slack > 0:
                time.sleep(slack)


if __name__ == "__main__":
    main()
