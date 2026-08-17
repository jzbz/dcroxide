// SPDX-License-Identifier: ISC

// Command powerloss (LD_PRELOAD shim + replay.py) makes a power cut
// reproducible, for any storage engine.
//
// It is in the tree rather than in the bench artifacts because ADR-0009's
// gate C now rests on it. The crash suite's other primitives -- an
// in-process `drop`, and `PowerLossBackend` in
// crates/dcroxide-database/tests/crash.rs -- cannot settle that gate: the
// first leaves the page cache intact so it cannot see a missing fsync at
// all, and the second is a `redb::StorageBackend`, so it reaches the
// metadata store but neither the flat `.fdb` block files nor any candidate
// engine. fjall exposes no injectable IO layer, and neither does lsm-tree
// beneath it.
//
// Results that depend on this tool, all in docs/bench-ledger.md: fjall
// surviving 10 rounds of real power loss, and dcroxide's own block files
// surviving 3 -- the latter showing that only metadata.redb ever has
// anything to undo, because DbCache::flush syncs the block files first and
// the metadata commit is 68-71% of block-sync wall time, so a kill at an
// arbitrary instant lands inside it.
//
// Usage:
//     make -C tools/powerloss
//     POWERLOSS_DIR=<store> POWERLOSS_LOG=<log> \
//         LD_PRELOAD=tools/powerloss/libpowerloss.so <target> &
//     kill -9 <target>            # the power cut
//     python3 tools/powerloss/replay.py <log>
//
// Power-loss shim: an engine-independent form of the crash primitive.
//
// The redb suite got a PowerLossBackend on 2026-08-15, but that is a
// redb::StorageBackend and fjall exposes no injectable IO layer, so the
// same property could not be asked of a candidate engine. This does it at
// the libc boundary instead, where every engine is equal.
//
// While the target runs, every write to a tracked file is preceded by a
// record of what that write is about to destroy: the bytes it overwrites
// and the file's length beforehand. A successful fsync/fdatasync on a file
// clears that file's pending records -- those bytes are on the platter and
// a power cut can no longer take them. Kill the process, replay what is
// left in reverse, and the tree is exactly as of its last successful sync.
//
// The undo log is deliberately NOT fsynced. The harness kills the target
// and then reads the log from the same machine, so the page cache is the
// right place for it, and syncing it would perturb the very timings and
// ordering under test.
//
// Tracked files are those under $POWERLOSS_DIR. Everything else -- the
// journal being read, stdout, the log itself -- is passed straight
// through, so the shim costs nothing outside the store.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAXFD 4096

static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t);
static int (*real_fsync)(int);
static int (*real_fdatasync)(int);
static int (*real_ftruncate)(int, off_t);
static int (*real_close)(int);

// Path per tracked fd; NULL means "not tracked".
static char *fd_path[MAXFD];
static int log_fd = -1;
static char track_dir[PATH_MAX];
static size_t track_len;
static __thread int in_shim; // re-entrancy guard: our own IO must not recurse

static void init(void) {
    static int done;
    if (done) return;
    done = 1;
    real_open = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_write = dlsym(RTLD_NEXT, "write");
    real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
    real_close = dlsym(RTLD_NEXT, "close");
    const char *d = getenv("POWERLOSS_DIR");
    const char *l = getenv("POWERLOSS_LOG");
    if (d) { snprintf(track_dir, sizeof track_dir, "%s", d); track_len = strlen(track_dir); }
    if (l) log_fd = real_open64(l, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

static int tracked(const char *path) {
    return track_len && path && strncmp(path, track_dir, track_len) == 0;
}

// Record layout: [type u8][pathlen u16][path][off u64][len u32][prevlen u64][data]
static void emit(char type, const char *path, uint64_t off, const void *data,
                 uint32_t len, uint64_t prevlen) {
    if (log_fd < 0) return;
    uint16_t pl = (uint16_t)strlen(path);
    // One buffered write per record keeps the log's own ordering simple.
    static __thread char buf[1 << 16];
    size_t n = 0;
    if (11 + pl + len > sizeof buf) return; // oversized write: skip rather than corrupt
    buf[n++] = type;
    memcpy(buf + n, &pl, 2); n += 2;
    memcpy(buf + n, path, pl); n += pl;
    memcpy(buf + n, &off, 8); n += 8;
    memcpy(buf + n, &len, 4); n += 4;
    memcpy(buf + n, &prevlen, 8); n += 8;
    if (len) { memcpy(buf + n, data, len); n += len; }
    real_write(log_fd, buf, n);
}

// Before a write lands, keep what it destroys.
static void save_before(int fd, uint64_t off, size_t len) {
    if (fd < 0 || fd >= MAXFD || !fd_path[fd]) return;
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    uint64_t prevlen = (uint64_t)st.st_size;
    static __thread char old[1 << 16];
    uint32_t keep = 0;
    if ((uint64_t)off < prevlen) {
        uint64_t avail = prevlen - off;
        keep = (uint32_t)(len < avail ? len : avail);
        if (keep > sizeof old) keep = sizeof old;
        // pread through the real symbol: this read must not be recorded.
        if (pread(fd, old, keep, (off_t)off) != (ssize_t)keep) keep = 0;
    }
    emit('W', fd_path[fd], off, old, keep, prevlen);
}

static void note_open(int fd, const char *path) {
    if (fd < 0 || fd >= MAXFD || !tracked(path)) return;
    struct stat st;
    int existed = stat(path, &st) == 0;
    free(fd_path[fd]);
    fd_path[fd] = strdup(path);
    if (!existed) emit('C', path, 0, NULL, 0, 0);
}

int open(const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int fd = real_open(path, flags, m);
    if (!in_shim) { in_shim = 1; note_open(fd, path); in_shim = 0; }
    return fd;
}

int open64(const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int fd = real_open64 ? real_open64(path, flags, m) : real_open(path, flags, m);
    if (!in_shim) { in_shim = 1; note_open(fd, path); in_shim = 0; }
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int fd = real_openat(dirfd, path, flags, m);
    if (!in_shim && path && path[0] == '/') { in_shim = 1; note_open(fd, path); in_shim = 0; }
    return fd;
}

ssize_t write(int fd, const void *buf, size_t n) {
    init();
    if (!in_shim && fd < MAXFD && fd >= 0 && fd_path[fd]) {
        in_shim = 1;
        off_t cur = lseek(fd, 0, SEEK_CUR);
        if (cur >= 0) save_before(fd, (uint64_t)cur, n);
        in_shim = 0;
    }
    return real_write(fd, buf, n);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, n); in_shim = 0; }
    return real_pwrite(fd, buf, n, off);
}

ssize_t pwrite64(int fd, const void *buf, size_t n, off64_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, n); in_shim = 0; }
    return real_pwrite64 ? real_pwrite64(fd, buf, n, off) : real_pwrite(fd, buf, n, (off_t)off);
}

int ftruncate(int fd, off_t len) {
    init();
    if (!in_shim && fd < MAXFD && fd >= 0 && fd_path[fd]) {
        in_shim = 1;
        struct stat st;
        if (fstat(fd, &st) == 0) emit('T', fd_path[fd], 0, NULL, 0, (uint64_t)st.st_size);
        in_shim = 0;
    }
    return real_ftruncate(fd, len);
}

// A successful sync makes this file's pending records unnecessary: those
// bytes survive a power cut, so the replay must not undo them.
static int after_sync(int fd, int rc) {
    if (rc == 0 && !in_shim && fd < MAXFD && fd >= 0 && fd_path[fd]) {
        in_shim = 1;
        emit('S', fd_path[fd], 0, NULL, 0, 0);
        in_shim = 0;
    }
    return rc;
}

int fsync(int fd) { init(); return after_sync(fd, real_fsync(fd)); }
int fdatasync(int fd) { init(); return after_sync(fd, real_fdatasync(fd)); }

int close(int fd) {
    init();
    if (fd >= 0 && fd < MAXFD && fd_path[fd]) { free(fd_path[fd]); fd_path[fd] = NULL; }
    return real_close(fd);
}
