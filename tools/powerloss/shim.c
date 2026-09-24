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
// anything to undo, because DbCache::run_flush syncs the block files first and
// the metadata commit is 68-71% of block-sync wall time, so a kill at an
// arbitrary instant lands inside it. Both ran on a shim that recorded no
// ftruncate64 (Rust's File::set_len), writev, pwritev or fallocate, dropped
// any overwrite of 64 KiB or more, put zeros back where a shrink had cut
// bytes off, and never recorded a file as created; none is re-run yet.
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
// and the file's length beforehand. A shrinking truncate keeps the bytes it
// cuts off the same way, and so does an fallocate that punches, zeroes or
// shifts a range. A successful fsync/fdatasync on a file clears that
// file's pending records -- those bytes are on the platter and a power cut
// can no longer take them. Kill the process, replay what is left in
// reverse, and every tracked file's contents and length are as of its last
// successful sync.
//
// What that does NOT model, so a clean replay does not rule it out:
//   - directory durability. A created file stops being undoable at its own
//     fsync; a missing fsync of the parent directory after a create, an
//     unlink or a rename is invisible. unlink and rename are not
//     interposed at all, so a file they remove or replace is not restored.
//   - partial persistence. Everything a file wrote since its last sync is
//     lost together, so a torn write, or a later write surviving an earlier
//     one, is never produced.
//   - an open with O_TRUNC of a file that already exists: what it cuts
//     off is not kept. No store file is opened that way.
//   - writes through a descriptor it did not see opened by an absolute
//     path under $POWERLOSS_DIR (a relative path, dup, fcntl(F_DUPFD)),
//     and anything issued as a raw syscall (Go's runtime, io_uring, mmap
//     stores) rather than through these libc entry points.
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAXFD 4096

static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_pwritev)(int, const struct iovec *, int, off_t);
static ssize_t (*real_pwritev64)(int, const struct iovec *, int, off64_t);
static ssize_t (*real_pwritev2)(int, const struct iovec *, int, off_t, int);
static ssize_t (*real_pwritev64v2)(int, const struct iovec *, int, off64_t, int);
static int (*real_fsync)(int);
static int (*real_fdatasync)(int);
static int (*real_ftruncate)(int, off_t);
static int (*real_ftruncate64)(int, off64_t);
static int (*real_fallocate)(int, int, off_t, off_t);
static int (*real_fallocate64)(int, int, off64_t, off64_t);
static int (*real_close)(int);

// Path per tracked fd; NULL means "not tracked".
static char *fd_path[MAXFD];
static int log_fd = -1;
static char track_dir[PATH_MAX];
static size_t track_len;
// Fault injection, for the failure modes a kill cannot produce: after
// $POWERLOSS_FAIL_AFTER successful writes to a path containing
// $POWERLOSS_FAIL_MATCH, every further write to it fails with EIO. That is
// what fjall #308 needs -- a journal write that FAILS, rather than a
// process that dies -- to see whether a later commit still reports success.
static char fail_match[PATH_MAX];
static size_t fail_match_len;
static long fail_after = -1;
static long fail_count = -1; // how many writes to fail; -1 = all of them
static long fail_seen;
static long failed_so_far;
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
    real_writev = dlsym(RTLD_NEXT, "writev");
    real_pwritev = dlsym(RTLD_NEXT, "pwritev");
    real_pwritev64 = dlsym(RTLD_NEXT, "pwritev64");
    real_pwritev2 = dlsym(RTLD_NEXT, "pwritev2");
    real_pwritev64v2 = dlsym(RTLD_NEXT, "pwritev64v2");
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
    real_ftruncate64 = dlsym(RTLD_NEXT, "ftruncate64");
    real_fallocate = dlsym(RTLD_NEXT, "fallocate");
    real_fallocate64 = dlsym(RTLD_NEXT, "fallocate64");
    real_close = dlsym(RTLD_NEXT, "close");
    const char *d = getenv("POWERLOSS_DIR");
    const char *l = getenv("POWERLOSS_LOG");
    if (d) { snprintf(track_dir, sizeof track_dir, "%s", d); track_len = strlen(track_dir); }
    if (l) log_fd = real_open64(l, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    const char *fm = getenv("POWERLOSS_FAIL_MATCH");
    const char *fa = getenv("POWERLOSS_FAIL_AFTER");
    if (fm) { snprintf(fail_match, sizeof fail_match, "%s", fm); fail_match_len = strlen(fail_match); }
    if (fa) fail_after = atol(fa);
    const char *fc = getenv("POWERLOSS_FAIL_COUNT");
    if (fc) fail_count = atol(fc);
}

static int tracked(const char *path) {
    return track_len && path && strncmp(path, track_dir, track_len) == 0;
}

// Should this write be failed? Counts matching writes first, so the target
// gets a working store before the fault lands mid-stream.
static int should_fail(int fd) {
    if (fail_after < 0 || !fail_match_len) return 0;
    if (fd < 0 || fd >= MAXFD || !fd_path[fd]) return 0;
    if (!strstr(fd_path[fd], fail_match)) return 0;
    if (fail_seen++ < fail_after) return 0;
    // A TRANSIENT fault is the interesting one: fjall #308 is about a
    // journal write failing and writes then RESUMING, so a later commit
    // lands after an unterminated record and still reports success. A
    // permanent fault only shows that every subsequent commit errors,
    // which is the engine behaving correctly and not the bug.
    if (fail_count >= 0 && failed_so_far >= fail_count) return 0;
    failed_so_far++;
    return 1;
}

// Record layout: [type u8][pathlen u16][path][off u64][len u32][prevlen u64][data]
#define REC_MAX (1 << 16)            // one record, header included
#define REC_HDR (1 + 2 + 8 + 4 + 8)  // everything but the path and the data

static void emit(char type, const char *path, uint64_t off, const void *data,
                 uint32_t len, uint64_t prevlen) {
    if (log_fd < 0) return;
    uint16_t pl = (uint16_t)strlen(path);
    // One buffered write per record keeps the log's own ordering simple.
    static __thread char buf[REC_MAX];
    size_t n = 0;
    // save_range sizes its chunks to fit; this only guards the buffer.
    if ((size_t)REC_HDR + pl + len > sizeof buf) return;
    buf[n++] = type;
    memcpy(buf + n, &pl, 2); n += 2;
    memcpy(buf + n, path, pl); n += pl;
    memcpy(buf + n, &off, 8); n += 8;
    memcpy(buf + n, &len, 4); n += 4;
    memcpy(buf + n, &prevlen, 8); n += 8;
    if (len) { memcpy(buf + n, data, len); n += len; }
    real_write(log_fd, buf, n);
}

// Before a change lands, keep what it destroys: the bytes of
// [off, off + len) that exist, and the file's length. A range longer than
// one record goes out as several, each carrying the same prior length, so
// an overwrite of any size is undone whole. Replay restores each record's
// bytes and then the length, which undoes a shrink as well as a write
// provided the bytes the shrink cut off were saved here first.
static void save_range(char type, int fd, uint64_t off, uint64_t len) {
    if (fd < 0 || fd >= MAXFD || !fd_path[fd]) return;
    struct stat st;
    if (fstat(fd, &st) != 0) return;
    const char *path = fd_path[fd];
    uint64_t prevlen = (uint64_t)st.st_size;
    size_t pl = strlen(path);
    if (REC_HDR + pl >= REC_MAX) return;
    static __thread char old[REC_MAX];
    uint64_t chunk = REC_MAX - REC_HDR - pl;
    uint64_t end = off;
    if (off < prevlen) end = prevlen - off < len ? prevlen : off + len;
    // Nothing to keep (an append, a growing truncate): the length alone.
    if (end == off) { emit(type, path, off, NULL, 0, prevlen); return; }
    for (uint64_t pos = off; pos < end; pos += chunk) {
        uint32_t keep = (uint32_t)(end - pos < chunk ? end - pos : chunk);
        // pread through the real symbol: this read must not be recorded.
        if (pread(fd, old, keep, (off_t)pos) != (ssize_t)keep) keep = 0;
        emit(type, path, pos, old, keep, prevlen);
    }
}

static void save_before(int fd, uint64_t off, size_t len) {
    save_range('W', fd, off, (uint64_t)len);
}

static size_t iov_total(const struct iovec *iov, int cnt) {
    size_t n = 0;
    for (int i = 0; i < cnt; i++) n += iov[i].iov_len;
    return n;
}

// The offset a positional write lands at: -1 means the file offset.
static uint64_t pos_or_cur(int fd, off64_t off) {
    if (off != -1) return (uint64_t)off;
    off_t cur = lseek(fd, 0, SEEK_CUR);
    return cur < 0 ? 0 : (uint64_t)cur;
}

// Whether an open is about to create its file. It has to be asked BEFORE
// the open: afterwards an O_CREAT open has always found its file, and a
// file this run created would be undone to empty rather than removed.
static int creates(const char *path, int flags) {
    if (in_shim || !(flags & O_CREAT) || !tracked(path)) return 0;
    struct stat st;
    return stat(path, &st) != 0;
}

static void note_open(int fd, const char *path, int created) {
    if (fd < 0 || fd >= MAXFD || !tracked(path)) return;
    free(fd_path[fd]);
    fd_path[fd] = strdup(path);
    if (created) emit('C', path, 0, NULL, 0, 0);
}

int open(const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int created = creates(path, flags);
    int fd = real_open(path, flags, m);
    if (!in_shim) { in_shim = 1; note_open(fd, path, created); in_shim = 0; }
    return fd;
}

int open64(const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int created = creates(path, flags);
    int fd = real_open64 ? real_open64(path, flags, m) : real_open(path, flags, m);
    if (!in_shim) { in_shim = 1; note_open(fd, path, created); in_shim = 0; }
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...) {
    init();
    mode_t m = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); m = va_arg(a, int); va_end(a); }
    int absolute = path && path[0] == '/';
    int created = absolute && creates(path, flags);
    int fd = real_openat(dirfd, path, flags, m);
    if (!in_shim && absolute) { in_shim = 1; note_open(fd, path, created); in_shim = 0; }
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
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_write(fd, buf, n);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, n); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwrite(fd, buf, n, off);
}

ssize_t pwrite64(int fd, const void *buf, size_t n, off64_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, n); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwrite64 ? real_pwrite64(fd, buf, n, off) : real_pwrite(fd, buf, n, (off_t)off);
}

ssize_t writev(int fd, const struct iovec *iov, int cnt) {
    init();
    if (!in_shim && fd < MAXFD && fd >= 0 && fd_path[fd]) {
        in_shim = 1;
        off_t cur = lseek(fd, 0, SEEK_CUR);
        if (cur >= 0) save_before(fd, (uint64_t)cur, iov_total(iov, cnt));
        in_shim = 0;
    }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_writev(fd, iov, cnt);
}

ssize_t pwritev(int fd, const struct iovec *iov, int cnt, off_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, iov_total(iov, cnt)); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwritev(fd, iov, cnt, off);
}

ssize_t pwritev64(int fd, const struct iovec *iov, int cnt, off64_t off) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, (uint64_t)off, iov_total(iov, cnt)); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwritev64 ? real_pwritev64(fd, iov, cnt, off) : real_pwritev(fd, iov, cnt, (off_t)off);
}

ssize_t pwritev2(int fd, const struct iovec *iov, int cnt, off_t off, int flags) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, pos_or_cur(fd, off), iov_total(iov, cnt)); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwritev2(fd, iov, cnt, off, flags);
}

ssize_t pwritev64v2(int fd, const struct iovec *iov, int cnt, off64_t off, int flags) {
    init();
    if (!in_shim) { in_shim = 1; save_before(fd, pos_or_cur(fd, off), iov_total(iov, cnt)); in_shim = 0; }
    if (should_fail(fd)) { errno = EIO; return -1; }
    return real_pwritev64v2 ? real_pwritev64v2(fd, iov, cnt, off, flags)
                            : real_pwritev2(fd, iov, cnt, (off_t)off, flags);
}

// A truncate keeps what a shrink cuts off, so replay puts those bytes back
// rather than re-extending the file with zeros.
static void save_truncate(int fd, uint64_t len) {
    if (!in_shim) { in_shim = 1; save_range('T', fd, len, UINT64_MAX); in_shim = 0; }
}

int ftruncate(int fd, off_t len) {
    init();
    save_truncate(fd, (uint64_t)len);
    return real_ftruncate(fd, len);
}

// A separate symbol from ftruncate, and the one Rust's File::set_len calls.
int ftruncate64(int fd, off64_t len) {
    init();
    save_truncate(fd, (uint64_t)len);
    return real_ftruncate64 ? real_ftruncate64(fd, len) : real_ftruncate(fd, (off_t)len);
}

// Allocation alone changes no byte but may grow the file; punching or
// zeroing changes the range; collapsing or inserting shifts everything
// from `off` on.
static void save_fallocate(int fd, int mode, uint64_t off, uint64_t len) {
    if (in_shim) return;
    in_shim = 1;
    if (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)) save_range('W', fd, off, UINT64_MAX);
    else if (mode & ~FALLOC_FL_KEEP_SIZE) save_range('W', fd, off, len);
    else save_range('W', fd, off, 0);
    in_shim = 0;
}

int fallocate(int fd, int mode, off_t off, off_t len) {
    init();
    save_fallocate(fd, mode, (uint64_t)off, (uint64_t)len);
    return real_fallocate(fd, mode, off, len);
}

int fallocate64(int fd, int mode, off64_t off, off64_t len) {
    init();
    save_fallocate(fd, mode, (uint64_t)off, (uint64_t)len);
    return real_fallocate64 ? real_fallocate64(fd, mode, off, len)
                            : real_fallocate(fd, mode, (off_t)off, (off_t)len);
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
