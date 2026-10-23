// SPDX-License-Identifier: ISC
//! The daemon's log file: a port of `jrick/logrotate` v1.1.2's
//! `rotator.Rotator` (`rotator/rotator.go`), which dcrd writes
//! `dcrd.log` through (`log.go:124-144`).  Only what dcrd uses is
//! ported: the `Write` path (dcrd never calls `Run`), no copy to
//! standard output (dcrd passes `tee` false and its `logWriter` writes
//! standard output itself), and the default compressor, gzip at the
//! default level with the `gz` suffix (dcrd never calls
//! `SetCompressor`).
//!
//! The rotator appends to the file and counts its bytes, starting from
//! the size the file had when opened.  Once a write that ends in a
//! newline brings the count to the threshold, 1000 bytes for every KiB
//! asked for (QUIRKS.md, QK-0029), it closes the file, renames it to
//! `<name>.<N>` with N one past the highest roll number beside it,
//! deletes the compressed rolls from the roll count behind the new one
//! downwards, reopens the name, and queues the roll for the compression
//! thread, which gzips the rolls one at a time to `<name>.<N>.gz`,
//! removing each uncompressed roll once its archive is written.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;

use crate::gostd::GoPathError;

/// The suffix of a compressed roll (`zSuffix`, `rotator.go:85`).
const COMPRESSED_SUFFIX: &str = "gz";

/// The name of the compression thread.
const COMPRESS_THREAD_NAME: &str = "log-compress";

/// Other handles may read the file while it is open (Windows'
/// `FILE_SHARE_READ`).
#[cfg(windows)]
const FILE_SHARE_READ: u32 = 0x0000_0001;

/// Other handles may write the file while it is open (Windows'
/// `FILE_SHARE_WRITE`).
#[cfg(windows)]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

/// A log file rotated once it reaches a size (`rotator.Rotator`).
pub(crate) struct Rotator {
    /// The file's size when opened plus every byte written to it since
    /// (`size`).
    size: i64,
    /// The size at which a write ending in a newline rotates the file
    /// (`threshold`).
    threshold: i64,
    /// How many rolls to keep; at zero or below every roll is kept
    /// (`maxRolls`, a Go `int`).
    max_rolls: isize,
    /// The log file's path (`filename`).
    filename: String,
    /// The open log file.  `None` once a rotation has failed after
    /// closing it, where Go's rotator is left holding a closed or nil
    /// `*os.File` (`out`).
    out: Option<File>,
    /// Taken by each compression for its whole run, so they run one at
    /// a time (`zMu`).  With one compression thread, and a roll gzipped
    /// inline only when there is none, they never contend for it; a
    /// test holds it to keep the compressions back.
    compressing: Arc<Mutex<()>>,
    /// The thread gzipping the rolls and the queue feeding it, once a
    /// rotation has started it, where Go's rotator starts a goroutine
    /// per roll and counts them in `wg`.
    compressor: Option<Compressor>,
}

/// The compression thread: it gzips the rolls queued to it in the order
/// they were made, and ends once the rotator lets go of the queue.
struct Compressor {
    /// Where each rotation queues its roll.
    queue: mpsc::Sender<String>,
    /// The thread, joined to wait for the rolls queued so far.
    thread: JoinHandle<()>,
}

impl Rotator {
    /// Open the log file at `filename`, creating it if need be, to
    /// rotate once `threshold_kb` thousand bytes have been written to
    /// it, keeping `max_rolls` rolls (`rotator.New`,
    /// `rotator.go:66-87`).  It is opened as `os.OpenFile(filename,
    /// O_CREATE|O_APPEND|O_RDWR, 0644)` opens it ([`go_open_options`]),
    /// and the size it already has counts toward the threshold.  The
    /// errors are the `*os.PathError`s of Go's open and stat.
    pub(crate) fn new(
        filename: &str,
        threshold_kb: i64,
        max_rolls: isize,
    ) -> Result<Rotator, GoPathError> {
        let opened = go_open_options()
            .create(true)
            .append(true)
            .read(true)
            .open(filename);
        let out = opened.map_err(|err| GoPathError {
            op: "open",
            path: filename.to_string(),
            err,
        })?;
        let size = out.metadata().map_err(|err| GoPathError {
            op: "stat",
            path: filename.to_string(),
            err,
        })?;
        Ok(Rotator {
            size: i64::try_from(size.len()).unwrap_or(i64::MAX),
            // Go's int64 arithmetic; the configuration's 32-bit size
            // keeps it far from wrapping (`config.go:888-890`).
            threshold: threshold_kb.wrapping_mul(1000),
            max_rolls,
            filename: filename.to_string(),
            out: Some(out),
            compressing: Arc::new(Mutex::new(())),
            compressor: None,
        })
    }

    /// Write `p` to the log file, then rotate the file if its count has
    /// reached the threshold and `p` ends in a newline (`Rotator.Write`,
    /// `rotator.go:156-171`).  A failed write counts the bytes that
    /// reached the file and is otherwise ignored.  A failed rotation is
    /// returned, as Go returns `0, err`, and the count is left as it
    /// is, so the next line tries again; dcrd's `logWriter` discards
    /// both results.
    pub(crate) fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let n = match self.out.as_mut() {
            Some(out) => write_counted(out, p),
            None => 0,
        };
        self.size = self.size.wrapping_add(i64::try_from(n).unwrap_or(i64::MAX));
        if self.size >= self.threshold && p.last() == Some(&b'\n') {
            self.rotate()?;
            self.size = 0;
        }
        Ok(n)
    }

    /// Close the log file, then wait for the compressions under way and
    /// queued (`Rotator.Close`, `rotator.go:173-178`).
    pub(crate) fn close(&mut self) {
        self.out = None;
        self.wait_compressed();
    }

    /// Wait for every roll queued so far to be compressed (`r.wg.Wait()`):
    /// let go of the queue and join the thread, which the next rotation
    /// starts again.
    fn wait_compressed(&mut self) {
        if let Some(Compressor { queue, thread }) = self.compressor.take() {
            drop(queue);
            let _ = thread.join();
        }
    }

    /// Roll the log file over (`Rotator.rotate`, `rotator.go:180-250`).
    fn rotate(&mut self) -> io::Result<()> {
        let max_num = self.highest_roll();

        // `r.out.Close()`.  After a rotation that failed past this point
        // Go's rotator holds a closed file, or nil, and `Close` fails on
        // either, so the log file takes nothing more until a restart.
        // std reports no error from a close, which Go returns.
        let Some(out) = self.out.take() else {
            return Err(io::Error::other("file already closed"));
        };
        drop(out);

        // Go's `int` arithmetic, wrapping as it does.
        let next = max_num.wrapping_add(1);
        let rotname = format!("{}.{next}", self.filename);
        std::fs::rename(&self.filename, &rotname)?;

        // Delete the compressed rolls from `max_rolls` behind the new
        // one downwards, stopping at the first that cannot be removed:
        // a gap left by a roll deleted by hand, or one still waiting to
        // be compressed, stops the deletion, and an uncompressed roll is
        // never deleted.
        if self.max_rolls > 0 {
            let mut n = next.wrapping_sub(self.max_rolls);
            while n >= 1 {
                let name = format!("{}.{n}.{COMPRESSED_SUFFIX}", self.filename);
                if go_remove(&name).is_err() {
                    break;
                }
                n = n.wrapping_sub(1);
            }
        }

        // `os.OpenFile(r.filename, os.O_CREATE|os.O_RDWR, 0644)`: no
        // `O_APPEND` this time, so a file someone created under the name
        // in the meantime is written from its start.
        let reopened = go_open_options()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.filename);
        self.out = Some(reopened?);

        self.compress_in_background(rotname);
        Ok(())
    }

    /// The highest roll number among the files beside the log file whose
    /// names are the log file's, a dot and anything more, as `rotate`'s
    /// glob of `<name>.*` finds them (`rotator.go:181-205`), or zero.  A
    /// directory that cannot be read reads as empty, as `filepath.Glob`
    /// ignores I/O errors.  The directory is listed rather than globbed,
    /// so a log directory whose path holds a glob metacharacter still
    /// has its rolls found (PARITY.md, *The log file*).
    fn highest_roll(&self) -> isize {
        let path = Path::new(&self.filename);
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        let Some(base) = path.file_name() else {
            return 0;
        };
        let mut prefix = base.as_encoded_bytes().to_vec();
        prefix.push(b'.');
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| roll_number(entry.file_name().as_encoded_bytes(), &prefix))
            .fold(0, isize::max)
    }

    /// Queue the roll at `rotname` to be gzipped and removed once the
    /// archive is written (the goroutine `rotate` starts for each roll,
    /// `rotator.go:235-247`).  One thread takes the rolls in turn, so a
    /// small `--logsize` queues rolls rather than starting a thread for
    /// each.  The first roll, and the first after the thread was joined,
    /// starts it; if it cannot be started the roll is gzipped before the
    /// write returns, where a goroutine cannot fail to start.
    fn compress_in_background(&mut self, rotname: String) {
        let rotname = match &self.compressor {
            Some(compressor) => match compressor.queue.send(rotname) {
                Ok(()) => return,
                // The thread ended early, which only a panic in it does.
                Err(mpsc::SendError(rotname)) => rotname,
            },
            None => rotname,
        };
        self.wait_compressed();
        let (queue, queued) = mpsc::channel::<String>();
        let turn = Arc::clone(&self.compressing);
        let first = rotname.clone();
        let spawned = std::thread::Builder::new()
            .name(COMPRESS_THREAD_NAME.to_string())
            .spawn(move || {
                for rotname in std::iter::once(first).chain(queued) {
                    compress_roll(&rotname, &turn);
                }
            });
        match spawned {
            Ok(thread) => self.compressor = Some(Compressor { queue, thread }),
            Err(_) => compress_roll(&rotname, &self.compressing),
        }
    }
}

/// The roll number in a file name beside the log file, which must start
/// with the log file's name and a dot (`prefix`): its last dot-separated
/// part, or the part before that when the last is `gz`, read as Go's
/// `strconv.Atoi` reads it, an optional sign and decimal digits that fit
/// an `int` (`rotator.go:189-204`).  Go splits the whole path, but with
/// the prefix holding two dots those parts are always the name's.
fn roll_number(name: &[u8], prefix: &[u8]) -> Option<isize> {
    if !name.starts_with(prefix) {
        return None;
    }
    let mut parts = name.rsplit(|&b| b == b'.');
    let mut part = parts.next()?;
    if part == COMPRESSED_SUFFIX.as_bytes() {
        part = parts.next()?;
    }
    std::str::from_utf8(part).ok()?.parse().ok()
}

/// Write all of `p` as Go's `os.File.Write` does, returning how many
/// bytes reached the file: after a short write or an interrupted one it
/// writes the rest, and it stops at an error or a write of nothing
/// (`internal/poll/fd_unix.go` `FD.Write`).  Each line is one write
/// straight to the file, with no buffer in between, so what was logged
/// before an abort is in the file.
fn write_counted(out: &mut File, p: &[u8]) -> usize {
    let mut written = 0usize;
    while let Some(rest) = p.get(written..).filter(|rest| !rest.is_empty()) {
        match out.write(rest) {
            Ok(0) => break,
            Ok(n) => written = written.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    written
}

/// Gzip one roll and remove it if that succeeded, holding the turn the
/// compressions take one at a time.
fn compress_roll(rotname: &str, turn: &Mutex<()>) {
    let _turn = turn.lock().unwrap_or_else(PoisonError::into_inner);
    if compress(rotname).is_ok() {
        let _ = go_remove(rotname);
    }
}

/// Write the gzip of the file at `name` to `<name>.gz` (`Rotator.compress`,
/// `rotator.go:252-279`).  The archive is created `0644` with
/// `O_CREATE|O_EXCL|O_WRONLY`, so one already there fails the
/// compression and leaves the roll uncompressed.  Its header is the one
/// Go's `gzip.Writer` writes with an empty `Header`: no name, comment or
/// time, no extra flags at the default level, and an unknown operating
/// system.
///
/// Go's compression fails, keeping the roll, when the archive's close
/// fails.  std reports no error from a close, so the archive is synced
/// before it is closed instead: a write the close would have reported
/// as failed, such as one an NFS server refused, fails the sync, and
/// the roll is kept (PARITY.md, *The log file*).
fn compress(name: &str) -> io::Result<()> {
    let mut f = go_open_options().read(true).open(name)?;
    let arc = go_open_options()
        .write(true)
        .create_new(true)
        .open(format!("{name}.{COMPRESSED_SUFFIX}"))?;
    let mut zw = flate2::write::GzEncoder::new(arc, flate2::Compression::default());
    io::copy(&mut f, &mut zw)?;
    zw.finish()?.sync_data()
}

/// Remove the file or empty directory at `name`, as Go's `os.Remove`
/// does: when unlinking it fails, it is removed as a directory
/// (`os/file_unix.go` `Remove`).  The error is the unlink's.
fn go_remove(name: &str) -> io::Result<()> {
    std::fs::remove_file(name).or_else(|err| std::fs::remove_dir(name).map_err(|_| err))
}

/// Open options set as Go's `os.OpenFile` sets what its flags leave
/// open.  A file it creates is `0644` less the umask; off Unix Go's mode
/// sets only the read-only attribute, which `0644` leaves clear, as std
/// does.  On Windows, while the file is open, other handles may read
/// and write it but not delete or rename it (`FILE_SHARE_READ |
/// FILE_SHARE_WRITE`, `syscall/syscall_windows.go` `Open`), where std
/// shares deletion too: so no other process can delete or rename the
/// log file while the node has it open, and an archive still being
/// written stops the deletion of old rolls, as with dcrd.
fn go_open_options() -> OpenOptions {
    #[cfg_attr(not(any(unix, windows)), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    options
}

#[cfg(test)]
// Test-harness arithmetic over small lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::Read;

    /// The log file's path in a test directory.
    fn log_path(dir: &tempfile::TempDir) -> String {
        dir.path()
            .join("dcroxide.log")
            .to_string_lossy()
            .into_owned()
    }

    /// The names in a directory, sorted.
    fn names(dir: &tempfile::TempDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The decompressed content of a gzip file.
    fn gunzip(path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(File::open(path).unwrap())
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// A line of `len` bytes, the newline included.
    fn line(len: usize, fill: u8) -> Vec<u8> {
        let mut line = vec![fill; len - 1];
        line.push(b'\n');
        line
    }

    /// dcrd's default `--logsize` of 10M is 10,240 KiB, and the rotator
    /// multiplies by 1000, not 1024 (QK-0029).
    #[test]
    fn a_kib_of_threshold_is_a_thousand_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let rotator = Rotator::new(&log_path(&dir), 10 << 10, 3).unwrap();
        assert_eq!(rotator.threshold, 10_240_000);
    }

    /// A line that brings the file to the threshold rotates it after it
    /// is written, so the roll holds that line; one that stops short
    /// does not.
    #[test]
    fn a_line_reaching_the_threshold_rotates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 1, 3).unwrap();

        assert_eq!(rotator.write(&line(999, b'a')).unwrap(), 999);
        assert_eq!(names(&dir), ["dcroxide.log"]);
        assert_eq!(rotator.write(&line(1, b'b')).unwrap(), 1);
        rotator.wait_compressed();
        assert_eq!(names(&dir), ["dcroxide.log", "dcroxide.log.1.gz"]);
        let mut first = line(999, b'a');
        first.extend(line(1, b'b'));
        assert_eq!(gunzip(&format!("{path}.1.gz")), first);
        assert_eq!(std::fs::read(&path).unwrap(), b"");

        // Past the threshold in one line rotates too.
        rotator.write(&line(1500, b'c')).unwrap();
        rotator.close();
        assert_eq!(
            names(&dir),
            ["dcroxide.log", "dcroxide.log.1.gz", "dcroxide.log.2.gz"]
        );
        assert_eq!(gunzip(&format!("{path}.2.gz")), line(1500, b'c'));
    }

    /// Only a write ending in a newline rotates, however far past the
    /// threshold the file is.
    #[test]
    fn a_write_without_a_newline_does_not_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 1, 3).unwrap();

        rotator.write(&[b'x'; 2000]).unwrap();
        assert_eq!(names(&dir), ["dcroxide.log"]);
        rotator.write(b"\n").unwrap();
        rotator.close();
        assert_eq!(names(&dir), ["dcroxide.log", "dcroxide.log.1.gz"]);
        let mut first = vec![b'x'; 2000];
        first.push(b'\n');
        assert_eq!(gunzip(&format!("{path}.1.gz")), first);
    }

    /// Rolls are numbered from one; once there are more than three, the
    /// oldest compressed roll goes, so three are kept beside the file.
    /// A threshold of zero (`--logsize=0K`) rotates after every line.
    #[test]
    fn three_rolls_are_kept_and_the_oldest_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 0, 3).unwrap();

        for n in 1..=5 {
            rotator.write(format!("line {n}\n").as_bytes()).unwrap();
            // Each compression finishes before the next rotation, which
            // a slower log leaves it to do on its own.
            rotator.wait_compressed();
        }
        rotator.close();
        assert_eq!(
            names(&dir),
            [
                "dcroxide.log",
                "dcroxide.log.3.gz",
                "dcroxide.log.4.gz",
                "dcroxide.log.5.gz"
            ]
        );
        for n in 3..=5 {
            assert_eq!(
                gunzip(&format!("{path}.{n}.gz")),
                format!("line {n}\n").into_bytes()
            );
        }
    }

    /// A roll's gzip decompresses to the bytes the file held, and its
    /// header is byte for byte the one Go's `gzip.Writer` writes:
    /// deflate, no flags, no time, no extra flags, unknown OS.
    #[test]
    fn a_roll_is_gzipped_with_gos_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 10, 3).unwrap();

        let mut written = Vec::new();
        let mut n = 0u32;
        while written.len() < 10_000 {
            let line = format!(
                "2026-10-23 12:00:00.000 [INF] SYNC: Processed {n} blocks ({:x})\n",
                n.wrapping_mul(2_654_435_761)
            );
            rotator.write(line.as_bytes()).unwrap();
            written.extend_from_slice(line.as_bytes());
            n = n.wrapping_add(1);
        }
        rotator.close();

        let gz = std::fs::read(format!("{path}.1.gz")).unwrap();
        assert_eq!(gz[..10], [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
        assert!(gz.len() < written.len() / 2, "the roll was not compressed");
        assert_eq!(gunzip(&format!("{path}.1.gz")), written);
        assert!(!Path::new(&format!("{path}.1")).exists());
    }

    /// A restart appends to the file it finds, and its size counts
    /// toward the threshold.
    #[test]
    fn a_restart_appends_and_counts_what_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);

        let mut rotator = Rotator::new(&path, 1, 3).unwrap();
        rotator.write(&line(995, b'a')).unwrap();
        rotator.close();

        let mut rotator = Rotator::new(&path, 1, 3).unwrap();
        assert_eq!(rotator.size, 995);
        rotator.write(&line(4, b'b')).unwrap();
        let mut expected = line(995, b'a');
        expected.extend(line(4, b'b'));
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert_eq!(names(&dir), ["dcroxide.log"]);

        // 999 bytes there and one more line of one reaches 1000.
        rotator.write(b"\n").unwrap();
        rotator.close();
        expected.push(b'\n');
        assert_eq!(names(&dir), ["dcroxide.log", "dcroxide.log.1.gz"]);
        assert_eq!(gunzip(&format!("{path}.1.gz")), expected);
    }

    /// A file already over the threshold is not rotated when opened,
    /// only after the first line written to it.
    #[test]
    fn a_file_over_the_threshold_rotates_after_the_next_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        std::fs::write(&path, vec![b'o'; 2000]).unwrap();

        let mut rotator = Rotator::new(&path, 1, 3).unwrap();
        assert_eq!(names(&dir), ["dcroxide.log"]);
        rotator.write(b"next\n").unwrap();
        rotator.close();
        let mut expected = vec![b'o'; 2000];
        expected.extend_from_slice(b"next\n");
        assert_eq!(gunzip(&format!("{path}.1.gz")), expected);
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }

    /// The numbering continues from the highest roll already there,
    /// and the deletion stops at the first compressed roll it cannot
    /// remove, so rolls past a gap stay, as does an uncompressed one.
    #[test]
    fn numbering_continues_and_a_gap_stops_the_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        for name in ["dcroxide.log.1", "dcroxide.log.2.gz", "dcroxide.log.7.gz"] {
            std::fs::write(dir.path().join(name), b"old").unwrap();
        }

        let mut rotator = Rotator::new(&path, 0, 3).unwrap();
        rotator.write(b"eighth\n").unwrap();
        rotator.wait_compressed();
        // The eighth roll deletes from the fifth down; there is none.
        assert_eq!(
            names(&dir),
            [
                "dcroxide.log",
                "dcroxide.log.1",
                "dcroxide.log.2.gz",
                "dcroxide.log.7.gz",
                "dcroxide.log.8.gz"
            ]
        );
        for n in 9..=10 {
            rotator.write(format!("roll {n}\n").as_bytes()).unwrap();
            rotator.wait_compressed();
        }
        rotator.close();
        // The tenth deletes the seventh, finds no sixth and stops: the
        // second stays, and the uncompressed first is never a target.
        assert_eq!(
            names(&dir),
            [
                "dcroxide.log",
                "dcroxide.log.1",
                "dcroxide.log.10.gz",
                "dcroxide.log.2.gz",
                "dcroxide.log.8.gz",
                "dcroxide.log.9.gz"
            ]
        );
        assert_eq!(gunzip(&format!("{path}.8.gz")), b"eighth\n");
    }

    /// Rolls made while a compression is under way queue behind it on
    /// the one compression thread.  They are numbered in turn, the
    /// deletion stops at the first roll still waiting to be compressed,
    /// as dcrd's does, and the close waits for every one.  The test holds
    /// the compressions' turn, so the thread compresses nothing until it
    /// lets go.
    #[test]
    fn rolls_queue_behind_a_compression_under_way() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 0, 3).unwrap();

        let turn = Arc::clone(&rotator.compressing);
        let held = turn.lock().unwrap();
        for n in 1..=5 {
            rotator.write(format!("line {n}\n").as_bytes()).unwrap();
        }
        // The fourth and fifth rotations found no `.1.gz` or `.2.gz` to
        // delete and stopped there.
        assert_eq!(
            names(&dir),
            [
                "dcroxide.log",
                "dcroxide.log.1",
                "dcroxide.log.2",
                "dcroxide.log.3",
                "dcroxide.log.4",
                "dcroxide.log.5"
            ]
        );
        drop(held);
        rotator.close();
        assert_eq!(
            names(&dir),
            [
                "dcroxide.log",
                "dcroxide.log.1.gz",
                "dcroxide.log.2.gz",
                "dcroxide.log.3.gz",
                "dcroxide.log.4.gz",
                "dcroxide.log.5.gz"
            ]
        );
        for n in 1..=5 {
            assert_eq!(
                gunzip(&format!("{path}.{n}.gz")),
                format!("line {n}\n").into_bytes()
            );
        }
    }

    /// An empty directory where a compressed roll would be is removed
    /// and the deletion goes on, as Go's `os.Remove` removes one.
    #[test]
    fn an_empty_directory_in_a_rolls_place_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        std::fs::write(dir.path().join("dcroxide.log.4.gz"), b"old").unwrap();
        std::fs::create_dir(dir.path().join("dcroxide.log.5.gz")).unwrap();
        std::fs::write(dir.path().join("dcroxide.log.7.gz"), b"old").unwrap();

        let mut rotator = Rotator::new(&path, 0, 3).unwrap();
        rotator.write(b"eighth\n").unwrap();
        rotator.close();
        // The eighth deletes from the fifth down: the directory, the
        // fourth, and no third, where it stops.
        assert_eq!(
            names(&dir),
            ["dcroxide.log", "dcroxide.log.7.gz", "dcroxide.log.8.gz"]
        );
    }

    /// Roll numbers are read from the names as dcrd's rotator reads
    /// them: the last dot-separated part, or the one before a `gz`,
    /// through `strconv.Atoi`.
    #[test]
    fn roll_numbers_are_read_as_go_reads_them() {
        let prefix = b"dcroxide.log.";
        for (name, number) in [
            ("dcroxide.log.5", Some(5)),
            ("dcroxide.log.5.gz", Some(5)),
            ("dcroxide.log.007.gz", Some(7)),
            ("dcroxide.log.+12", Some(12)),
            ("dcroxide.log.-3.gz", Some(-3)),
            ("dcroxide.log.old.9", Some(9)),
            ("dcroxide.log.5.tmp", None),
            ("dcroxide.log.5.gz.gz", None),
            ("dcroxide.log.gz", None),
            ("dcroxide.log.", None),
            ("dcroxide.log.+", None),
            ("dcroxide.log.99999999999999999999", None),
            ("dcroxide.log", None),
            ("dcroxide.logs.5", None),
            ("dcrd.log.5", None),
        ] {
            assert_eq!(roll_number(name.as_bytes(), prefix), number, "{name}");
        }
    }

    /// A rotation that fails after closing the file leaves the log
    /// file taking nothing more, as dcrd's rotator is left with a closed
    /// file: here the rename fails because the directory went away.
    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_stops_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("logs");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("dcroxide.log").to_string_lossy().into_owned();
        let mut rotator = Rotator::new(&path, 1, 3).unwrap();

        std::fs::remove_dir_all(&sub).unwrap();
        assert!(rotator.write(&line(1000, b'a')).is_err());
        std::fs::create_dir(&sub).unwrap();
        assert!(rotator.write(b"after\n").is_err());
        rotator.close();
        assert_eq!(std::fs::read_dir(&sub).unwrap().count(), 0);
    }

    /// The file and the archive are created `0644` less the umask, as
    /// a file std creates `0644` is.
    #[cfg(unix)]
    #[test]
    fn files_are_created_as_dcrds_are() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let reference = dir.path().join("reference");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&reference)
            .unwrap();
        let mode = |path: &str| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let expected = mode(&reference.to_string_lossy());

        let path = log_path(&dir);
        let mut rotator = Rotator::new(&path, 0, 3).unwrap();
        rotator.write(b"one\n").unwrap();
        rotator.close();
        assert_eq!(mode(&path), expected);
        assert_eq!(mode(&format!("{path}.1.gz")), expected);
    }

    /// The open error is Go's `*os.PathError`.
    #[cfg(unix)]
    #[test]
    fn an_open_error_reads_as_gos() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("missing")
            .join("dcroxide.log")
            .to_string_lossy()
            .into_owned();
        let err = Rotator::new(&path, 1, 3).err().unwrap();
        assert_eq!(
            err.to_string(),
            format!("open {path}: no such file or directory")
        );
    }
}
