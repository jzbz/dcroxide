// SPDX-License-Identifier: ISC
//! Storage with a gate that holds one thread's writes, so a test can stop
//! a metadata commit that runs on a thread of its own at its first write
//! and look at the database while that commit is under way.
//!
//! A database opened with `dcroxide_database::Options::background_commit`
//! makes the redb commit of a flush on a thread named
//! [`COMMITTER_THREAD_NAME`], while the thread that tripped the flush
//! goes on.  How far that commit has got when the test looks is a race
//! unless something holds it.  [`GateBackend`] wraps the store's backend
//! and, while it is armed, blocks every write, length change and sync
//! made on a thread of that name until the test opens the gate.  Going
//! by the thread's name holds the committer and nothing else: the
//! foreground's own flushes, and redb's writes when the last handle is
//! dropped, pass an armed gate untouched.
//!
//! It composes with [`crate::powerloss::PowerLossBackend`]: wrap that one
//! and the test can schedule a power failure while the commit is held,
//! then open the gate onto it.
//!
//! **A commit held while it lengthens the file holds up every
//! transaction.**  redb grows its file, and syncs the longer file, under
//! the lock of its allocator state (redb-4.3.0 `page_manager.rs`, `grow`),
//! and a transaction that begins takes that lock to find the newest
//! commit (`latest_committed_snapshot`).  With real storage that is a
//! wait of one `ftruncate` and one `fsync`.  At a gate it lasts until the
//! gate opens: nothing can begin beside a commit whose first operation is
//! a length change.  [`GateBackend::holds_a_length_change`] says whether
//! that is where the committer was stopped, so a test that goes on to
//! begin transactions beside the held commit can leave them out, or fail
//! at once with the reason.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The name of the thread a [`GateBackend`] holds: the one the database
/// makes a handed-over commit on (`dcroxide_database::COMMIT_THREAD_NAME`,
/// which this crate cannot name without depending on the database crate;
/// the database's tests check that the two agree).
pub const COMMITTER_THREAD_NAME: &str = "dbcommit";

/// The gate's state.
#[derive(Debug, Default)]
struct Gate {
    /// Whether the committer's mutating operations are held.
    armed: bool,
    /// Operations held at the gate now.
    held: usize,
    /// Of those, the length changes.
    held_length_changes: usize,
}

/// Storage that forwards everything to the backend it wraps, and holds
/// the mutating operations of the thread named [`COMMITTER_THREAD_NAME`]
/// while it is armed.
///
/// A held operation has not reached the wrapped backend: it is forwarded
/// only once the gate opens.  So a commit held at its first operation has
/// written nothing, and a power failure scheduled on the wrapped backend
/// while it is held refuses the whole of it.
#[derive(Debug)]
pub struct GateBackend {
    inner: Arc<dyn redb::StorageBackend>,
    gate: Mutex<Gate>,
    changed: Condvar,
}

impl GateBackend {
    /// A gate over `inner`, open.
    pub fn new(inner: Arc<dyn redb::StorageBackend>) -> Arc<GateBackend> {
        Arc::new(GateBackend {
            inner,
            gate: Mutex::new(Gate::default()),
            changed: Condvar::new(),
        })
    }

    /// Shut the gate: from now on the committer's writes, length changes
    /// and syncs wait at it.
    pub fn arm(&self) {
        self.gate.lock().expect("gate lock").armed = true;
    }

    /// Open the gate, letting through whatever waits at it and everything
    /// after.
    pub fn open(&self) {
        self.gate.lock().expect("gate lock").armed = false;
        self.changed.notify_all();
    }

    /// Wait until an operation is held at the gate, for at most
    /// `timeout`; whether one is.
    pub fn wait_held(&self, timeout: Duration) -> bool {
        let deadline = Instant::now().checked_add(timeout);
        let mut gate = self.gate.lock().expect("gate lock");
        while gate.held == 0 {
            let left = deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                return false;
            }
            gate = self.changed.wait_timeout(gate, left).expect("gate lock").0;
        }
        true
    }

    /// Whether an operation is held at the gate now.
    pub fn is_held(&self) -> bool {
        self.gate.lock().expect("gate lock").held > 0
    }

    /// Whether the operation held at the gate now is a change of the
    /// file's length: the committer was stopped while redb was growing
    /// the file, and no transaction can begin until the gate opens (see
    /// the module documentation).
    pub fn holds_a_length_change(&self) -> bool {
        self.gate.lock().expect("gate lock").held_length_changes > 0
    }

    /// Hold the calling thread here while the gate is armed, if it is the
    /// committer.  `length_change` says the operation is a `set_len`.
    fn pass(&self, length_change: bool) {
        if std::thread::current().name() != Some(COMMITTER_THREAD_NAME) {
            return;
        }
        let mut gate = self.gate.lock().expect("gate lock");
        if !gate.armed {
            return;
        }
        gate.held = gate.held.saturating_add(1);
        if length_change {
            gate.held_length_changes = gate.held_length_changes.saturating_add(1);
        }
        self.changed.notify_all();
        while gate.armed {
            gate = self.changed.wait(gate).expect("gate lock");
        }
        gate.held = gate.held.saturating_sub(1);
        if length_change {
            gate.held_length_changes = gate.held_length_changes.saturating_sub(1);
        }
    }
}

impl redb::StorageBackend for GateBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.pass(true);
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.pass(false);
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.pass(false);
        self.inner.write(offset, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::StorageBackend as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Storage that counts the mutating operations that reach it.
    #[derive(Debug, Default)]
    struct Counting {
        ops: AtomicUsize,
    }

    impl redb::StorageBackend for Counting {
        fn len(&self) -> Result<u64, std::io::Error> {
            Ok(0)
        }

        fn read(&self, _: u64, _: &mut [u8]) -> Result<(), std::io::Error> {
            Ok(())
        }

        fn set_len(&self, _: u64) -> Result<(), std::io::Error> {
            self.ops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn sync_data(&self) -> Result<(), std::io::Error> {
            self.ops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn write(&self, _: u64, _: &[u8]) -> Result<(), std::io::Error> {
            self.ops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// An armed gate holds the committer's operations before they reach
    /// the backend and lets every other thread's through; opening it
    /// releases what it held.
    #[test]
    fn an_armed_gate_holds_the_committer_and_nobody_else() {
        let counting = Arc::new(Counting::default());
        let gate = GateBackend::new(Arc::clone(&counting) as Arc<dyn redb::StorageBackend>);
        gate.arm();

        // This thread is not the committer.
        gate.write(0, b"x").expect("write");
        gate.set_len(1).expect("set_len");
        gate.sync_data().expect("sync");
        assert_eq!(counting.ops.load(Ordering::SeqCst), 3);
        assert!(!gate.wait_held(Duration::from_millis(20)));

        let committer = {
            let gate = Arc::clone(&gate);
            std::thread::Builder::new()
                .name(COMMITTER_THREAD_NAME.to_string())
                .spawn(move || {
                    // Reads are never held.
                    gate.read(0, &mut [0u8; 1]).expect("read");
                    gate.write(0, b"y").expect("write");
                    gate.sync_data().expect("sync");
                })
                .expect("spawn")
        };
        assert!(gate.wait_held(Duration::from_secs(60)), "the write is held");
        assert!(gate.is_held());
        assert!(!gate.holds_a_length_change(), "a write is held");
        assert_eq!(
            counting.ops.load(Ordering::SeqCst),
            3,
            "a held operation has not reached the backend"
        );
        gate.open();
        committer.join().expect("committer");
        assert_eq!(counting.ops.load(Ordering::SeqCst), 5);
        assert!(!gate.is_held());
    }

    /// A committer stopped at a length change is told apart from one
    /// stopped at a write or a sync, for as long as it is held.
    #[test]
    fn a_held_length_change_is_told_apart() {
        let counting = Arc::new(Counting::default());
        let gate = GateBackend::new(Arc::clone(&counting) as Arc<dyn redb::StorageBackend>);
        gate.arm();
        let committer = {
            let gate = Arc::clone(&gate);
            std::thread::Builder::new()
                .name(COMMITTER_THREAD_NAME.to_string())
                .spawn(move || {
                    gate.set_len(4096).expect("set_len");
                })
                .expect("spawn")
        };
        assert!(
            gate.wait_held(Duration::from_secs(60)),
            "the length change is held"
        );
        assert!(gate.holds_a_length_change());
        assert_eq!(counting.ops.load(Ordering::SeqCst), 0);
        gate.open();
        committer.join().expect("committer");
        assert!(!gate.holds_a_length_change() && !gate.is_held());
        assert_eq!(counting.ops.load(Ordering::SeqCst), 1);
    }
}
