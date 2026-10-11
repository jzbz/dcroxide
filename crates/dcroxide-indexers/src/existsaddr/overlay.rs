// SPDX-License-Identifier: ISC
//! The exists-address index's unconfirmed overlay (dcrd `mpExistsAddr`
//! behind `unconfirmedLock`), and the one copy of it that a connect
//! queued for the daemon's index thread brings with it
//! ([`crate::ExistsAddrUnconfirmed::with_copy`]).  dcrd has no copy: its
//! handler goroutine drains the map when it processes the block.

use std::collections::HashSet;
use std::sync::{LockResult, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::Key;

/// The overlay, and the copy the update in progress is to use.
#[derive(Default)]
pub(crate) struct Overlay {
    /// The addresses of the unconfirmed transactions seen so far and not
    /// yet handed to the memtable by a connect.
    keys: RwLock<HashSet<Key>>,
    /// The copy installed for the connect being processed, until that
    /// connect takes it or its caller withdraws it.  A leaf lock: nothing
    /// else is taken while it is held.
    copy: Mutex<Option<Vec<Key>>>,
}

impl Overlay {
    /// The set, for reading (dcrd `unconfirmedLock.RLock`).
    pub(crate) fn read(&self) -> LockResult<RwLockReadGuard<'_, HashSet<Key>>> {
        self.keys.read()
    }

    /// The set, for writing (dcrd `unconfirmedLock.Lock`).
    pub(crate) fn write(&self) -> LockResult<RwLockWriteGuard<'_, HashSet<Key>>> {
        self.keys.write()
    }

    /// The keys the set holds now.
    pub(crate) fn keys(&self) -> Vec<Key> {
        self.read()
            .expect("unconfirmed overlay lock poisoned")
            .iter()
            .copied()
            .collect()
    }

    /// Install the copy the next connect uses, or withdraw it with `None`.
    pub(crate) fn set_copy(&self, copy: Option<Vec<Key>>) {
        *self.copy.lock().expect("overlay copy lock poisoned") = copy;
    }

    /// Take the installed copy, if there is one.
    pub(crate) fn take_copy(&self) -> Option<Vec<Key>> {
        self.copy.lock().expect("overlay copy lock poisoned").take()
    }
}
