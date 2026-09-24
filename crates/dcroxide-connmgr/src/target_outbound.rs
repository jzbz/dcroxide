// SPDX-License-Identifier: ISC
//! The reservation sequence of one automatic outbound attempt (dcrd
//! `internal/connmgr` `targetOutboundHandler`'s loop body before it
//! spawns the dial goroutine), so the permits, the outbound group
//! entry, the host permit and the dial registration are taken and
//! given back in the core rather than by each daemon branch.

use dcroxide_addrmgr::NetAddress;

use crate::manager::{ClosePlan, ConnManager};

/// What taking an automatic attempt's two permits came to
/// ([`ConnManager::auto_outbound_acquire`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoPermits {
    /// Both permits are held; the attempt goes on to pick an address.
    Held,
    /// No active-outbound permit is free, and nothing is held.  dcrd
    /// blocks in that acquire; every outbound permit comes back through
    /// an automatic dial's own failure or close, so the daemon waits
    /// and tries again.
    Exhausted,
    /// The active-outbound permit is held and the attempt is parked on
    /// the total-connections semaphore, as dcrd's handler blocks in its
    /// second acquire still holding the first
    /// ([`crate::SemCount::acquire_or_wait`]).  The release that frees a
    /// total permit hands it to the attempt, which collects it with
    /// [`crate::SemCount::take_grant`] and goes on as [`AutoPermits::Held`].
    Parked,
}

/// What one pass of the automatic reservation sequence came to.
#[derive(Debug, PartialEq, Eq)]
pub enum AutoBegin {
    /// No active-outbound or total-connection permit is free.  dcrd
    /// blocks in the acquire; the daemon waits and tries again.
    PermitsExhausted,
    /// The attempt failed after its permits were taken, and everything
    /// it had reserved is released again (a failed attempt for dcrd's
    /// `failedAttempts`).
    Failed,
    /// The dial is registered under `id`.  Its reservations release
    /// through [`ClosePlan::auto_outbound`], on the dial's failure or on
    /// the connection's close.
    Dial {
        /// The connection ID the dial is registered under.
        id: u64,
        /// The picked address.
        addr: NetAddress,
        /// Whether a per-host permit was reserved for it.
        host_permit_reserved: bool,
    },
}

impl ClosePlan {
    /// The reservations an automatic outbound dial holds, as the plan
    /// that releases them: the `onClose` dcrd's `targetOutboundHandler`
    /// hands its dial, removing the outbound group entry and releasing
    /// the host permit (when one was reserved) and both semaphore
    /// permits.
    pub fn auto_outbound(host_permit_reserved: bool) -> ClosePlan {
        ClosePlan {
            remove_outbound_group: true,
            release_total_sem: true,
            release_outbound_sem: true,
            release_host_permit: host_permit_reserved,
            signal_persistent: None,
        }
    }
}

impl ConnManager {
    /// Take the two permits of an automatic attempt in dcrd
    /// `targetOutboundHandler`'s order: the active-outbounds permit, then
    /// the total-connections permit, parking on the latter when it is
    /// full rather than giving the first back ([`AutoPermits::Parked`]).
    pub fn auto_outbound_acquire(&mut self) -> AutoPermits {
        if !self.active_outbounds_sem.try_acquire() {
            return AutoPermits::Exhausted;
        }
        if !self.total_normal_conns_sem.acquire_or_wait() {
            return AutoPermits::Parked;
        }
        AutoPermits::Held
    }

    /// Finish an automatic attempt whose two permits are held, given what
    /// `pickOutboundAddr` came to: the per-host permit and the dial
    /// registration (the prologue of dcrd's `dial`).  A failed pick gives
    /// back the two permits, the only reservations not yet tied to an
    /// address; any later failure releases everything through
    /// [`ConnManager::connect_unwind`] over [`ClosePlan::auto_outbound`],
    /// the plan the dial's failure and close run too, so no failure
    /// branch can leak a permit or a group entry on its own.  Never
    /// [`AutoBegin::PermitsExhausted`].
    ///
    /// Split from the permits and the pick so a daemon can draw the
    /// candidates between the two with its lock on the manager released
    /// (the address source takes the address manager's lock, and dcrd's
    /// pick holds only the outbound groups' mutex).
    pub fn auto_outbound_reserve(&mut self, picked: Result<NetAddress, String>) -> AutoBegin {
        let addr = match picked {
            Ok(addr) => addr,
            Err(_) => {
                // Nothing is tied to an address yet: only the two
                // permits.
                self.total_normal_conns_sem.release();
                self.active_outbounds_sem.release();
                return AutoBegin::Failed;
            }
        };
        let (host_permit_reserved, begun) = match self.maybe_reserve_host_permit(&addr) {
            Ok(reserved) => (reserved, self.begin_dial(&addr, None)),
            Err(e) => (false, Err(e)),
        };
        match begun {
            Ok(id) => AutoBegin::Dial {
                id,
                addr,
                host_permit_reserved,
            },
            Err(_) => {
                self.connect_unwind(&addr, &ClosePlan::auto_outbound(host_permit_reserved));
                AutoBegin::Failed
            }
        }
    }

    /// One pass of dcrd `targetOutboundHandler`'s reservation sequence,
    /// in its order: the active-outbounds permit, the total-connections
    /// permit, `pickOutboundAddr` (which registers the address's group),
    /// the per-host permit, and the dial registration (the prologue of
    /// dcrd's `dial`).  dcrd blocks in the two acquires; here a permit
    /// that is not free ends the pass with
    /// [`AutoBegin::PermitsExhausted`], holding nothing (the daemon's
    /// fill instead parks on the total permit through
    /// [`ConnManager::auto_outbound_acquire`]).  Once the permits are
    /// held the pass finishes as [`ConnManager::auto_outbound_reserve`]
    /// does.  The source returns each candidate with its last attempt
    /// time in nanoseconds, as [`ConnManager::pick_outbound_addr`] takes
    /// it, and runs with the manager borrowed.
    pub fn auto_outbound_begin(
        &mut self,
        get_new_address: &mut dyn FnMut() -> Result<(NetAddress, i64), String>,
        now_nanos: i64,
    ) -> AutoBegin {
        if !self.active_outbounds_sem.try_acquire() {
            return AutoBegin::PermitsExhausted;
        }
        if !self.total_normal_conns_sem.try_acquire() {
            self.active_outbounds_sem.release();
            return AutoBegin::PermitsExhausted;
        }
        let picked = self.pick_outbound_addr(get_new_address, now_nanos);
        self.auto_outbound_reserve(picked)
    }
}
