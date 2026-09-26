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
    /// [`ConnManager::auto_outbound_take_grant`] and goes on as
    /// [`AutoPermits::Held`].
    Parked,
}

/// What finishing an automatic attempt whose permits are held came to
/// ([`ConnManager::auto_outbound_reserve`]).
#[derive(Debug, PartialEq, Eq)]
pub enum AutoBegin {
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

    /// Whether an automatic attempt is parked on the total-connections
    /// semaphore ([`AutoPermits::Parked`]), holding its active-outbounds
    /// permit as dcrd's handler does while blocked in
    /// `totalNormalConnsSem.Acquire`
    /// (`internal/connmgr/connmanager.go:2163`).  It has nothing to do
    /// until a release hands it the permit.
    pub fn auto_outbound_parked(&self) -> bool {
        self.total_normal_conns_sem.is_waiting()
    }

    /// Collect the total-connections permit a release handed the parked
    /// attempt, if one did: dcrd's blocked `Acquire` returning.  The
    /// attempt then holds both permits, as after [`AutoPermits::Held`],
    /// and goes on to pick an address.
    pub fn auto_outbound_take_grant(&mut self) -> bool {
        self.total_normal_conns_sem.take_grant()
    }

    /// Finish an automatic attempt whose two permits are held, given what
    /// `pickOutboundAddr` came to: the per-host permit and the dial
    /// registration (the prologue of dcrd's `dial`).  A failed pick gives
    /// back the two permits, the only reservations not yet tied to an
    /// address; any later failure releases everything through
    /// [`ConnManager::connect_unwind`] over [`ClosePlan::auto_outbound`],
    /// the plan the dial's failure and close run too, so no failure
    /// branch can leak a permit or a group entry on its own.
    ///
    /// Split from the permits and the pick so a daemon can draw the
    /// candidates between the two with its lock on the manager released
    /// (the address source takes the address manager's lock, and dcrd's
    /// pick holds only the outbound groups' mutex).  One pass of dcrd's
    /// sequence is [`ConnManager::auto_outbound_acquire`], then
    /// `pickOutboundAddr` ([`ConnManager::pick_outbound_addr`], or the
    /// daemon's own loop over
    /// [`ConnManager::claim_outbound_candidate`]), then this.
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
}
