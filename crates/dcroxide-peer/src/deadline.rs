// SPDX-License-Identifier: ISC
//! The stall detector: the response deadline tables and the state dcrd's
//! `stallHandler` goroutine owns (dcrd peer `pendingDeadlines`,
//! `maybeAddDeadline`, `maybeRemoveDeadline`, `checkDeadlines`, and
//! `stallHandler`).
//!
//! A peer that asks for data and then never answers must not be able to
//! pin the requester forever: dcrd arms a deadline whenever it sends a
//! message that expects a response, clears it when the response
//! arrives, and disconnects the peer when a deadline passes.  The
//! deadlines are adjusted forward by the time spent inside the message
//! callbacks, because the next message is not read until the previous
//! one has finished processing — without that adjustment a slow local
//! operation (a long block validation, say) would look exactly like a
//! remote stall and disconnect honest peers.
//!
//! # Per-inventory accountability
//!
//! `release-v2.1.5` kept one table keyed by the *command* a response
//! would arrive as, and armed the whole group a `getdata` could be
//! answered with — so any single delivery cleared every entry.  With 16
//! block requests in flight that let a peer deliver one block just
//! inside the timeout and thereby settle all sixteen, keeping the slots
//! pinned indefinitely while the chain made no progress.
//!
//! Master splits the state in two ([`PendingDeadlines`]): `getdata`
//! arms one deadline per requested [`InvVect`], and only the matching
//! block, transaction, mix message, or `notfound` entry settles it.
//! Each requested item is accountable on its own.  A separate
//! command-keyed table carries the one remaining request that is not
//! inventory-shaped, `getinitstate`.
//!
//! The pure table operations live here so the daemon's stall thread and
//! the parity vectors share one implementation; [`StallDetector`] wraps
//! them in the state dcrd keeps in its `stallHandler` stack frame.

use std::collections::HashMap;
use std::time::Instant;

use dcroxide_chainhash::Hash;
use dcroxide_wire::{InvType, InvVect, MAX_INV_PER_MSG, Message};

use crate::STALL_RESPONSE_TIMEOUT;

/// How much inventory a peer may have outstanding before serving any of
/// it (dcrd's `maxBurst` inside `maybeAddDeadline`): one full inventory
/// message plus half again.  A `getdata` that would push the pending
/// count past this is refused and the peer disconnected, which stops a
/// peer running far ahead with announcements it never answers.
pub const MAX_PENDING_INV_BURST: usize = MAX_INV_PER_MSG as usize + (MAX_INV_PER_MSG as usize) / 2;

/// The command a `getinitstate` expects back.
const CMD_INIT_STATE: &str = "initstate";

/// What a pending response is waiting for, used to report which one
/// stalled (dcrd's `checkDeadlines` error text, built from a bare
/// command or from `invVectSummary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallReason {
    /// A command-keyed response never arrived (dcrd's `pendingCmds`).
    Command(&'static str),
    /// A requested inventory item was never served (dcrd's
    /// `pendingData`).
    Inventory(InvVect),
}

impl StallReason {
    /// The full text dcrd's `checkDeadlines` returns for this reason.
    pub fn exceeded_text(&self) -> String {
        format!("deadline exceeded for {self}")
    }
}

impl core::fmt::Display for StallReason {
    /// Renders a command bare and an inventory item through dcrd's
    /// `invVectSummary` (peer `log.go`), which the stall log quotes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StallReason::Command(cmd) => f.write_str(cmd),
            StallReason::Inventory(iv) => {
                let kind = match iv.inv_type {
                    InvType::ERROR => "error",
                    InvType::TX => "tx",
                    InvType::BLOCK => "block",
                    InvType::FILTERED_BLOCK => "filtered block",
                    InvType::MIX => "mix message",
                    InvType(other) => return write!(f, "unknown ({other}) {}", iv.hash),
                };
                write!(f, "{kind} {}", iv.hash)
            }
        }
    }
}

/// What a received message settles in the pending tables — the message
/// arms of dcrd's `maybeRemoveDeadline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settles {
    /// The message answers nothing that could have been pending.
    Nothing,
    /// One requested inventory item.
    Inventory(InvVect),
    /// Every item a `notfound` lists, each settled the same way a
    /// delivery would settle it.
    Inventories(Vec<InvVect>),
    /// A command-keyed response.
    Command(&'static str),
}

/// Classify what a received message settles.
///
/// `mix_hash` supplies the mixing-message identity hash for the eight
/// mix commands and is ignored for everything else.  dcrd computes that
/// hash once in `readMessage` — immediately after deserializing, via
/// the `hashable` interface — and caches it on the message, so
/// `maybeRemoveDeadline` only reads it back.  dcroxide keeps the hash
/// out of the wire types, so the reader computes it once and passes it
/// here, which is the same single-hash-per-message shape.
///
/// Passing `None` for a mixing message settles nothing, leaving its
/// deadline armed; callers serving mix traffic must supply the hash or
/// honest mixing peers will eventually be disconnected.
pub fn settles(msg: &Message, mix_hash: Option<Hash>) -> Settles {
    match msg {
        Message::Block(block) => Settles::Inventory(InvVect {
            inv_type: InvType::BLOCK,
            hash: block.block_hash(),
        }),
        Message::Tx(tx) => Settles::Inventory(InvVect {
            inv_type: InvType::TX,
            hash: tx.tx_hash(),
        }),
        Message::MixPairReq(_)
        | Message::MixKeyExchange(_)
        | Message::MixCiphertexts(_)
        | Message::MixSlotReserve(_)
        | Message::MixFactoredPoly(_)
        | Message::MixDCNet(_)
        | Message::MixConfirm(_)
        | Message::MixSecrets(_) => match mix_hash {
            Some(hash) => Settles::Inventory(InvVect {
                inv_type: InvType::MIX,
                hash,
            }),
            None => Settles::Nothing,
        },
        Message::NotFound(not_found) => Settles::Inventories(not_found.inv_list.clone()),
        Message::InitState(_) => Settles::Command(CMD_INIT_STATE),
        _ => Settles::Nothing,
    }
}

/// The outcome of arming deadlines for a message about to be sent.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmOutcome {
    /// Any deadlines the message expects are armed.  Messages that
    /// expect no response also report this.
    Armed,
    /// The peer already has too much inventory outstanding without
    /// serving it, so nothing was armed and it must be disconnected
    /// (dcrd logs "exceeded max pending inventory announcements without
    /// serving data" and calls `Disconnect`).
    ExceededPendingBurst,
}

/// The expected-response deadlines, in nanoseconds on the caller's
/// clock (dcrd's `pendingDeadlines`).
#[derive(Debug, Default)]
pub struct PendingDeadlines {
    /// Requested inventory items awaiting delivery or a `notfound`.
    data: HashMap<InvVect, i64>,
    /// Command-keyed responses awaiting their message.
    cmds: HashMap<&'static str, i64>,
}

impl PendingDeadlines {
    /// An empty pair of tables.
    pub fn new() -> PendingDeadlines {
        PendingDeadlines::default()
    }

    /// How many inventory items are awaiting a response.
    pub fn pending_inv_count(&self) -> usize {
        self.data.len()
    }

    /// How many command-keyed responses are outstanding.
    pub fn pending_cmd_count(&self) -> usize {
        self.cmds.len()
    }

    /// Whether nothing at all is outstanding.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.cmds.is_empty()
    }

    /// The deadline armed for an inventory item, if any.
    pub fn inv_deadline(&self, iv: &InvVect) -> Option<i64> {
        self.data.get(iv).copied()
    }

    /// Every inventory item awaiting a response, in arbitrary order.
    pub fn pending_invs(&self) -> impl Iterator<Item = &InvVect> {
        self.data.keys()
    }

    /// Every command awaiting a response, in arbitrary order.
    pub fn pending_cmds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.cmds.keys().copied()
    }

    /// The deadline armed for a command, if any.
    pub fn cmd_deadline(&self, cmd: &str) -> Option<i64> {
        self.cmds.get(cmd).copied()
    }
}

/// Arm the deadlines a sent message expects back (dcrd
/// `maybeAddDeadline`), given the already-computed absolute deadline.
///
/// Only `getdata` and `getinitstate` arm anything at master.  Everything
/// else is intentionally ignored, and dcrd spells out why for each:
/// `ping` responses arrive too late behind a sync backlog to be
/// meaningful, `version`/`verack` are handled by the handshake before
/// the async loops start, `mempool` and `getminings` need not answer
/// when they have nothing to send, and `getblocks`/`getheaders` need not
/// answer when the remote has nothing for the locator.
pub fn maybe_add_deadline(
    pending: &mut PendingDeadlines,
    msg: &Message,
    deadline_nanos: i64,
) -> ArmOutcome {
    match msg {
        Message::GetData(get_data) => {
            // Refuse to let the peer get further ahead with advertised
            // inventory than it is willing to serve.
            let projected = pending.data.len().saturating_add(get_data.inv_list.len());
            if projected > MAX_PENDING_INV_BURST {
                return ArmOutcome::ExceededPendingBurst;
            }
            // Expects a block, tx, mix, or notfound per requested item.
            for iv in &get_data.inv_list {
                pending.data.insert(*iv, deadline_nanos);
            }
            ArmOutcome::Armed
        }
        Message::GetInitState(_) => {
            pending.cmds.insert(CMD_INIT_STATE, deadline_nanos);
            ArmOutcome::Armed
        }
        _ => ArmOutcome::Armed,
    }
}

/// Clear whatever a received message settles (dcrd
/// `maybeRemoveDeadline`).  Items that were never requested, and
/// messages that answer nothing, are a no-op.
pub fn maybe_remove_deadline(pending: &mut PendingDeadlines, settles: &Settles) {
    match settles {
        Settles::Nothing => {}
        Settles::Inventory(iv) => {
            pending.data.remove(iv);
        }
        Settles::Inventories(ivs) => {
            for iv in ivs {
                pending.data.remove(iv);
            }
        }
        Settles::Command(cmd) => {
            pending.cmds.remove(cmd);
        }
    }
}

/// Return the pending response that did not arrive by its adjusted
/// deadline, if any (dcrd `checkDeadlines`).  `offset_nanos` is the time
/// spent in message callbacks since the last check, which pushes every
/// deadline forward by that much.
///
/// Command-keyed entries are checked before inventory, matching dcrd's
/// loop order.  Master has no exemptions: it never arms a deadline for a
/// request that is allowed to go unanswered, so every entry present is
/// one a peer genuinely owes.
pub fn check_deadlines(
    pending: &PendingDeadlines,
    now_nanos: i64,
    offset_nanos: i64,
) -> Option<StallReason> {
    for (cmd, deadline) in &pending.cmds {
        if now_nanos < deadline.saturating_add(offset_nanos) {
            continue;
        }
        return Some(StallReason::Command(cmd));
    }
    for (iv, deadline) in &pending.data {
        if now_nanos < deadline.saturating_add(offset_nanos) {
            continue;
        }
        return Some(StallReason::Inventory(*iv));
    }
    None
}

/// The stall-detection state dcrd's `stallHandler` goroutine owns: the
/// pending response deadlines plus the handler-active accounting that
/// adjusts them forward by the time message callbacks take.
///
/// The daemon shares one of these between the peer's input loop (which
/// reports received messages and brackets the callbacks), the output
/// loop (which reports sent messages), and the stall thread (which
/// ticks [`StallDetector::check`] and disconnects on a stall).  Time
/// comes from a monotonic clock captured at construction, so a wall
/// clock adjustment can never fabricate or mask a stall.
#[derive(Debug)]
pub struct StallDetector {
    /// The monotonic origin every recorded instant is measured from.
    base: Instant,
    /// The expected response deadlines, in nanoseconds since `base`.
    pending: PendingDeadlines,
    /// When the in-progress message callback started, if one is active.
    handler_started_nanos: Option<i64>,
    /// Callback time accumulated since the last check.
    deadline_offset_nanos: i64,
    /// The base deadline granted to an expected response.
    response_timeout_nanos: i64,
}

impl Default for StallDetector {
    fn default() -> StallDetector {
        StallDetector::new()
    }
}

impl StallDetector {
    /// Create a detector using dcrd's `stallResponseTimeout`.
    pub fn new() -> StallDetector {
        StallDetector::with_response_timeout(STALL_RESPONSE_TIMEOUT)
    }

    /// Create a detector granting responses `response_timeout_nanos`
    /// to arrive.  Tests use a short timeout so a stall is observable
    /// in milliseconds instead of dcrd's 30 seconds.
    pub fn with_response_timeout(response_timeout_nanos: i64) -> StallDetector {
        StallDetector {
            base: Instant::now(),
            pending: PendingDeadlines::new(),
            handler_started_nanos: None,
            deadline_offset_nanos: 0,
            response_timeout_nanos,
        }
    }

    /// The monotonic now, in nanoseconds since the detector was built.
    fn now_nanos(&self) -> i64 {
        i64::try_from(self.base.elapsed().as_nanos()).unwrap_or(i64::MAX)
    }

    /// How much inventory the peer currently owes.
    pub fn pending_inv_count(&self) -> usize {
        self.pending.pending_inv_count()
    }

    /// Report a message being sent to the peer, arming the deadlines it
    /// expects (dcrd's `sccSendMessage`).
    ///
    /// [`ArmOutcome::ExceededPendingBurst`] means the peer has run too
    /// far ahead with unanswered inventory and the caller must
    /// disconnect it.
    pub fn sent_message(&mut self, msg: &Message) -> ArmOutcome {
        let deadline = self.now_nanos().saturating_add(self.response_timeout_nanos);
        maybe_add_deadline(&mut self.pending, msg, deadline)
    }

    /// Report a message received from the peer, clearing what it
    /// settles (dcrd's `sccReceiveMessage`).
    ///
    /// `mix_hash` carries the mixing-message identity hash; see
    /// [`settles`] for why the caller computes it.
    pub fn received_message(&mut self, msg: &Message, mix_hash: Option<Hash>) {
        let settled = settles(msg, mix_hash);
        maybe_remove_deadline(&mut self.pending, &settled);
    }

    /// Report that a message callback is about to run (dcrd's
    /// `sccHandlerStart`).  An unbalanced start while one is already
    /// active keeps the earlier start time, exactly as dcrd's warn and
    /// continue does.
    pub fn handler_start(&mut self) {
        if self.handler_started_nanos.is_some() {
            return;
        }
        self.handler_started_nanos = Some(self.now_nanos());
    }

    /// Report that a message callback finished (dcrd's
    /// `sccHandlerDone`), extending the active deadlines by the time it
    /// took.  An unbalanced done with no active handler is ignored.
    pub fn handler_done(&mut self) {
        let Some(started) = self.handler_started_nanos.take() else {
            return;
        };
        let duration = self.now_nanos().saturating_sub(started);
        self.deadline_offset_nanos = self.deadline_offset_nanos.saturating_add(duration);
    }

    /// Check every pending response against its adjusted deadline,
    /// returning what stalled (dcrd's `stallTicker` case).
    ///
    /// The offset is the callback time accumulated since the last check
    /// plus, when a callback is running right now, the time it has been
    /// running — so a peer is never blamed for time the local node
    /// spent not reading its socket.  The accumulated offset is reset
    /// afterwards, exactly like dcrd's per-tick reset.
    pub fn check(&mut self) -> Option<StallReason> {
        let now = self.now_nanos();
        let mut offset = self.deadline_offset_nanos;
        if let Some(started) = self.handler_started_nanos {
            offset = offset.saturating_add(now.saturating_sub(started));
        }
        let stalled = check_deadlines(&self.pending, now, offset);
        self.deadline_offset_nanos = 0;
        stalled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_wire::{MsgGetData, MsgNotFound};

    fn hash_of(n: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = n;
        Hash(h)
    }

    fn inv(inv_type: InvType, n: u8) -> InvVect {
        InvVect {
            inv_type,
            hash: hash_of(n),
        }
    }

    fn get_data(invs: &[InvVect]) -> Message {
        Message::GetData(MsgGetData {
            inv_list: invs.to_vec(),
        })
    }

    /// The regression the per-inventory split exists to fix: delivering
    /// one block must settle that block alone, not every request in
    /// flight.  Under the command-keyed table a peer could answer one
    /// getdata just inside the timeout and keep all sixteen block slots
    /// pinned forever.
    #[test]
    fn a_delivered_block_settles_only_its_own_request() {
        let mut pending = PendingDeadlines::new();
        let wanted = [
            inv(InvType::BLOCK, 1),
            inv(InvType::BLOCK, 2),
            inv(InvType::BLOCK, 3),
        ];
        assert_eq!(
            maybe_add_deadline(&mut pending, &get_data(&wanted), 100),
            ArmOutcome::Armed
        );
        assert_eq!(pending.pending_inv_count(), 3);

        maybe_remove_deadline(&mut pending, &Settles::Inventory(wanted[1]));
        assert_eq!(
            pending.pending_inv_count(),
            2,
            "one delivery must not settle the other two requests"
        );
        assert_eq!(pending.inv_deadline(&wanted[1]), None);
        assert_eq!(pending.inv_deadline(&wanted[0]), Some(100));
        assert_eq!(pending.inv_deadline(&wanted[2]), Some(100));
    }

    #[test]
    fn only_getdata_and_getinitstate_arm_anything() {
        for msg in [
            Message::VerAck,
            Message::MemPool,
            Message::GetAddr,
            Message::GetMiningState,
            Message::SendHeaders,
        ] {
            let mut pending = PendingDeadlines::new();
            assert_eq!(
                maybe_add_deadline(&mut pending, &msg, 100),
                ArmOutcome::Armed
            );
            assert!(
                pending.is_empty(),
                "{} must arm nothing at master",
                msg.command()
            );
        }
    }

    #[test]
    fn a_notfound_settles_every_item_it_lists() {
        let mut pending = PendingDeadlines::new();
        let wanted = [
            inv(InvType::BLOCK, 1),
            inv(InvType::TX, 2),
            inv(InvType::MIX, 3),
        ];
        let _ = maybe_add_deadline(&mut pending, &get_data(&wanted), 100);
        let not_found = Message::NotFound(MsgNotFound {
            inv_list: vec![wanted[0], wanted[1]],
        });
        maybe_remove_deadline(&mut pending, &settles(&not_found, None));
        assert_eq!(pending.pending_inv_count(), 1);
        assert_eq!(pending.inv_deadline(&wanted[2]), Some(100));
    }

    /// A getdata that would push the pending count past the burst
    /// ceiling arms nothing and reports the disconnect.
    #[test]
    fn an_oversized_burst_is_refused_rather_than_armed() {
        let mut pending = PendingDeadlines::new();
        let exactly_max: Vec<InvVect> = (0..MAX_PENDING_INV_BURST)
            .map(|i| InvVect {
                inv_type: InvType::BLOCK,
                hash: {
                    let mut h = [0u8; 32];
                    h[0] = (i & 0xff) as u8;
                    h[1] = ((i >> 8) & 0xff) as u8;
                    h[2] = ((i >> 16) & 0xff) as u8;
                    Hash(h)
                },
            })
            .collect();
        assert_eq!(
            maybe_add_deadline(&mut pending, &get_data(&exactly_max), 100),
            ArmOutcome::Armed,
            "exactly the ceiling is allowed"
        );
        assert_eq!(pending.pending_inv_count(), MAX_PENDING_INV_BURST);

        // One more item is over, so nothing changes and the peer goes.
        assert_eq!(
            maybe_add_deadline(&mut pending, &get_data(&[inv(InvType::BLOCK, 0xff)]), 100),
            ArmOutcome::ExceededPendingBurst
        );
        assert_eq!(
            pending.pending_inv_count(),
            MAX_PENDING_INV_BURST,
            "a refused burst must not arm anything"
        );
    }

    #[test]
    fn a_deadline_trips_only_once_it_has_passed() {
        let mut pending = PendingDeadlines::new();
        let _ = maybe_add_deadline(&mut pending, &get_data(&[inv(InvType::BLOCK, 1)]), 100);
        assert_eq!(check_deadlines(&pending, 99, 0), None);
        assert_eq!(
            check_deadlines(&pending, 100, 0),
            Some(StallReason::Inventory(inv(InvType::BLOCK, 1))),
            "now == deadline trips, matching dcrd's !now.Before(deadline)"
        );
    }

    #[test]
    fn the_callback_offset_pushes_the_deadline_forward() {
        let mut pending = PendingDeadlines::new();
        let _ = maybe_add_deadline(&mut pending, &get_data(&[inv(InvType::BLOCK, 1)]), 100);
        // Well past the deadline, but the local node spent all of that
        // time inside a callback rather than reading the socket.
        assert_eq!(check_deadlines(&pending, 1_000, 901), None);
        // An offset exactly equal to the overshoot still trips, since
        // the comparison is strict.
        assert!(check_deadlines(&pending, 1_000, 900).is_some());
        assert!(check_deadlines(&pending, 1_000, 0).is_some());
    }

    /// Master dropped release-v2.1.5's `miningstate` exemption because
    /// it never arms one in the first place.
    #[test]
    fn getminings_arms_nothing_so_needs_no_exemption() {
        let mut pending = PendingDeadlines::new();
        let _ = maybe_add_deadline(&mut pending, &Message::GetMiningState, 0);
        assert!(pending.is_empty());
        assert_eq!(check_deadlines(&pending, i64::MAX, 0), None);
    }

    /// A minimal, valid-shaped `mixpairreq`; only its variant matters
    /// here, since the identity hash is supplied by the caller.
    fn mix_pair_req() -> Message {
        Message::MixPairReq(dcroxide_wire::MsgMixPairReq {
            signature: [0u8; 64],
            identity: [0u8; 33],
            expiry: 0,
            mix_amount: 0,
            script_class: String::new(),
            tx_version: 0,
            lock_time: 0,
            message_count: 0,
            input_value: 0,
            utxos: Vec::new(),
            change: None,
            flags: 0,
            pairing_flags: 0,
        })
    }

    #[test]
    fn a_mixing_message_without_its_hash_settles_nothing() {
        let msg = mix_pair_req();
        assert_eq!(settles(&msg, None), Settles::Nothing);
        let hash = hash_of(7);
        assert_eq!(
            settles(&msg, Some(hash)),
            Settles::Inventory(InvVect {
                inv_type: InvType::MIX,
                hash
            })
        );
    }

    #[test]
    fn the_reason_text_matches_dcrds_inv_summary() {
        assert_eq!(
            StallReason::Inventory(inv(InvType::BLOCK, 7)).exceeded_text(),
            format!("deadline exceeded for block {}", hash_of(7))
        );
        assert_eq!(
            StallReason::Inventory(inv(InvType::MIX, 7)).exceeded_text(),
            format!("deadline exceeded for mix message {}", hash_of(7))
        );
        assert_eq!(
            StallReason::Inventory(inv(InvType::FILTERED_BLOCK, 7)).exceeded_text(),
            format!("deadline exceeded for filtered block {}", hash_of(7))
        );
        assert_eq!(
            StallReason::Inventory(inv(InvType(9), 7)).exceeded_text(),
            format!("deadline exceeded for unknown (9) {}", hash_of(7))
        );
        assert_eq!(
            StallReason::Command("initstate").exceeded_text(),
            "deadline exceeded for initstate"
        );
    }

    #[test]
    fn the_detector_reports_what_stalled() {
        let mut detector = StallDetector::with_response_timeout(0);
        assert_eq!(detector.check(), None, "nothing pending is not a stall");
        let wanted = inv(InvType::BLOCK, 1);
        assert_eq!(
            detector.sent_message(&get_data(&[wanted])),
            ArmOutcome::Armed
        );
        assert_eq!(
            detector.check(),
            Some(StallReason::Inventory(wanted)),
            "an unanswered getdata stalls, naming the item"
        );

        let mut detector = StallDetector::with_response_timeout(0);
        let _ = detector.sent_message(&get_data(&[wanted]));
        detector.received_message(
            &Message::NotFound(MsgNotFound {
                inv_list: vec![wanted],
            }),
            None,
        );
        assert_eq!(detector.check(), None, "a notfound settles it");
    }

    #[test]
    fn an_active_handler_holds_off_the_stall() {
        // A 50ms response timeout with a callback that runs for 200ms:
        // the peer would look stalled were the callback time not
        // credited back to it.  Overshoot in the sleep is harmless, the
        // offset grows with it.
        let mut detector = StallDetector::with_response_timeout(50_000_000);
        let _ = detector.sent_message(&get_data(&[inv(InvType::BLOCK, 1)]));
        detector.handler_start();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            detector.check(),
            None,
            "time spent in a running callback is not the peer's fault"
        );
        detector.handler_done();
        assert_eq!(
            detector.check(),
            None,
            "the finished callback's time still offsets this tick"
        );
        assert!(
            detector.check().is_some(),
            "the offset is reset per tick, so the stall surfaces next tick"
        );
    }
}
