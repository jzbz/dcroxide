// SPDX-License-Identifier: ISC
//! Where a connection's input loop gets its messages from, and the
//! thread that reads ahead of that loop on the sync peer's connection.
//!
//! dcrd's `inHandler` reads one message, runs its listener and reads the
//! next only when the listener has returned (`peer/peer.go:1535-1599`).
//! The input loop here ([`crate::peerloop`]) does the same through a
//! `MsgSource`: it asks for the next message when it has finished the
//! one before, and the source says what arrived and how many bytes the
//! read took off the wire.  `InlineSource` is that read made on the
//! input thread itself, at the moment it is asked for.
//!
//! # Reading ahead
//!
//! During the initial chain sync the input thread of the sync peer's
//! connection is the thread that connects blocks, and between two blocks
//! it also read the next one off the socket, checked its checksum,
//! decoded it and hashed its transactions.  `ReadAheadSource` moves
//! that work to a thread of its own, `peer-reader`, which dcrd does not
//! have (PARITY *Reading ahead of the block handler*).  The thread is
//! started the first time the connection has a block handled, is kept,
//! and the server says reading ahead is wanted
//! ([`crate::peerloop::ServeHooks::read_ahead_wanted`]); until then, and
//! on every connection that never gets there, the input thread reads for
//! itself exactly as before.
//!
//! The reader owns the framed transport from then on and hands each
//! frame through a queue of at most `READ_AHEAD_MAX_ITEMS` items to
//! the input loop, which is unchanged.  What keeps the connection's
//! observable behaviour dcrd's:
//!
//! - **Order.**  One reader appends, one handler takes from the front,
//!   so the handler sees the frames in the order they ended on the wire.
//! - **Values, and one verdict the chain returns.**  The reader acts on
//!   nothing but the frame.  A block it hands over with the hashes of
//!   its transactions, the roots of its two transaction merkle trees and
//!   its counts of signature operations under each answer the treasury
//!   agenda can give (`dcroxide_blockchain::HashedBlock`), which the
//!   chain reads where it would have computed them and not before; no
//!   merkle root is compared with a header and no count with the limit
//!   on the reader's thread.  The one rule applied there is the
//!   context-free checks of the block's data
//!   (`HashedBlock::check_data_sanity`, dcrd `checkBlockDataSanity`),
//!   made with the values of the chain parameters the server gives
//!   (`ServeHooks::data_sanity_params`), and only where it gives them.
//!   Their verdict goes with the block unread, and the chain returns it
//!   at the point where it makes those checks of any other block, after
//!   the header and merkle checks, so the order of the checks and every
//!   result are unchanged.
//!   The block also carries the payload it was decoded from, laid out as
//!   its record for the block files, which the chain writes where it
//!   would have serialized the block and taken the record's checksum
//!   (dcrd stores the payload too, `server.go:1359`,
//!   `dcrutil/block.go:54-58`).  The payload is kept only once it has
//!   been compared with the block's serialization and found to be it
//!   (`HashedBlock::keep_wire_bytes`), so the block files hold the same
//!   bytes whichever thread read the block.  Every ban, disconnect,
//!   reject, log line, pong and stall-detector event comes from the
//!   input thread, from the same code, at the same position in the
//!   stream.  A failed read is the last item in the queue and is acted
//!   on only after every frame before it.
//! - **Early reads only behind a block.**  The reader starts a frame
//!   before the handler is waiting for it only when the frame it read
//!   last was a block and the handler's latest answer was that reading
//!   ahead is wanted.  In every other case it starts a frame only once
//!   the handler is waiting with nothing queued, which is when
//!   `inHandler` starts its read.
//! - **The teardown flag.**  The handler tests the connection's flag
//!   before taking each item, as `inHandler` tests its disconnect flag
//!   before each read and the transport tests it before each receive.
//!   Nothing queued is handed over once the flag is up.
//! - **The idle budget.**  A frame's read budget runs from the moment
//!   the handler began waiting for it with nothing else left to take
//!   (`BudgetStart::Waiter` in `transport.rs`), not from when the
//!   reader began to read it, and not from when the handler began
//!   waiting for a frame before it.
//!
//! The reader takes no lock but the queue's and, to hand a block to
//! signature pre-verification, the script pool's, never the two at once.
//! It calls no hook, logs nothing about the peer and queues nothing to
//! it.
//!
//! # Signature pre-verification
//!
//! When the process has a signature pre-verifier
//! ([`crate::preverify::installed`]), the reader hands it each block it
//! has hashed before queueing the block, as long as the handler's latest
//! answer was that reading ahead is wanted, and the block goes to the
//! script pool's helpers unless the chain will check none of its
//! scripts.  Once reading ahead is no longer wanted, after the initial
//! chain sync, the reader that is kept hands over nothing: a block read
//! in turn is taken as soon as it is queued, before a helper could do
//! anything for it.  The helpers fill the signature cache the chain's
//! connect checks read, and reach no verdict (PARITY *Signature
//! pre-verification ahead of the block thread*).  The handler withdraws
//! a block from it as it takes the block, and every block still queued
//! when it leaves, so the pre-verifier holds no block the read-ahead has
//! let go of.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_blockchain::HashedBlock;
use dcroxide_blockchain::preverify::{Preverifier, Ticket};
use dcroxide_blockchain::validate::DataSanityParams;
use dcroxide_chainhash::Hash;
use dcroxide_netsync::manager::LogLevel;
use dcroxide_peer::{MsgTransport, ReadError};
use dcroxide_wire::Message;

use crate::peerloop::{READ_TORN_DOWN_TEXT, mix_message_hash};
use crate::transport::{
    BlockFrame, BudgetStart, Cancel, READ_POLL_INTERVAL, Teardown, WireTransport,
};

/// What one read produced, and the bytes it took off the wire.
pub(crate) struct ReadItem {
    /// The message, or why the read failed.
    pub(crate) result: Result<Received, ReadError>,
    /// The wire bytes this read consumed, for the peer's receive
    /// accounting (dcrd's `readMessage` adding its count to
    /// `bytesReceived`).  Zero from a transport that does not count.
    pub(crate) read_delta: u64,
}

impl ReadItem {
    /// The item a read gives when the connection was torn down under it
    /// (`read_exact_by_deadline` in `transport.rs` finding the flag up).
    fn torn_down() -> ReadItem {
        ReadItem {
            result: Err(ReadError::io(READ_TORN_DOWN_TEXT)),
            read_delta: 0,
        }
    }

    /// Whether the item is a block.
    fn is_block(&self) -> bool {
        self.result.as_ref().is_ok_and(Received::is_block)
    }
}

/// A message as the input loop is handed it.
pub(crate) enum Received {
    /// A decoded message with the mixing identity hash computed as it
    /// was read (dcrd's `readMessage` caching `WriteHash` on a mixing
    /// message), which is `None` for every other message and when the
    /// hashing failed.
    Message {
        /// The message.
        msg: Message,
        /// Its mixing identity hash, if it has one.
        mix_hash: Option<Hash>,
    },
    /// A block the reader thread read, ahead of the handler or in turn,
    /// with its block hash and the hashes of its transactions computed on
    /// that thread (what dcrd's `dcrutil.Block` holds, made lazily while
    /// the chain processes the block), with the roots of its two
    /// transaction merkle trees, which dcrd builds inside its merkle
    /// check, with its two counts of signature operations, which dcrd
    /// makes inside its contextual block check, and with the payload it
    /// arrived in laid out as its block-file record.  A block the input
    /// thread read for itself, on a connection that has no reader
    /// thread, arrives as a [`Received::Message`] and is hashed inside
    /// the chain.
    Block(HashedBlock),
}

impl Received {
    /// Whether this is a block, however it was read.
    pub(crate) fn is_block(&self) -> bool {
        matches!(
            self,
            Received::Block(_)
                | Received::Message {
                    msg: Message::Block(_),
                    ..
                }
        )
    }
}

/// The messages of one connection, in the order they arrived.
pub(crate) trait MsgSource {
    /// The next message, or the failed read that ends the stream.  The
    /// input loop calls this with no lock held, and only when it has
    /// finished handling the message before.
    fn next(&mut self) -> ReadItem;

    /// The input loop has finished handling a block and keeps the
    /// connection, and `wanted` is the server's answer to whether reading
    /// ahead of the handler is wanted from here on
    /// ([`crate::peerloop::ServeHooks::read_ahead_wanted`]).  A source
    /// that only reads when asked ignores it.
    fn block_handled(&mut self, _wanted: bool) {}
}

/// The source that reads on the calling thread when it is asked: dcrd's
/// `inHandler` calling `readMessage`.
pub(crate) struct InlineSource<'t, T: MsgTransport> {
    transport: &'t mut T,
    /// The transport's cumulative read counter as of the last read, so
    /// each message contributes its own delta.
    read_total: u64,
}

impl<'t, T: MsgTransport> InlineSource<'t, T> {
    /// A source over the transport, counting from the bytes it has read
    /// so far: the handshake's were folded into the peer's counters by
    /// the connection assembly.
    pub(crate) fn new(transport: &'t mut T) -> InlineSource<'t, T> {
        let read_total = transport.total_bytes_read();
        InlineSource {
            transport,
            read_total,
        }
    }
}

/// Read one message on the calling thread, with the bytes the read took
/// since `read_total` was last brought up to date.
fn read_inline<T: MsgTransport>(transport: &mut T, read_total: &mut u64) -> ReadItem {
    let result = transport.read_message();
    let total = transport.total_bytes_read();
    let read_delta = total.wrapping_sub(*read_total);
    *read_total = total;
    ReadItem {
        // Hash a mixing message once, before any lock is taken: dcrd
        // does this in `readMessage` and caches the hash on the message,
        // and the stall detector and the server handler both read this
        // one.
        result: result.map(|msg| {
            let mix_hash = mix_message_hash(&msg);
            Received::Message { msg, mix_hash }
        }),
        read_delta,
    }
}

impl<T: MsgTransport> MsgSource for InlineSource<'_, T> {
    fn next(&mut self) -> ReadItem {
        read_inline(self.transport, &mut self.read_total)
    }
}

/// The most frames that have been read and not yet taken by the handler,
/// the one being read included.
///
/// The download window bounds what an honest sync peer has in flight
/// (`dcroxide_netsync::manager::BUDGET_WINDOW_BLOCKS`); this bounds how
/// much of that is decoded in memory ahead of the block being connected
/// instead of waiting in the socket's buffers.  The reader is several
/// times faster than the connect, so a deeper queue would only hold more
/// decoded blocks, and a hostile sync peer could fill it with blocks of
/// the largest size.
///
/// A block the reader read holds the frame it arrived in as well, as its
/// block-file record, from the read until the handler has finished with
/// the block: the payload and twenty-eight bytes for each of these
/// items and for the block being handled.  No frame is held anywhere
/// else, so this bound is the bound on them too.  While the reader
/// checks a frame it also holds that one block's serialization, which
/// it lets go of before the block is queued.
pub(crate) const READ_AHEAD_MAX_ITEMS: usize = 4;

/// What the reader and the handler of one connection share.
///
/// A mutex and two condition variables rather than a channel: the
/// reader's rule needs to know that the handler is waiting with nothing
/// queued, which a channel does not say.  The lock is a leaf.  Neither
/// side holds another lock while it takes this one, and the reader takes
/// no other lock at all.
pub(crate) struct Shared {
    state: Mutex<State>,
    /// The reader parks here until it may read the next frame.
    room: Condvar,
    /// The handler parks here until an item is queued.
    ready: Condvar,
    /// The connection's teardown flag.
    cancel: Cancel,
    /// The process's signature pre-verifier, if it has one.
    preverify: Option<Arc<Preverifier>>,
    /// The values of the chain parameters the reader makes each block's
    /// data sanity checks with, if the server gave any.
    data_sanity: Option<DataSanityParams>,
}

/// The state behind [`Shared`]'s lock.
struct State {
    /// The frames read and not yet taken, oldest first, each block with
    /// the ticket of its pre-verification, if it was queued for one.
    queue: VecDeque<(ReadItem, Option<Ticket>)>,
    /// Whether reading ahead is wanted, as the handler last said.
    ahead: bool,
    /// Since when the handler has been waiting with nothing to take, if
    /// it is.  This is when the idle budget of the frame it waits for
    /// starts.  It is set when the handler finds the queue empty and
    /// cleared when it takes an item, so it is still set between the
    /// queueing of that frame and the handler's taking it; what the read
    /// in progress is told is [`Shared::waiting_since`]'s answer, which
    /// allows for that.
    waiting_since: Option<Instant>,
    /// Whether the reader is parked on `room`.
    reader_parked: bool,
    /// The handler has left: nothing more is taken.
    handler_gone: bool,
    /// The reader has queued its last item, or has exited.
    reader_done: bool,
    /// The most items the queue has held.
    max_queued: usize,
}

impl State {
    /// Keep the high-water marks up to date after an item was queued.
    fn note_queued(&mut self) {
        if self.queue.len() > self.max_queued {
            self.max_queued = self.queue.len();
            STATS.max_queued.fetch_max(
                u64::try_from(self.max_queued).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }
}

impl Shared {
    /// The shared state of a connection whose handler has just handled a
    /// block and wants the frames behind it read ahead, with the signature
    /// pre-verifier its blocks are handed to, if any, and the values its
    /// blocks' data sanity checks are made with, if any.
    fn new(
        cancel: Cancel,
        preverify: Option<Arc<Preverifier>>,
        data_sanity: Option<DataSanityParams>,
    ) -> Shared {
        Shared {
            state: Mutex::new(State {
                queue: VecDeque::with_capacity(READ_AHEAD_MAX_ITEMS),
                ahead: true,
                waiting_since: None,
                reader_parked: false,
                handler_gone: false,
                reader_done: false,
                max_queued: 0,
            }),
            room: Condvar::new(),
            ready: Condvar::new(),
            cancel,
            preverify,
            data_sanity,
        }
    }

    /// Lock the state.  Every critical section here leaves the state
    /// consistent, so a lock poisoned by a panic on the other side is
    /// taken anyway: the side that is left must still be able to end the
    /// connection.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Park the reader until it may read the next frame, and say whether
    /// it may: `false` once the handler has left.
    ///
    /// The frame may be read ahead of the handler when the frame before
    /// it was a block (`after_block`), reading ahead is wanted and fewer
    /// than [`READ_AHEAD_MAX_ITEMS`] frames are waiting.  Otherwise it
    /// may be read only when the handler is waiting with nothing queued,
    /// which is when dcrd's `inHandler` begins its read.
    fn may_read(&self, after_block: bool) -> bool {
        let mut state = self.lock();
        loop {
            if state.handler_gone {
                return false;
            }
            let early = state.ahead && after_block;
            if early && state.queue.len() < READ_AHEAD_MAX_ITEMS {
                return true;
            }
            if state.waiting_since.is_some() && state.queue.is_empty() {
                return true;
            }
            state.reader_parked = true;
            // Parked with reading ahead allowed means the queue is full:
            // the reader is waiting for the block thread.
            let parked = early.then(Instant::now);
            state = self
                .room
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.reader_parked = false;
            if let Some(parked) = parked {
                add_nanos(&STATS.reader_waited_nanos, parked.elapsed());
            }
        }
    }

    /// Hand a block the reader hashed to signature pre-verification, if
    /// the process does it and reading ahead is wanted: the ticket to
    /// withdraw it with, when the block was queued for it.  Called with
    /// the queue's lock released; it takes that lock to read whether
    /// reading ahead is wanted, and lets go of it before the pool's.
    fn preverify(&self, block: &HashedBlock) -> Option<Ticket> {
        let preverify = self.preverify.as_ref()?;
        let ahead = self.lock().ahead;
        if !ahead {
            return None;
        }
        preverify.submit(block)
    }

    /// Withdraw from pre-verification the block of `ticket` and every
    /// block handed to it before.  Called with the queue's lock released.
    fn withdraw(&self, ticket: Option<Ticket>) {
        if let (Some(preverify), Some(ticket)) = (&self.preverify, ticket) {
            preverify.withdraw_through(ticket);
        }
    }

    /// Queue a frame the reader read, with the ticket of its
    /// pre-verification when it is a block that has one.  `false` once
    /// the handler has left, when the frame is dropped and its block
    /// withdrawn.
    fn push(&self, item: ReadItem, ticket: Option<Ticket>) -> bool {
        let mut state = self.lock();
        if state.handler_gone {
            drop(state);
            self.withdraw(ticket);
            return false;
        }
        debug_assert!(!state.reader_done, "a frame behind the reader's last item");
        state.queue.push_back((item, ticket));
        debug_assert!(state.queue.len() <= READ_AHEAD_MAX_ITEMS);
        state.note_queued();
        // The handler is parked only while it is waiting with nothing to
        // take, so that is the only time it needs waking.
        if state.waiting_since.is_some() {
            self.ready.notify_one();
        }
        true
    }

    /// Queue the reader's last item, the failed read that ends the
    /// stream.  It is behind every frame read before it, and nothing is
    /// queued after it.
    fn push_last(&self, item: ReadItem) {
        let mut state = self.lock();
        if !state.handler_gone {
            state.queue.push_back((item, None));
            state.note_queued();
        }
        state.reader_done = true;
        self.ready.notify_one();
    }

    /// The reader has exited, however it did.
    fn reader_exited(&self) {
        self.lock().reader_done = true;
        self.ready.notify_one();
    }

    /// Since when the handler has been waiting for the frame being read,
    /// if it is: the start of that frame's idle budget
    /// ([`BudgetStart::Waiter`]).
    ///
    /// While anything is queued the handler is not waiting for the frame
    /// being read, whatever it is doing: it has an earlier frame to take
    /// first.  That covers the moment between the queueing of a frame the
    /// handler was parked for and its taking that frame, when the instant
    /// its wait began is still on record.  The frame behind gets a budget
    /// of its own, which starts when the handler comes back with nothing
    /// left to take, as each read `inHandler` makes is given a fresh
    /// deadline (`readMessage`, `peer/peer.go:963-964`).  Answering with
    /// the recorded instant there would charge the frame behind a block
    /// with the handler's wait for the block, and a block whose last byte
    /// arrived inside its budget but whose checksum, decoding, hashing
    /// and laying out as a block-file record ended after it would cost
    /// the peer its connection.
    fn waiting_since(&self) -> Option<Instant> {
        let state = self.lock();
        if state.queue.is_empty() {
            state.waiting_since
        } else {
            None
        }
    }

    /// The next item for the handler, parking until there is one.
    ///
    /// The teardown flag is tested before every hand-over, and at least
    /// every [`READ_POLL_INTERVAL`] while parked, as the transport tests
    /// it before every receive: once it is up the answer is the read
    /// error an inline read gives then, and nothing queued is handed
    /// over.
    fn next(&self) -> ReadItem {
        let mut state = self.lock();
        loop {
            if self.cancel.is_cancelled() {
                return ReadItem::torn_down();
            }
            if let Some((item, ticket)) = state.queue.pop_front() {
                let waited = state.waiting_since.take();
                // Taking an item makes room, which the reader is only
                // waiting for while reading ahead is wanted.
                if state.reader_parked && state.ahead {
                    self.room.notify_one();
                }
                if let Some(since) = waited
                    && state.ahead
                    && item.is_block()
                {
                    add_nanos(&STATS.handler_waited_nanos, since.elapsed());
                }
                // The block is the handler's from here: its scripts are
                // checked by the chain, and pre-verification moves on.
                drop(state);
                self.withdraw(ticket);
                return item;
            }
            if state.reader_done {
                return ReadItem::torn_down();
            }
            // Nothing to take: the handler is waiting from here, which
            // starts the idle budget of the frame it waits for and lets
            // a reader that reads only in turn begin that frame.
            if state.waiting_since.is_none() {
                state.waiting_since = Some(Instant::now());
            }
            if state.reader_parked {
                self.room.notify_one();
            }
            state = self
                .ready
                .wait_timeout(state, READ_POLL_INTERVAL)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Record whether reading ahead is wanted, as the handler says after
    /// each block.
    fn set_ahead(&self, wanted: bool) {
        let mut state = self.lock();
        let became_wanted = wanted && !state.ahead;
        state.ahead = wanted;
        if became_wanted && state.reader_parked {
            self.room.notify_one();
        }
    }

    /// The handler has left: nothing more is taken, what is queued is
    /// dropped and withdrawn from pre-verification, and a parked reader
    /// is woken to exit.
    fn leave(&self) {
        let dropped = {
            let mut state = self.lock();
            state.handler_gone = true;
            std::mem::take(&mut state.queue)
        };
        self.withdraw(dropped.iter().filter_map(|(_, ticket)| *ticket).max());
        self.room.notify_one();
        drop(dropped);
    }

    /// The most items the queue has held.
    #[cfg(test)]
    fn max_queued(&self) -> usize {
        self.lock().max_queued
    }
}

/// What the reader thread reads frames from: the connection's transport,
/// or a scripted double in tests.
pub(crate) trait FrameReader {
    /// Read the next frame.  `since` says when the thread the frame is
    /// read for began waiting for it, which is when its idle budget
    /// starts ([`BudgetStart::Waiter`]).
    fn read(&mut self, since: &dyn Fn() -> Option<Instant>) -> Result<Message, ReadError>;

    /// The cumulative bytes read off the connection.
    fn total_bytes_read(&self) -> u64;

    /// The time spent checking and decoding frames since the last call,
    /// in nanoseconds.
    fn take_decode_nanos(&mut self) -> u64;

    /// The frame the last read decoded its block from, as it came off
    /// the wire, if that read gave a block and the reader keeps frames.
    /// It is handed out once.
    fn take_block_frame(&mut self) -> Option<BlockFrame>;
}

impl FrameReader for WireTransport<Teardown> {
    fn read(&mut self, since: &dyn Fn() -> Option<Instant>) -> Result<Message, ReadError> {
        self.read_message_paced(BudgetStart::Waiter(since))
    }

    fn total_bytes_read(&self) -> u64 {
        self.bytes_read()
    }

    fn take_decode_nanos(&mut self) -> u64 {
        WireTransport::take_decode_nanos(self)
    }

    fn take_block_frame(&mut self) -> Option<BlockFrame> {
        WireTransport::take_block_frame(self)
    }
}

/// Marks the reader as exited when its loop ends, a panic included, so a
/// handler waiting for it is not left waiting.
struct ReaderExit<'a>(&'a Shared);

impl Drop for ReaderExit<'_> {
    fn drop(&mut self) {
        self.0.reader_exited();
    }
}

/// The reader thread: read frames as [`Shared::may_read`] allows, hash
/// the blocks among them, make their data sanity checks when the queue
/// holds the values to make them with, and queue each frame for the
/// handler, until a read fails or the handler leaves.
///
/// It is handed the transport, the queue and the counters its own work
/// is added to, which are the process's ([`STATS`]) for every reader
/// thread of a node, and nothing else.  It acts on no verdict: the one
/// it may reach, of a block's data sanity checks, goes with the block to
/// the chain unread.  After its first failed read it reads nothing more.
fn reader_loop<R: FrameReader>(mut reader: R, shared: &Shared, stats: &Stats) {
    let _exit = ReaderExit(shared);
    let mut read_total = reader.total_bytes_read();
    // The reader starts right behind a block the handler has handled.
    let mut after_block = true;
    while shared.may_read(after_block) {
        let result = reader.read(&|| shared.waiting_since());
        let total = reader.total_bytes_read();
        let read_delta = total.wrapping_sub(read_total);
        read_total = total;
        stats.frames.fetch_add(1, Ordering::Relaxed);
        stats
            .decode_nanos
            .fetch_add(reader.take_decode_nanos(), Ordering::Relaxed);
        match result {
            Err(e) => {
                shared.push_last(ReadItem {
                    result: Err(e),
                    read_delta,
                });
                break;
            }
            Ok(msg) => {
                let mut ticket = None;
                let received = match msg {
                    // Hash the block here, and count its signature
                    // operations, off the thread that connects blocks.
                    // The hashes and counts travel with the block they
                    // were computed from, and nothing about the block is
                    // decided by computing them.
                    Message::Block(block) => {
                        let frame = reader.take_block_frame();
                        let began = Instant::now();
                        let mut hashed = HashedBlock::new(Arc::new(block));
                        add_nanos(&stats.hash_nanos, began.elapsed());
                        stats.blocks.fetch_add(1, Ordering::Relaxed);
                        stats.block_bytes.fetch_add(read_delta, Ordering::Relaxed);
                        // The payload the block was decoded from goes
                        // with it, laid out here as its record for the
                        // block files, so that the thread that stores
                        // the block neither serializes it nor takes the
                        // record's checksum (dcrd's `OnBlock` keeps the
                        // payload the same way, `server.go:1359`).  The
                        // payload is compared with the block's
                        // serialization first, here, and one that
                        // differs is dropped: the block is then stored
                        // as one that arrived without.
                        if let Some(frame) = frame {
                            let began = Instant::now();
                            let kept =
                                hashed.keep_wire_bytes(frame.buf, frame.payload_at, frame.net.0);
                            add_nanos(&stats.record_nanos, began.elapsed());
                            if kept {
                                stats.records.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // The block goes to signature pre-verification
                        // before it is queued, so that the helpers can
                        // start on it while it waits.
                        ticket = shared.preverify(&hashed);
                        // Its data sanity checks are made here too, with
                        // the values the server gave, if it gave any.
                        // The verdict goes with the block, unread: the
                        // chain returns it where it makes those checks,
                        // and nothing is done about it here.
                        if let Some(params) = shared.data_sanity {
                            let began = Instant::now();
                            hashed.check_data_sanity(params);
                            add_nanos(&stats.hash_nanos, began.elapsed());
                        }
                        Received::Block(hashed)
                    }
                    // A mixing message is hashed once as it is read, as
                    // on the inline path.
                    msg => {
                        let mix_hash = mix_message_hash(&msg);
                        Received::Message { msg, mix_hash }
                    }
                };
                let is_block = received.is_block();
                let item = ReadItem {
                    result: Ok(received),
                    read_delta,
                };
                if !shared.push(item, ticket) {
                    break;
                }
                after_block = is_block;
            }
        }
    }
}

/// The message source of a served connection: the input thread's own
/// reads until read-ahead is first wanted behind a block, and the reader
/// thread's queue from then on.
pub(crate) struct ReadAheadSource {
    mode: Mode,
    /// The transport's cumulative read counter as of the last read the
    /// input thread made itself.
    read_total: u64,
    /// The connection's teardown flag.
    cancel: Cancel,
    /// How the peer is named in the log.
    label: String,
    /// A reader could not be started once, and is not tried again.
    gave_up: bool,
    /// The values of the chain parameters a reader thread makes each
    /// block's data sanity checks with, if the server gave any.
    data_sanity: Option<DataSanityParams>,
}

/// Who reads the connection.
enum Mode {
    /// The input thread, when it is ready for the next message.
    Inline(WireTransport<Teardown>),
    /// The reader thread, which owns the transport.
    Ahead {
        /// The queue between the two threads.
        shared: Arc<Shared>,
        /// The reader thread.
        reader: JoinHandle<()>,
        /// A handle on the connection to end it with, sharing its flag.
        interrupt: Teardown,
    },
    /// Nobody: the source has been finished.
    Finished,
}

impl ReadAheadSource {
    /// A source that reads `transport` on the calling thread until
    /// read-ahead is wanted.  `cancel` is the connection's teardown flag
    /// and `label` names the peer in the log.  A reader thread it starts
    /// makes the data sanity checks of each block it hashes with
    /// `data_sanity`, if that is given, and of none otherwise.
    pub(crate) fn new(
        transport: WireTransport<Teardown>,
        cancel: Cancel,
        label: String,
        data_sanity: Option<DataSanityParams>,
    ) -> ReadAheadSource {
        let read_total = transport.bytes_read();
        ReadAheadSource {
            mode: Mode::Inline(transport),
            read_total,
            cancel,
            label,
            gave_up: false,
            data_sanity,
        }
    }

    /// Hand the transport to a new reader thread, or keep reading it on
    /// the input thread when one cannot be started.
    ///
    /// The thread is started before it is given the transport: a spawn
    /// the OS refuses drops its closure, and the transport must not go
    /// with it (`crate::runtime::spawn_conn_thread`).  A refusal is not
    /// fatal and is not retried; dcrd's goroutines cannot fail to start,
    /// and neither can a connection that simply goes on as it was.
    fn start_reader(&mut self, transport: WireTransport<Teardown>) -> Mode {
        let interrupt = match transport.get_ref().try_clone() {
            Ok(interrupt) => interrupt,
            Err(e) => {
                self.gave_up = true;
                crate::logging::debug(
                    "PEER",
                    &format!(
                        "Unable to share the connection of peer {} with a read-ahead thread: \
                         {e} -- reading on the input thread",
                        self.label
                    ),
                );
                return Mode::Inline(transport);
            }
        };
        let shared = Arc::new(Shared::new(
            self.cancel.clone(),
            crate::preverify::installed().cloned(),
            self.data_sanity,
        ));
        let (hand_over, handed) = mpsc::sync_channel::<WireTransport<Teardown>>(1);
        let reader_shared = Arc::clone(&shared);
        let spawned = crate::runtime::spawn_conn_thread("peer-reader", move || {
            if let Ok(transport) = handed.recv() {
                reader_loop(transport, &reader_shared, &STATS);
            }
        });
        let reader = match spawned {
            Ok(reader) => reader,
            Err(e) => {
                self.gave_up = true;
                crate::logging::warn(
                    "PEER",
                    &format!(
                        "Unable to start a read-ahead thread for peer {}: {e} -- reading on \
                         the input thread",
                        self.label
                    ),
                );
                return Mode::Inline(transport);
            }
        };
        match hand_over.send(transport) {
            Ok(()) => {
                STATS.connections.fetch_add(1, Ordering::Relaxed);
                crate::logging::debug(
                    "PEER",
                    &format!("Reading ahead of the block handler for peer {}", self.label),
                );
                Mode::Ahead {
                    shared,
                    reader,
                    interrupt,
                }
            }
            // The thread ended without taking the transport, which comes
            // back with the error.
            Err(mpsc::SendError(transport)) => {
                self.gave_up = true;
                let _ = reader.join();
                Mode::Inline(transport)
            }
        }
    }

    /// End the connection: raise its flag and shut the socket down (dcrd
    /// `Peer.Disconnect`), and release the reader thread if there is
    /// one.  The input loop has ended, so nothing queued is handled.
    pub(crate) fn disconnect(&mut self) {
        match &self.mode {
            Mode::Inline(transport) => transport.get_ref().disconnect(),
            Mode::Ahead {
                shared, interrupt, ..
            } => {
                interrupt.disconnect();
                shared.leave();
            }
            Mode::Finished => {}
        }
    }

    /// Wait for the reader thread, if there is one, to exit, so that no
    /// thread outlives the connection.  The connection is ended first if
    /// [`ReadAheadSource::disconnect`] has not ended it already.
    ///
    /// The reader touches only the socket, the queue and counters, so it
    /// is joined last.  It exits at once from the queue, and from a
    /// receive when the socket's shutdown ends it or, where that does
    /// not end a receive already blocked, within [`READ_POLL_INTERVAL`].
    pub(crate) fn finish(mut self) {
        if let Mode::Ahead {
            shared,
            reader,
            interrupt,
        } = std::mem::replace(&mut self.mode, Mode::Finished)
        {
            interrupt.disconnect();
            shared.leave();
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
impl ReadAheadSource {
    /// Whether a reader thread reads the connection.
    pub(crate) fn is_ahead(&self) -> bool {
        matches!(self.mode, Mode::Ahead { .. })
    }

    /// The most items the reader thread's queue has held, if a reader
    /// thread reads the connection.
    pub(crate) fn max_queued(&self) -> Option<usize> {
        match &self.mode {
            Mode::Ahead { shared, .. } => Some(shared.max_queued()),
            Mode::Inline(_) | Mode::Finished => None,
        }
    }

    /// Whether the reader thread has exited, if a reader thread reads
    /// the connection.
    pub(crate) fn reader_exited(&self) -> Option<bool> {
        match &self.mode {
            Mode::Ahead { reader, .. } => Some(reader.is_finished()),
            Mode::Inline(_) | Mode::Finished => None,
        }
    }
}

impl Drop for ReadAheadSource {
    /// A source dropped without [`ReadAheadSource::finish`] still
    /// releases its reader thread, without waiting for it.
    fn drop(&mut self) {
        if matches!(self.mode, Mode::Ahead { .. }) {
            self.disconnect();
        }
    }
}

impl MsgSource for ReadAheadSource {
    fn next(&mut self) -> ReadItem {
        match &mut self.mode {
            Mode::Inline(transport) => read_inline(transport, &mut self.read_total),
            Mode::Ahead { shared, .. } => shared.next(),
            Mode::Finished => ReadItem::torn_down(),
        }
    }

    fn block_handled(&mut self, wanted: bool) {
        match &self.mode {
            Mode::Ahead { shared, .. } => shared.set_ahead(wanted),
            // A reader is started only behind a block the connection was
            // kept for, while its flag is down: a block that got the
            // peer disconnected raised the flag as it was handled.
            Mode::Inline(_) if wanted && !self.gave_up && !self.cancel.is_cancelled() => {
                self.mode = match std::mem::replace(&mut self.mode, Mode::Finished) {
                    Mode::Inline(transport) => self.start_reader(transport),
                    mode => mode,
                };
            }
            Mode::Inline(_) | Mode::Finished => {}
        }
    }
}

/// The environment variable that turns the read-ahead of blocks off
/// ([`read_ahead_setting`]).
pub const READ_AHEAD_VAR: &str = "DCROXIDE_READ_AHEAD";

/// Whether the daemon reads ahead of the block handler on its sync
/// peer's connection, given the [`READ_AHEAD_VAR`] setting, with the
/// line to log about the setting, if any, and the level to log it at.
///
/// Unset, it does, and nothing is said.  `off`, in any case, or `0`
/// turns it off: every connection is then read by its input thread
/// alone, as dcrd reads.  Surrounding whitespace is ignored.  Any other
/// value is ignored with a warning rather than being fatal, like the
/// daemon's other tuning variables.
pub fn read_ahead_setting(setting: Option<&str>) -> (bool, Option<(LogLevel, String)>) {
    let Some(raw) = setting else {
        return (true, None);
    };
    let value = raw.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" {
        let line = format!("Read-ahead of blocks disabled by {READ_AHEAD_VAR}");
        return (false, Some((LogLevel::Info, line)));
    }
    let line = format!("{READ_AHEAD_VAR}={value} is neither off nor 0; using the default");
    (true, Some((LogLevel::Warn, line)))
}

/// What the reader threads of this process have done, for the line the
/// daemon logs as it shuts down ([`shutdown_line`]).  Process-wide and
/// relaxed: they are sums for a person to read, and nothing depends on
/// a connection's threads having been joined before they are read.
struct Stats {
    /// Connections that started a reader thread.
    connections: AtomicU64,
    /// Reads the reader threads made, failed ones included.
    frames: AtomicU64,
    /// Blocks the reader threads read.
    blocks: AtomicU64,
    /// The wire bytes of those blocks.
    block_bytes: AtomicU64,
    /// Time the reader threads spent on checksums and decoding.
    decode_nanos: AtomicU64,
    /// Time the reader threads spent hashing blocks
    /// (`HashedBlock::new`: the hashes, the merkle trees and the counts
    /// of signature operations) and making their data sanity checks
    /// (`HashedBlock::check_data_sanity`).
    hash_nanos: AtomicU64,
    /// Blocks the reader threads handed over with the payload they were
    /// decoded from laid out as a block-file record.
    records: AtomicU64,
    /// Time the reader threads spent comparing those payloads with the
    /// blocks' serializations and laying the records out, the ones that
    /// were then dropped included.
    record_nanos: AtomicU64,
    /// Time the reader threads were parked with read-ahead allowed, that
    /// is with the queue full.
    reader_waited_nanos: AtomicU64,
    /// Time the handlers were parked waiting for a block while reading
    /// ahead was wanted.
    handler_waited_nanos: AtomicU64,
    /// The most items any connection's queue has held.
    max_queued: AtomicU64,
}

impl Stats {
    /// Counters that have counted nothing.
    const fn new() -> Stats {
        Stats {
            connections: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            block_bytes: AtomicU64::new(0),
            decode_nanos: AtomicU64::new(0),
            hash_nanos: AtomicU64::new(0),
            records: AtomicU64::new(0),
            record_nanos: AtomicU64::new(0),
            reader_waited_nanos: AtomicU64::new(0),
            handler_waited_nanos: AtomicU64::new(0),
            max_queued: AtomicU64::new(0),
        }
    }
}

/// The counters of this process.  A reader thread is handed them as it
/// starts ([`reader_loop`]); the queue adds its waits and its high-water
/// mark to them directly.
static STATS: Stats = Stats::new();

/// Add a duration to a nanosecond counter.
fn add_nanos(counter: &AtomicU64, elapsed: Duration) {
    counter.fetch_add(
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// A nanosecond count as seconds with millisecond precision.
fn seconds(nanos: u64) -> String {
    let millis = nanos / 1_000_000;
    format!("{}.{:03}", millis / 1000, millis % 1000)
}

/// What the reader threads did over the life of the process, as one
/// line, or `None` when no reader thread read anything.
/// `records_written` is how many block-file records the block database
/// wrote as they were handed to it
/// (`dcroxide_database::Database::records_written_as_laid_out`), which
/// the caller reads from the node's database.
///
/// The times are sums over all reader threads.  The checksum and decode
/// time and the hashing time together are timed work that left the block
/// thread; the socket reads themselves are not timed.  The hashing time
/// is that of everything `HashedBlock::new` computes and, where the
/// server gave the values for them, of the blocks' data sanity checks.
/// The two waits say which side was short: the reader waits for the
/// block thread when the queue is full, and the block thread waits for
/// the reader when the queue is empty.  The most items queued is the
/// check on the queue's bound of four.  The index queue's figure
/// ([`crate::indexes::notify_blocked_nanos`]) is how long the block
/// thread was held up handing blocks to the index thread.
///
/// The last three are about the block-file records.  The first is how
/// many of the blocks were handed over with their payload laid out as
/// one; a count below the blocks read means payloads that were not kept.
/// The second is the time the reader threads spent serializing those
/// blocks, comparing the payloads with the serializations and taking the
/// records' checksums: the serialization and the checksum are work the
/// block thread does for every other block as it stores it, and the
/// comparison is the reader's alone.  The third is how many records the
/// database then wrote as they stood.  It is below the first by the
/// blocks the chain did not store, and a database that wrote none of the
/// records laid out for it laid every one of them out again.
pub fn shutdown_line(records_written: u64) -> Option<String> {
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    if load(&STATS.frames) == 0 {
        return None;
    }
    Some(format!(
        "Read-ahead: {} blocks ({} bytes) on {} connections; checksum and decode {} s and \
         hashing {} s done off the block thread; the reader waited {} s for the block thread; \
         the block thread waited {} s for the reader; at most {} items queued; index queue \
         full for {} s; block-file records laid out for {} blocks in {} s, {} written as laid \
         out",
        load(&STATS.blocks),
        load(&STATS.block_bytes),
        load(&STATS.connections),
        seconds(load(&STATS.decode_nanos)),
        seconds(load(&STATS.hash_nanos)),
        seconds(load(&STATS.reader_waited_nanos)),
        seconds(load(&STATS.handler_waited_nanos)),
        load(&STATS.max_queued),
        seconds(crate::indexes::notify_blocked_nanos()),
        load(&STATS.records),
        seconds(load(&STATS.record_nanos)),
        records_written,
    ))
}

#[cfg(test)]
// Test-harness arithmetic over small counts and fixed waits.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    use dcroxide_wire::{
        BlockHeader, CurrencyNet, MESSAGE_HEADER_SIZE, MsgBlock, MsgPing, MsgTx, TxOut,
    };

    /// The network the scripted frames are for.
    const NET: CurrencyNet = CurrencyNet::REG_NET;

    /// How long a test waits for something that must happen.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// How long a test watches for something that must not happen.
    const QUIET: Duration = Duration::from_millis(150);

    /// One scripted read.
    enum Step {
        /// The frame arrives at once, having taken this many bytes.
        Frame(Message, u64),
        /// The message arrives at once with the bytes it is said to have
        /// been decoded from, a message header and then the payload, as
        /// the transport keeps them for a block.
        Kept(Message, Vec<u8>),
        /// The frame arrives once the test opens the gate.
        Gated(Message, u64),
        /// The read fails at once, having taken this many bytes.
        Fail(ReadError, u64),
        /// The read hangs, whatever happens to the connection's flag,
        /// until the test opens the gate, and then fails.
        Hang,
    }

    /// What the scripted reader tells the test about one read.
    #[derive(Debug)]
    struct ReadLog {
        /// The read's position in the script.
        index: usize,
        /// What `since` answered as the read began.
        since_at_start: Option<Instant>,
    }

    /// A [`FrameReader`] that plays a script and reports each read as it
    /// starts.  Past the end of the script a read waits for the
    /// connection's flag and fails as the transport does.
    struct Scripted {
        steps: VecDeque<Step>,
        index: usize,
        total: u64,
        cancel: Cancel,
        started: mpsc::Sender<ReadLog>,
        gate: mpsc::Receiver<()>,
        /// What `since` answered when a gated read was let through.
        since_at_gate: mpsc::Sender<Option<Instant>>,
        /// The frame of the last read, if the script gave it one.
        frame: Option<BlockFrame>,
    }

    impl FrameReader for Scripted {
        fn read(&mut self, since: &dyn Fn() -> Option<Instant>) -> Result<Message, ReadError> {
            let _ = self.started.send(ReadLog {
                index: self.index,
                since_at_start: since(),
            });
            self.index += 1;
            self.frame = None;
            match self.steps.pop_front() {
                Some(Step::Frame(msg, bytes)) => {
                    self.total += bytes;
                    Ok(msg)
                }
                Some(Step::Kept(msg, buf)) => {
                    self.total += buf.len() as u64;
                    self.frame = Some(BlockFrame {
                        buf,
                        payload_at: MESSAGE_HEADER_SIZE,
                        net: NET,
                    });
                    Ok(msg)
                }
                Some(Step::Gated(msg, bytes)) => {
                    let _ = self.gate.recv_timeout(PATIENCE * 6);
                    let _ = self.since_at_gate.send(since());
                    self.total += bytes;
                    Ok(msg)
                }
                Some(Step::Fail(err, bytes)) => {
                    self.total += bytes;
                    Err(err)
                }
                Some(Step::Hang) => {
                    let _ = self.gate.recv_timeout(PATIENCE * 6);
                    Err(ReadError::io("the hung read was released"))
                }
                None => {
                    while !self.cancel.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(ReadError::io(READ_TORN_DOWN_TEXT))
                }
            }
        }

        fn total_bytes_read(&self) -> u64 {
            self.total
        }

        fn take_decode_nanos(&mut self) -> u64 {
            0
        }

        fn take_block_frame(&mut self) -> Option<BlockFrame> {
            self.frame.take()
        }
    }

    /// A reader thread over a script, and the handler's side of its
    /// queue for the test to drive.
    struct Rig {
        shared: Arc<Shared>,
        cancel: Cancel,
        started: mpsc::Receiver<ReadLog>,
        gate: mpsc::Sender<()>,
        since_at_gate: mpsc::Receiver<Option<Instant>>,
        reader: Option<JoinHandle<()>>,
    }

    impl Rig {
        /// Start a reader thread over the script, as a connection does
        /// behind a block it wants read ahead of.
        fn start(steps: Vec<Step>) -> Rig {
            Rig::start_counting(steps, None)
        }

        /// [`Rig::start`] with the reader's own work counted in the
        /// given counters, where it is otherwise counted in the
        /// process's, which every reader thread of this test binary
        /// moves.
        fn start_counting(steps: Vec<Step>, stats: Option<Arc<Stats>>) -> Rig {
            Rig::start_with(steps, stats, None, None)
        }

        /// [`Rig::start`] with the blocks read handed to the given
        /// signature pre-verifier.
        fn start_preverifying(steps: Vec<Step>, preverify: Arc<Preverifier>) -> Rig {
            Rig::start_with(steps, None, Some(preverify), None)
        }

        fn start_with(
            steps: Vec<Step>,
            stats: Option<Arc<Stats>>,
            preverify: Option<Arc<Preverifier>>,
            data_sanity: Option<DataSanityParams>,
        ) -> Rig {
            let cancel = Cancel::new();
            let shared = Arc::new(Shared::new(cancel.clone(), preverify, data_sanity));
            let (started_tx, started) = mpsc::channel();
            let (gate, gate_rx) = mpsc::channel();
            let (since_tx, since_at_gate) = mpsc::channel();
            let scripted = Scripted {
                steps: steps.into(),
                index: 0,
                total: 0,
                cancel: cancel.clone(),
                started: started_tx,
                gate: gate_rx,
                since_at_gate: since_tx,
                frame: None,
            };
            let reader_shared = Arc::clone(&shared);
            let reader = std::thread::spawn(move || {
                reader_loop(scripted, &reader_shared, stats.as_deref().unwrap_or(&STATS));
            });
            Rig {
                shared,
                cancel,
                started,
                gate,
                since_at_gate,
                reader: Some(reader),
            }
        }

        /// The next read to start must be the one at `index`.
        #[track_caller]
        fn expect_started(&self, index: usize) -> ReadLog {
            let log = self
                .started
                .recv_timeout(PATIENCE)
                .unwrap_or_else(|_| panic!("read {index} never started"));
            assert_eq!(log.index, index, "the reads start in script order");
            log
        }

        /// No read may start for a while.
        #[track_caller]
        fn expect_no_start(&self) {
            if let Ok(log) = self.started.recv_timeout(QUIET) {
                panic!(
                    "read {} started before the handler waited for it",
                    log.index
                );
            }
        }

        /// The handler takes its next item, which must be a message.  A
        /// block comes with its hashes, which must be its own.
        #[track_caller]
        fn take(&self) -> Message {
            match self.shared.next().result {
                Ok(Received::Message { msg, .. }) => {
                    assert!(
                        !matches!(msg, Message::Block(_)),
                        "the reader handed over a block it had not hashed"
                    );
                    msg
                }
                Ok(Received::Block(hashed)) => {
                    assert_eq!(*hashed.hash(), hashed.block().header.block_hash());
                    hashed.tx_hashes().assert_for(hashed.block());
                    Message::Block(Arc::unwrap_or_clone(hashed.into_block()))
                }
                Err(e) => panic!("the stream ended early: {e}"),
            }
        }

        /// Wait for the reader thread to exit.
        #[track_caller]
        fn join_reader(&mut self) {
            let reader = self.reader.take().expect("the reader is joined once");
            let deadline = Instant::now() + PATIENCE;
            while !reader.is_finished() {
                assert!(Instant::now() < deadline, "the reader thread did not exit");
                std::thread::sleep(Duration::from_millis(2));
            }
            reader.join().expect("the reader thread panicked");
        }

        /// End the connection as the source does, and wait for the
        /// reader thread.
        #[track_caller]
        fn finish(mut self) {
            self.cancel.cancel();
            self.shared.leave();
            let _ = self.gate.send(());
            self.join_reader();
        }
    }

    /// A block told apart by its header's nonce.
    fn block(nonce: u32) -> Message {
        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        header.nonce = nonce;
        Message::Block(MsgBlock {
            header,
            transactions: Vec::new(),
            stransactions: Vec::new(),
        })
    }

    /// A ping with the nonce.
    fn ping(nonce: u64) -> Message {
        Message::Ping(MsgPing { nonce })
    }

    /// A block with one transaction, told apart by its header's nonce,
    /// and the frame a peer sends it in.
    fn block_and_frame(nonce: u32) -> (MsgBlock, Vec<u8>) {
        let Message::Block(mut block) = block(nonce) else {
            unreachable!("a block");
        };
        let mut tx = MsgTx::default();
        tx.tx_out.push(TxOut {
            value: i64::from(nonce),
            version: 0,
            pk_script: vec![0x51; 40],
        });
        block.transactions.push(tx);
        let frame = dcroxide_wire::write_message(
            &Message::Block(block.clone()),
            dcroxide_wire::PROTOCOL_VERSION,
            NET,
        )
        .expect("frame the block");
        (block, frame)
    }

    /// A frame of the script.
    fn frame(msg: Message) -> Step {
        Step::Frame(msg, 24)
    }

    /// A small deterministic generator for the scripts.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    /// The handler receives the items in exactly the order their frames
    /// were read, blocks and other messages alike.
    #[test]
    fn items_come_out_in_the_order_they_were_read() {
        let mut rng = Lcg(7);
        let script: Vec<Message> = (0..200u32)
            .map(|i| {
                if rng.next().is_multiple_of(3) {
                    ping(u64::from(i))
                } else {
                    block(i)
                }
            })
            .collect();
        let rig = Rig::start(script.iter().cloned().map(frame).collect());
        for (i, want) in script.iter().enumerate() {
            assert_eq!(&rig.take(), want, "item {i}");
        }
        rig.finish();
    }

    /// With the handler busy, exactly four frames are read and the fifth
    /// read waits; each item the handler takes lets one more be read.
    #[test]
    fn at_most_four_items_are_ahead_and_the_fifth_read_waits() {
        let rig = Rig::start((0..10).map(|i| frame(block(i))).collect());
        for index in 0..READ_AHEAD_MAX_ITEMS {
            rig.expect_started(index);
        }
        rig.expect_no_start();
        assert_eq!(rig.shared.max_queued(), READ_AHEAD_MAX_ITEMS);

        // The handler takes one: one more is read, and no more.
        assert_eq!(rig.take(), block(0));
        rig.expect_started(READ_AHEAD_MAX_ITEMS);
        rig.expect_no_start();
        assert_eq!(rig.take(), block(1));
        rig.expect_started(READ_AHEAD_MAX_ITEMS + 1);
        rig.expect_no_start();
        assert_eq!(rig.shared.max_queued(), READ_AHEAD_MAX_ITEMS);
        rig.finish();
    }

    /// Behind a block the next frame is read while the handler is still
    /// busy with the block: it never asks.
    #[test]
    fn the_frame_after_a_block_is_read_while_the_block_is_handled() {
        // The reader starts behind a block the handler has just handled.
        let rig = Rig::start(vec![frame(block(0)), frame(block(1)), frame(ping(2))]);
        let first = rig.expect_started(0);
        assert_eq!(first.since_at_start, None, "nobody was waiting for it");
        rig.expect_started(1);
        rig.expect_started(2);
        assert_eq!(rig.shared.waiting_since(), None);
        rig.finish();
    }

    /// A frame behind a message that is not a block is read only once
    /// the handler is waiting for it with nothing left to take, which is
    /// when `inHandler` would read it.
    #[test]
    fn a_frame_after_a_message_that_is_not_a_block_waits_for_the_handler() {
        let rig = Rig::start(vec![
            frame(block(0)),
            frame(ping(1)),
            frame(block(2)),
            frame(block(3)),
        ]);
        // The block and the ping behind it are read at once; the frame
        // behind the ping is not.
        rig.expect_started(0);
        rig.expect_started(1);
        rig.expect_no_start();

        // Not while the handler has the block, and not while it has the
        // ping: items it took without having to wait.
        assert_eq!(rig.take(), block(0));
        rig.expect_no_start();
        assert_eq!(rig.take(), ping(1));
        rig.expect_no_start();

        // Only when it asks with nothing queued.
        assert_eq!(rig.take(), block(2));
        rig.expect_started(2);
        // And behind that block the reader is ahead again.
        rig.expect_started(3);
        rig.finish();
    }

    /// Once the handler says reading ahead is no longer wanted, every
    /// frame is read only when the handler is waiting for it, blocks
    /// included; when it is wanted again the reader goes ahead again.
    #[test]
    fn when_read_ahead_is_no_longer_wanted_each_frame_waits_for_the_handler() {
        let rig = Rig::start((0..12).map(|i| frame(block(i))).collect());
        for index in 0..READ_AHEAD_MAX_ITEMS {
            rig.expect_started(index);
        }
        rig.expect_no_start();

        // What was read ahead is handed over; nothing more is read
        // meanwhile, although every one of these is a block.
        rig.shared.set_ahead(false);
        for nonce in 0..READ_AHEAD_MAX_ITEMS as u32 {
            assert_eq!(rig.take(), block(nonce));
            rig.expect_no_start();
        }

        // From here each frame is read when the handler waits for it.
        for nonce in 4..7 {
            assert_eq!(rig.take(), block(nonce));
            rig.expect_started(nonce as usize);
            rig.expect_no_start();
        }

        // Wanted again: the parked reader goes ahead without being asked.
        rig.shared.set_ahead(true);
        for index in 7..7 + READ_AHEAD_MAX_ITEMS {
            rig.expect_started(index);
        }
        rig.expect_no_start();
        rig.finish();
    }

    /// A failed read is handed over after every frame read before it,
    /// and the reader reads nothing after it.
    #[test]
    fn a_failed_read_is_delivered_after_the_items_before_it_and_ends_the_stream() {
        let mut rig = Rig::start(vec![
            frame(block(0)),
            frame(block(1)),
            Step::Fail(ReadError::wire("payload checksum failed"), 30),
            frame(block(3)),
            frame(block(4)),
        ]);
        // The reader ends at the failed read, with the handler still
        // busy and nothing taken.
        rig.join_reader();
        for index in 0..3 {
            rig.expect_started(index);
        }
        rig.expect_no_start();

        assert_eq!(rig.take(), block(0));
        assert_eq!(rig.take(), block(1));
        let failed = rig.shared.next();
        assert_eq!(failed.read_delta, 30);
        match failed.result {
            Err(e) => assert_eq!(e, ReadError::wire("payload checksum failed")),
            Ok(_) => panic!("the failed read was handed over as a message"),
        }

        // Past the end there is only the torn-down read, as a read of a
        // connection that is gone gives.
        let after = rig.shared.next();
        assert_eq!(after.read_delta, 0);
        match after.result {
            Err(e) => assert_eq!(e, ReadError::io(READ_TORN_DOWN_TEXT)),
            Ok(_) => panic!("an item behind the failed read"),
        }
    }

    /// Once the connection's flag is up nothing queued is handed over:
    /// the handler gets the read error an inline read gives then.
    #[test]
    fn nothing_queued_is_handed_over_once_the_connection_is_cancelled() {
        let rig = Rig::start((0..4).map(|i| frame(block(i))).collect());
        for index in 0..READ_AHEAD_MAX_ITEMS {
            rig.expect_started(index);
        }
        assert_eq!(rig.take(), block(0));

        rig.cancel.cancel();
        for _ in 0..3 {
            let item = rig.shared.next();
            assert_eq!(item.read_delta, 0);
            match item.result {
                Err(e) => assert_eq!(e, ReadError::io(READ_TORN_DOWN_TEXT)),
                Ok(_) => panic!("a queued item was handed over after the teardown"),
            }
        }
        rig.finish();
    }

    /// A handler parked on an empty queue sees the flag go up within
    /// about a poll interval, with nobody to wake it: the reader here is
    /// stuck in a read that ignores the flag.
    #[test]
    fn a_waiting_handler_notices_the_flag_within_the_poll_interval() {
        let rig = Rig::start(vec![Step::Hang]);
        rig.expect_started(0);

        let (answered_tx, answered) = mpsc::channel();
        let handler_shared = Arc::clone(&rig.shared);
        std::thread::spawn(move || {
            let item = handler_shared.next();
            let _ = answered_tx.send(item.result.map(|_| ()));
        });
        // Let the handler park, then raise the flag behind its back.
        std::thread::sleep(READ_POLL_INTERVAL / 4);
        let raised = Instant::now();
        rig.cancel.cancel();

        let answer = answered
            .recv_timeout(READ_POLL_INTERVAL * 4)
            .expect("the parked handler never looked at the flag again");
        assert_eq!(answer, Err(ReadError::io(READ_TORN_DOWN_TEXT)));
        assert!(raised.elapsed() < READ_POLL_INTERVAL * 3);
        rig.finish();
    }

    /// When the handler leaves, a reader parked on a full queue exits,
    /// and so does one blocked in a read once the connection's flag has
    /// ended that read.
    #[test]
    fn leaving_wakes_a_parked_reader_and_one_blocked_in_a_read() {
        // Parked: four frames are queued and nobody takes them.
        let mut parked = Rig::start((0..10).map(|i| frame(block(i))).collect());
        for index in 0..READ_AHEAD_MAX_ITEMS {
            parked.expect_started(index);
        }
        parked.expect_no_start();
        parked.shared.leave();
        parked.join_reader();
        parked.expect_no_start();

        // Blocked in a read: the script is empty, so the read waits for
        // the flag as the transport's does.
        let mut reading = Rig::start(Vec::new());
        reading.expect_started(0);
        reading.cancel.cancel();
        reading.shared.leave();
        reading.join_reader();
    }

    /// How the handler of the stall test answers after each block.
    #[derive(Clone, Copy, Debug)]
    enum Wanted {
        Always,
        Never,
        Mixed,
    }

    /// Ten thousand items pass through with reading ahead wanted, not
    /// wanted, and switched at random, and with blocks only and blocks
    /// among other messages.  A wake-up lost on either side would leave
    /// both threads parked and the run would not finish in time.
    #[test]
    fn ten_thousand_items_pass_through_in_each_mode_without_a_stall() {
        const ITEMS: u32 = 10_000;
        for (wanted, blocks_only) in [
            (Wanted::Always, true),
            (Wanted::Never, true),
            (Wanted::Never, false),
            (Wanted::Mixed, false),
        ] {
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let mut rng = Lcg(u64::from(blocks_only) + 11);
                let script: Vec<Message> = (0..ITEMS)
                    .map(|i| {
                        if blocks_only || rng.next().is_multiple_of(2) {
                            block(i)
                        } else {
                            ping(u64::from(i))
                        }
                    })
                    .collect();
                let rig = Rig::start(script.iter().cloned().map(frame).collect());
                if matches!(wanted, Wanted::Never) {
                    rig.shared.set_ahead(false);
                }
                for want in &script {
                    let got = rig.take();
                    assert_eq!(&got, want);
                    if matches!(got, Message::Block(_)) {
                        match wanted {
                            Wanted::Always => rig.shared.set_ahead(true),
                            Wanted::Never => rig.shared.set_ahead(false),
                            Wanted::Mixed => rig.shared.set_ahead(!rng.next().is_multiple_of(3)),
                        }
                    }
                }
                assert!(rig.shared.max_queued() <= READ_AHEAD_MAX_ITEMS);
                rig.finish();
                let _ = done_tx.send(());
            });
            done.recv_timeout(Duration::from_secs(30))
                .unwrap_or_else(|_| panic!("{wanted:?}, blocks only {blocks_only}: stalled"));
        }
    }

    /// Each item carries the bytes its own read took, a failed read
    /// included.
    #[test]
    fn each_message_carries_its_own_byte_count() {
        let sizes = [180u64, 24, 393_216, 32, 1];
        let mut steps: Vec<Step> = sizes
            .iter()
            .enumerate()
            .map(|(i, bytes)| Step::Frame(block(i as u32), *bytes))
            .collect();
        steps.push(Step::Fail(ReadError::io("unexpected EOF"), 13));
        let mut rig = Rig::start(steps);
        for bytes in sizes {
            let item = rig.shared.next();
            assert!(item.result.is_ok());
            assert_eq!(item.read_delta, bytes);
        }
        let failed = rig.shared.next();
        assert!(failed.result.is_err());
        assert_eq!(failed.read_delta, 13);
        rig.join_reader();
    }

    /// The instant the transport is given for a frame's idle budget is
    /// unset while the handler is busy or has an item to take, and is
    /// the moment the handler began to wait once it does.
    #[test]
    fn the_budget_start_is_none_while_the_handler_is_busy_and_set_when_it_waits() {
        let rig = Rig::start(vec![frame(block(0)), Step::Gated(block(1), 24)]);
        // Both reads begin with the handler busy.
        assert_eq!(rig.expect_started(0).since_at_start, None);
        assert_eq!(rig.expect_started(1).since_at_start, None);

        // Taking an item that was ready is not waiting.
        assert_eq!(rig.take(), block(0));
        assert_eq!(rig.shared.waiting_since(), None);

        // The handler asks for the frame still being read: it waits.
        let before = Instant::now();
        let (taken_tx, taken) = mpsc::channel();
        let handler_shared = Arc::clone(&rig.shared);
        std::thread::spawn(move || {
            let _ = taken_tx.send(handler_shared.next().result.is_ok());
        });
        let deadline = Instant::now() + PATIENCE;
        let waiting = loop {
            if let Some(since) = rig.shared.waiting_since() {
                break since;
            }
            assert!(Instant::now() < deadline, "the handler never began waiting");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(waiting >= before && waiting <= Instant::now());

        // The read in progress is told the same instant, and it does not
        // move while the handler keeps waiting.
        std::thread::sleep(Duration::from_millis(20));
        rig.gate.send(()).expect("open the gate");
        assert_eq!(
            rig.since_at_gate.recv_timeout(PATIENCE).expect("the gate"),
            Some(waiting)
        );
        assert_eq!(taken.recv_timeout(PATIENCE), Ok(true));
        // The hand-over ends the wait.
        assert_eq!(rig.shared.waiting_since(), None);
        rig.finish();
    }

    /// The instant the handler began waiting does not move while it goes
    /// on waiting, through the poll intervals at which it tests the flag
    /// again: an idle budget longer than one interval still runs out.
    #[test]
    fn the_budget_start_does_not_move_while_the_handler_keeps_waiting() {
        let rig = Rig::start(vec![Step::Gated(block(0), 24)]);
        rig.expect_started(0);
        let (taken_tx, taken) = mpsc::channel();
        let handler_shared = Arc::clone(&rig.shared);
        std::thread::spawn(move || {
            let _ = taken_tx.send(handler_shared.next().result.is_ok());
        });
        let deadline = Instant::now() + PATIENCE;
        let waiting = loop {
            if let Some(since) = rig.shared.waiting_since() {
                break since;
            }
            assert!(Instant::now() < deadline, "the handler never began waiting");
            std::thread::sleep(Duration::from_millis(1));
        };

        // Two and a half poll intervals on, it is still that instant, for
        // the handler and for the read in progress.
        std::thread::sleep(READ_POLL_INTERVAL * 5 / 2);
        assert_eq!(rig.shared.waiting_since(), Some(waiting));
        rig.gate.send(()).expect("open the gate");
        assert_eq!(
            rig.since_at_gate.recv_timeout(PATIENCE).expect("the gate"),
            Some(waiting)
        );
        assert_eq!(taken.recv_timeout(PATIENCE), Ok(true));
        rig.finish();
    }

    /// A frame the reader begins behind a block the handler was parked
    /// for is not charged with the handler's wait for that block.  The
    /// instant that wait began stays on record until the handler takes
    /// the block, and the reader does not wait for that: it goes straight
    /// on to the next frame, which nobody is waiting for while the block
    /// is still queued.  That frame's budget starts when the handler
    /// comes back with nothing left to take.
    ///
    /// The handler here is the test itself, so the moment between the
    /// queueing of the block and its being taken, which lasts as long as
    /// a thread takes to wake, lasts as long as the test needs.
    #[test]
    fn a_frame_behind_a_block_the_handler_waited_for_gets_a_budget_of_its_own() {
        let rig = Rig::start(vec![Step::Gated(block(0), 24), Step::Gated(block(1), 24)]);
        assert_eq!(rig.expect_started(0).since_at_start, None);
        // The handler has been waiting for the frame being read, as
        // `next` records when it finds nothing to take.
        let began = Instant::now();
        rig.shared.lock().waiting_since = Some(began);
        assert_eq!(rig.shared.waiting_since(), Some(began));

        // The block arrives.  Its own read was the one waited for.
        rig.gate.send(()).expect("open the gate");
        assert_eq!(
            rig.since_at_gate.recv_timeout(PATIENCE).expect("the gate"),
            Some(began)
        );
        // It is queued and not yet taken, and the read of the frame
        // behind it begins: nobody is waiting for that one.
        let behind = rig.expect_started(1);
        assert_eq!(
            behind.since_at_start, None,
            "the frame behind a queued block was given the wait for the block"
        );
        assert_eq!(rig.shared.waiting_since(), None);
        // The wait for the block is still on record for its hand-over.
        assert_eq!(rig.shared.lock().waiting_since, Some(began));

        // The handler takes the block, and is busy with it.
        assert_eq!(rig.take(), block(0));
        let taken_at = Instant::now();
        assert_eq!(rig.shared.waiting_since(), None);

        // It comes back for the frame behind, which is still being read,
        // and only now does that frame's budget start.
        let (taken_tx, taken) = mpsc::channel();
        let handler_shared = Arc::clone(&rig.shared);
        std::thread::spawn(move || {
            let _ = taken_tx.send(handler_shared.next().result.is_ok());
        });
        let deadline = Instant::now() + PATIENCE;
        let waiting = loop {
            if let Some(since) = rig.shared.waiting_since() {
                break since;
            }
            assert!(Instant::now() < deadline, "the handler never began waiting");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            waiting >= taken_at,
            "the wait for the block was carried over"
        );
        rig.gate.send(()).expect("open the gate");
        assert_eq!(
            rig.since_at_gate.recv_timeout(PATIENCE).expect("the gate"),
            Some(waiting)
        );
        assert_eq!(taken.recv_timeout(PATIENCE), Ok(true));
        rig.finish();
    }

    /// A reader thread that dies ends the stream for the handler, which
    /// is not left waiting for a frame that will never be queued.
    #[test]
    fn a_reader_thread_that_panics_ends_the_stream_for_the_handler() {
        struct Panicking;

        impl FrameReader for Panicking {
            fn read(&mut self, _since: &dyn Fn() -> Option<Instant>) -> Result<Message, ReadError> {
                panic!("the scripted reader panics");
            }

            fn total_bytes_read(&self) -> u64 {
                0
            }

            fn take_decode_nanos(&mut self) -> u64 {
                0
            }

            fn take_block_frame(&mut self) -> Option<BlockFrame> {
                None
            }
        }

        let shared = Arc::new(Shared::new(Cancel::new(), None, None));
        let reader_shared = Arc::clone(&shared);
        let reader = std::thread::spawn(move || reader_loop(Panicking, &reader_shared, &STATS));
        assert!(reader.join().is_err(), "the reader thread panicked");

        let (answered_tx, answered) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = answered_tx.send(shared.next().result.map(|_| ()));
        });
        let answer = answered
            .recv_timeout(READ_POLL_INTERVAL * 4)
            .expect("the handler is left waiting for a reader that is gone");
        assert_eq!(answer, Err(ReadError::io(READ_TORN_DOWN_TEXT)));
    }

    /// A block at `height` whose one transaction has an input of the
    /// shape signature pre-verification guesses a script for, told apart
    /// by its header's nonce.  Its signature does not verify, which only
    /// makes the lane's work on it short.
    fn guessable_block(nonce: u32, height: u32) -> Message {
        let Message::Block(mut block) = block(nonce) else {
            unreachable!("a block");
        };
        block.header.height = height;
        // Nine bytes of signature, the last its hash type, SigHashAll.
        let mut signature_script = vec![0x09];
        signature_script.extend([0x30; 8]);
        signature_script.push(0x01);
        signature_script.push(0x21);
        signature_script.extend([0x02; 33]);
        let mut tx = MsgTx::default();
        tx.tx_in.push(dcroxide_wire::TxIn {
            previous_out_point: dcroxide_wire::OutPoint {
                hash: Hash([nonce as u8; 32]),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            sequence: u32::MAX,
            signature_script,
            ..dcroxide_wire::TxIn::default()
        });
        block.transactions.push(tx);
        Message::Block(block)
    }

    /// A pre-verifier on the process-wide script pool whose queue has
    /// room for `blocks` blocks of [`guessable_block`]'s size, or `None`
    /// on a machine whose pool has no helper.
    fn preverifier(blocks: usize, floor: i64) -> Option<Arc<Preverifier>> {
        let Message::Block(sample) = guessable_block(0, 0) else {
            unreachable!("a block");
        };
        let room = sample.serialize_size() * blocks;
        let cache = Arc::new(dcroxide_txscript::SigCache::new(100));
        let preverifier = Preverifier::new(cache, 1, room)?;
        preverifier.set_floor(floor);
        Some(Arc::new(preverifier))
    }

    /// The reader hands the blocks above the floor to signature
    /// pre-verification, which holds each until the handler takes it:
    /// with room for one block, the block behind one not yet taken is
    /// refused, and the one behind one taken is queued.
    #[test]
    fn blocks_read_ahead_are_preverified_above_the_floor_until_taken() {
        let Some(preverifier) = preverifier(1, 10) else {
            return;
        };
        let rig = Rig::start_preverifying(
            vec![
                frame(guessable_block(0, 10)),
                frame(guessable_block(1, 11)),
                Step::Gated(guessable_block(2, 12), 24),
                Step::Gated(guessable_block(3, 13), 24),
                frame(ping(4)),
            ],
            Arc::clone(&preverifier),
        );
        // Block 0 is at the floor and is not handed over; block 1 is.
        for index in 0..3 {
            rig.expect_started(index);
        }
        let counts = preverifier.counts();
        assert_eq!((counts.blocks, counts.refused), (1, 0));
        // Block 2 finds block 1 still held.
        let _ = rig.gate.send(());
        rig.expect_started(3);
        assert_eq!(preverifier.counts().refused, 1);
        // Taking block 1 lets it go: block 3 is queued.
        assert_eq!(rig.take(), guessable_block(0, 10));
        assert_eq!(rig.take(), guessable_block(1, 11));
        let _ = rig.gate.send(());
        rig.expect_started(4);
        let counts = preverifier.counts();
        assert_eq!((counts.blocks, counts.refused), (2, 1));
        assert_eq!(counts.inputs, 2);
        assert_eq!(rig.take(), guessable_block(2, 12));
        assert_eq!(rig.take(), guessable_block(3, 13));
        assert_eq!(rig.take(), ping(4));
        rig.finish();
        // Nothing is held once every block was taken.
        let Message::Block(block) = guessable_block(5, 15) else {
            unreachable!("a block");
        };
        let hashed = HashedBlock::new(Arc::new(block));
        assert!(preverifier.submit(&hashed).is_some());
    }

    /// A handler that leaves withdraws the blocks still queued, and a
    /// block the reader read as the handler left is withdrawn as it is
    /// dropped.
    #[test]
    fn a_handler_that_leaves_lets_preverification_go_of_its_blocks() {
        let Some(preverifier) = preverifier(2, -1) else {
            return;
        };
        let rig = Rig::start_preverifying(
            vec![
                frame(guessable_block(0, 1)),
                frame(guessable_block(1, 2)),
                Step::Hang,
            ],
            Arc::clone(&preverifier),
        );
        for index in 0..3 {
            rig.expect_started(index);
        }
        assert_eq!(preverifier.counts().blocks, 2);
        rig.finish();
        let submit = |nonce: u32| {
            let Message::Block(block) = guessable_block(nonce, 9) else {
                unreachable!("a block");
            };
            preverifier.submit(&HashedBlock::new(Arc::new(block)))
        };
        let first = submit(7).expect("the queue has room again");
        let _second = submit(8).expect("for both blocks");
        preverifier.withdraw_through(first);

        // A block read after the handler left: queued for
        // pre-verification, then dropped with the frame.
        let Some(preverifier) = preverifier_for_one() else {
            return;
        };
        let mut rig = Rig::start_preverifying(
            vec![Step::Gated(guessable_block(0, 1), 24)],
            Arc::clone(&preverifier),
        );
        rig.expect_started(0);
        rig.shared.leave();
        let _ = rig.gate.send(());
        rig.join_reader();
        assert_eq!(preverifier.counts().blocks, 1);
        let Message::Block(block) = guessable_block(9, 9) else {
            unreachable!("a block");
        };
        assert!(
            preverifier
                .submit(&HashedBlock::new(Arc::new(block)))
                .is_some(),
            "the dropped block was let go"
        );
    }

    /// [`preverifier`] with room for one block and no floor.
    fn preverifier_for_one() -> Option<Arc<Preverifier>> {
        preverifier(1, -1)
    }

    /// Once the handler says reading ahead is no longer wanted, as it
    /// does after the initial chain sync, the reader hands no block to
    /// pre-verification: not the block it was reading when it was told,
    /// nor those it reads in turn after, and again once it is wanted.
    #[test]
    fn blocks_read_while_read_ahead_is_not_wanted_are_not_preverified() {
        let Some(preverifier) = preverifier(8, -1) else {
            return;
        };
        let rig = Rig::start_preverifying(
            vec![
                frame(guessable_block(0, 1)),
                Step::Gated(guessable_block(1, 2), 24),
                frame(guessable_block(2, 3)),
                frame(guessable_block(3, 4)),
                frame(guessable_block(4, 5)),
            ],
            Arc::clone(&preverifier),
        );
        rig.expect_started(0);
        rig.expect_started(1);
        // Block 0 was read ahead and handed over.
        assert_eq!(preverifier.counts().blocks, 1);
        rig.shared.set_ahead(false);
        let _ = rig.gate.send(());
        assert_eq!(rig.take(), guessable_block(0, 1));
        assert_eq!(rig.take(), guessable_block(1, 2));
        // Each from here is read once the handler waits for it.
        assert_eq!(rig.take(), guessable_block(2, 3));
        rig.expect_started(2);
        assert_eq!(rig.take(), guessable_block(3, 4));
        rig.expect_started(3);
        assert_eq!(preverifier.counts().blocks, 1);
        // Wanted again, the next block read is handed over.
        rig.shared.set_ahead(true);
        assert_eq!(rig.take(), guessable_block(4, 5));
        rig.expect_started(4);
        assert_eq!(preverifier.counts().blocks, 2);
        rig.finish();
    }

    /// A reader given the values of the chain parameters makes the data
    /// sanity checks of every block it hashes with them, ahead of the
    /// handler and in turn alike, and hands each block over carrying that
    /// verdict.  A reader given none hands every block over without one.
    /// Messages that are not blocks are handed over as they were read
    /// either way.
    #[test]
    fn blocks_read_carry_the_sanity_checks_made_with_the_values_given() {
        let values = DataSanityParams::of(&dcroxide_chaincfg::regnet_params());
        for given in [Some(values), None] {
            let rig = Rig::start_with(
                vec![
                    frame(block(1)),
                    Step::Gated(block(2), 24),
                    frame(ping(3)),
                    frame(block(4)),
                ],
                None,
                None,
                given,
            );
            let take_block = |nonce: u32| match rig.shared.next().result {
                Ok(Received::Block(hashed)) => {
                    assert_eq!(hashed.block().header.nonce, nonce);
                    assert_eq!(hashed.data_sanity_params(), given, "block {nonce}");
                }
                Ok(Received::Message { msg, .. }) => panic!("block {nonce} arrived as {msg:?}"),
                Err(e) => panic!("block {nonce}: {e}"),
            };
            // Blocks 1 and 2 are read ahead of the handler.
            rig.expect_started(0);
            rig.expect_started(1);
            rig.shared.set_ahead(false);
            let _ = rig.gate.send(());
            take_block(1);
            take_block(2);
            // From here each frame is read once the handler waits for it.
            assert_eq!(rig.take(), ping(3));
            rig.expect_started(2);
            take_block(4);
            rig.expect_started(3);
            rig.finish();
        }
    }

    /// `DCROXIDE_READ_AHEAD` turns the read-ahead off with `off` or `0`
    /// and says so; unset it stays on and nothing is said; anything else
    /// warns and leaves it on.
    #[test]
    fn read_ahead_settings_parse() {
        assert_eq!(read_ahead_setting(None), (true, None));
        for raw in ["off", "OFF", "Off", " off ", "0", "\t0\n"] {
            assert_eq!(
                read_ahead_setting(Some(raw)),
                (
                    false,
                    Some((
                        LogLevel::Info,
                        "Read-ahead of blocks disabled by DCROXIDE_READ_AHEAD".to_string()
                    ))
                ),
                "{raw:?}"
            );
        }
        for raw in ["", " ", "on", "1", "true", "no", "false", "00", "off0", "4"] {
            assert_eq!(
                read_ahead_setting(Some(raw)),
                (
                    true,
                    Some((
                        LogLevel::Warn,
                        format!(
                            "DCROXIDE_READ_AHEAD={} is neither off nor 0; using the default",
                            raw.trim()
                        )
                    ))
                ),
                "{raw:?}"
            );
        }
    }

    /// A block the reader is handed with the frame it was decoded from
    /// goes to the handler with that frame's payload laid out as its
    /// block-file record, for the frame's network and in the frame's own
    /// buffer: the payload is not copied on the way.  A block read
    /// without a frame goes without a record, and so does one whose
    /// frame holds anything but its serialization: a byte more, or
    /// another block of the same length.  The block and its hashes
    /// arrive either way, and only the records that were kept are
    /// counted.
    #[test]
    fn a_block_is_handed_over_with_its_frame_laid_out_as_its_record() {
        use dcroxide_database::BlockRecord;

        let (kept, mut kept_frame) = block_and_frame(1);
        let (bare, bare_frame) = block_and_frame(2);
        let (longer, mut longer_frame) = block_and_frame(3);
        longer_frame.push(0);
        let (paired, paired_frame) = block_and_frame(4);
        let (_, another_frame) = block_and_frame(5);
        assert_eq!(another_frame.len(), paired_frame.len());

        // Room behind the payload for the record's checksum, as the
        // transport reserves it, and where the payload lies: the record
        // must be laid out around it there.
        kept_frame.reserve_exact(BlockRecord::SUFFIX_LEN);
        let payload_at = kept_frame[MESSAGE_HEADER_SIZE..].as_ptr();
        let kept_wire = kept_frame.clone();

        // The reader's work is counted in counters of this test's own:
        // the process's are moved by every reader thread of this binary.
        let stats = Arc::new(Stats::new());
        let rig = Rig::start_counting(
            vec![
                Step::Kept(Message::Block(kept.clone()), kept_frame),
                Step::Frame(Message::Block(bare.clone()), bare_frame.len() as u64),
                Step::Kept(Message::Block(longer.clone()), longer_frame),
                Step::Kept(Message::Block(paired.clone()), another_frame),
            ],
            Some(Arc::clone(&stats)),
        );
        let take = || match rig.shared.next().result {
            Ok(Received::Block(hashed)) => hashed,
            Ok(Received::Message { msg, .. }) => panic!("not hashed: {msg:?}"),
            Err(e) => panic!("the stream ended early: {e}"),
        };

        let hashed = take();
        assert_eq!(**hashed.block(), kept);
        let record = hashed.record().expect("the frame's payload was kept");
        assert_eq!(record.block(), kept.serialize());
        assert_eq!(record.block(), &kept_wire[MESSAGE_HEADER_SIZE..]);
        assert_eq!(
            record.block().as_ptr(),
            payload_at,
            "the payload was copied on its way to the record"
        );
        assert_eq!(record.hash(), hashed.hash());
        assert_eq!(record.network(), NET.0);
        // The record's leading fields, laid over the end of the frame's
        // header: the network and the block's length.
        let prefix = [
            NET.0.to_le_bytes(),
            (kept.serialize_size() as u32).to_le_bytes(),
        ]
        .concat();
        assert_eq!(record.as_bytes()[..8], prefix);
        assert_eq!(
            record.as_bytes().len(),
            kept_wire.len() - MESSAGE_HEADER_SIZE + 12
        );

        for (block, what) in [
            (bare, "no frame"),
            (longer, "a byte behind the block"),
            (paired, "another block's frame"),
        ] {
            let hashed = take();
            assert_eq!(**hashed.block(), block, "{what}");
            assert_eq!(*hashed.hash(), block.header.block_hash(), "{what}");
            hashed.tx_hashes().assert_for(hashed.block());
            assert!(hashed.record().is_none(), "{what}");
        }
        rig.finish();
        // Four blocks read, one record: the shutdown line counts the
        // records that were kept, not the frames that were offered.
        assert_eq!(stats.blocks.load(Ordering::Relaxed), 4, "blocks read");
        assert_eq!(stats.records.load(Ordering::Relaxed), 1, "records laid out");
    }

    /// The shutdown line reports times in seconds to the millisecond,
    /// and exists once a reader thread has read something.
    #[test]
    fn the_shutdown_line_reports_what_the_readers_did() {
        assert_eq!(seconds(0), "0.000");
        assert_eq!(seconds(999_999), "0.000");
        assert_eq!(seconds(1_234_567_890), "1.234");
        assert_eq!(seconds(61_000_000_000), "61.000");

        let rig = Rig::start(vec![Step::Frame(block(0), 180)]);
        assert_eq!(rig.take(), block(0));
        rig.finish();
        let line = shutdown_line(7).expect("a reader thread read a block");
        assert!(line.starts_with("Read-ahead: "), "{line}");
        for part in [
            " blocks (",
            " bytes) on ",
            " connections; checksum and decode ",
            " s and hashing ",
            " s done off the block thread; the reader waited ",
            " s for the block thread; the block thread waited ",
            " s for the reader; at most ",
            " items queued; index queue full for ",
            " s; block-file records laid out for ",
            " blocks in ",
        ] {
            assert!(line.contains(part), "{part:?} is missing from: {line}");
        }
        // The line ends with the count it was handed, the database's.
        assert!(line.ends_with(" s, 7 written as laid out"), "{line}");
    }
}
