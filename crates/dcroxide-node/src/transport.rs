// SPDX-License-Identifier: ISC
//! The wire-message transport over a byte stream — dcrd's message
//! framing (`ReadMessage`/`WriteMessage`) applied to a peer connection.
//!
//! The ported peer module drives the version handshake and the per-peer
//! message loops over the [`dcroxide_peer::MsgTransport`] trait, leaving
//! the concrete framing to the daemon.  [`WireTransport`] is that
//! framing: it reads and writes whole [`Message`]s over any byte stream
//! (a TCP connection in the daemon, an in-memory pipe in tests) using
//! the ported wire codec, and tallies the wire bytes moved in each
//! direction so the peer loop can feed dcrd's byte accounting.
//!
//! The idle read deadline dcrd sets before each read
//! (`SetReadDeadline(now + IdleTimeout)` in `readMessage`) is an
//! absolute bound over the whole message; the transport reproduces it
//! by running every receive under a read timeout of the remaining
//! budget, so a byte-dribbling peer cannot extend one message read past
//! the budget the peer loop configures.
//!
//! That budget is minutes long, so the read is additionally chopped
//! into [`READ_POLL_INTERVAL`] slices and a [`Cancel`] flag is checked
//! between them.  Go's `Conn.Close` makes a goroutine blocked in `Read`
//! return on every platform, so dcrd tears a connection down by closing
//! it; the port has no equivalent, because `TcpStream::shutdown` on one
//! `try_clone`d handle does not reliably abort a blocking `recv` already
//! in flight on another handle under Winsock.  Waiting on the socket
//! alone therefore left a peer the stall detector had already logged as
//! disconnected parked until its idle timeout expired.  Polling a flag
//! makes teardown promptness independent of that platform difference.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use crate::socktimeout::SocketTimeout;

use dcroxide_peer::MsgTransport;
use dcroxide_wire::{
    CurrencyNet, MESSAGE_HEADER_SIZE, Message, read_message as wire_read_message,
    read_message_header as wire_read_message_header, write_message as wire_write_message,
};

/// How long a single receive may block before the read loop comes back
/// up to re-check the deadline and the [`Cancel`] flag.
///
/// This is a teardown-latency knob, not a timeout: the absolute budget
/// still governs when a read fails, and a slice expiring is not an
/// error.  A second is far inside dcrd's fifteen-second stall tick while
/// costing one wake-up per second per idle connection — about 125 a
/// second at the default `--maxpeers`, against the tens of thousands of
/// messages a second the same threads handle mid-sync.
pub const READ_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// A one-way "stop reading" signal shared by a connection's loops.
///
/// The peer's threads cannot rely on the socket to carry this: see the
/// module documentation on `shutdown` versus a blocking `recv` under
/// Winsock.  Whoever decides the connection is over — the stall
/// detector, the output loop, the server's shutdown — raises this, and
/// the reader notices within [`READ_POLL_INTERVAL`] rather than
/// whenever its idle budget happens to run out.
///
/// The flag also records whether the node's own shutdown raised it
/// ([`Cancel::cancel_for_shutdown`]): dcrd's shutdown cancels the server
/// context rather than only closing the conn, and a handshake reports
/// that differently (`Handshake`'s `ctx.Done` arm,
/// `peer/peer.go:2352-2353`).
#[derive(Clone, Default)]
pub struct Cancel(std::sync::Arc<std::sync::atomic::AtomicU8>);

/// [`Cancel`]'s raised state.
const CANCEL_RAISED: u8 = 1;

/// [`Cancel`]'s raised state when the node's shutdown raised it.  It is
/// above [`CANCEL_RAISED`], so a plain raise never clears it.
const CANCEL_SHUTDOWN: u8 = 2;

impl Cancel {
    /// A flag that has not been raised.
    pub fn new() -> Cancel {
        Cancel::default()
    }

    /// Raise the flag.  Idempotent, and safe to call from any thread.
    pub fn cancel(&self) {
        self.0
            .fetch_max(CANCEL_RAISED, std::sync::atomic::Ordering::Relaxed);
    }

    /// Raise the flag because the node is shutting down.  Idempotent,
    /// and safe to call from any thread.
    pub fn cancel_for_shutdown(&self) {
        self.0
            .fetch_max(CANCEL_SHUTDOWN, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the flag has been raised.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed) != 0
    }

    /// Whether the node's shutdown raised the flag.
    pub fn is_shutdown(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed) == CANCEL_SHUTDOWN
    }
}

/// A connection's teardown handle: a socket handle to shut down and the
/// [`Cancel`] flag its reader polls, bound together so neither half can
/// be raised without the other (dcrd `peer.Peer.Disconnect`,
/// `peer/peer.go:1974-1986`, which closes `p.conn` and CASes
/// `p.disconnect` / closes `p.quit` inside one method under one mutex).
///
/// dcrd needs no such pairing at its call sites: `Conn.Close` alone
/// aborts every blocked `Read`, so `Disconnect` is the whole teardown
/// and its callers in `server.go` cannot get it half right.  The port
/// needs both halves -- see this module's documentation on `shutdown`
/// versus a blocking `recv` under Winsock -- and used to write them out
/// by hand at each site, which is why the server's own disconnect paths
/// shut the socket down and left the flag alone while the peer loops
/// raised both.  Owning both here makes the mismatch unrepresentable: a
/// disconnect path holds a `Teardown` rather than a `TcpStream`, so it
/// has no lone socket handle to shut down.
pub struct Teardown {
    conn: std::net::TcpStream,
    cancel: Cancel,
}

impl Teardown {
    /// A teardown handle for a freshly accepted or dialed connection,
    /// its flag lowered.
    pub fn new(conn: std::net::TcpStream) -> Teardown {
        Teardown {
            conn,
            cancel: Cancel::new(),
        }
    }

    /// Another handle on the same connection, sharing this one's flag.
    ///
    /// Sharing is the invariant the whole mechanism rests on: the reader
    /// polls the flag its transport was handed, so a handle carrying a
    /// second flag would raise one nobody reads -- the pre-fix
    /// behaviour, reintroduced silently.  Deliberately fallible, exactly
    /// like the `TcpStream::try_clone` it wraps, so the callers that
    /// already tolerate a failed clone keep doing so unchanged.
    pub fn try_clone(&self) -> std::io::Result<Teardown> {
        Ok(Teardown {
            conn: self.conn.try_clone()?,
            cancel: self.cancel.clone(),
        })
    }

    /// This connection's flag, to hand its read transport
    /// ([`WireTransport::set_cancel`]).
    pub fn cancel(&self) -> Cancel {
        self.cancel.clone()
    }

    /// Borrow the socket handle, for the address queries the server
    /// makes of it (`local_addr`, reported as `getpeerinfo`'s
    /// `addrlocal`).  Not a teardown seam: end a connection with
    /// [`Teardown::disconnect`], never with a bare `shutdown` here.
    pub fn get_ref(&self) -> &std::net::TcpStream {
        &self.conn
    }

    /// End the connection: raise the flag the reader polls, then shut
    /// the socket down so the remote gets its FIN (dcrd
    /// `peer.Peer.Disconnect`, whose single `p.conn.Close()` does both).
    /// Idempotent, and safe to call from any thread.
    ///
    /// It takes no lock -- the flag is one relaxed atomic store and the
    /// shutdown is a syscall -- so it is safe to call while a registry
    /// mutex is held, which is where the server's disconnect paths call
    /// it from.  dcrd does the same: `disconnectNode` calls
    /// `Disconnect()` under `peerState.Lock()`.
    ///
    /// The flag goes up first, so there is never a moment when the
    /// socket is dead and the flag is still down.
    pub fn disconnect(&self) {
        self.cancel.cancel();
        let _ = self.conn.shutdown(std::net::Shutdown::Both);
    }

    /// End the connection because the node is shutting down: the same
    /// teardown as [`Teardown::disconnect`], with the flag marked as the
    /// shutdown's ([`Cancel::cancel_for_shutdown`]).  dcrd's shutdown
    /// cancels the server context that each `Handshake` selects on, so a
    /// handshake it cuts short fails with `errHandshakeTimeout` from that
    /// arm (`peer/peer.go:2352-2353`), not with the read it interrupted.
    pub fn disconnect_for_shutdown(&self) {
        self.cancel.cancel_for_shutdown();
        let _ = self.conn.shutdown(std::net::Shutdown::Both);
    }
}

// Framing runs directly over the teardown handle rather than over a
// further clone of the socket, so pairing the flag with the handle costs
// a connection no extra descriptors.  `&TcpStream` is itself `Read` and
// `Write` in std, which is what makes the delegation free.
impl Read for Teardown {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&self.conn).read(buf)
    }
}

impl Write for Teardown {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&self.conn).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&self.conn).flush()
    }
}

// The impl lives here rather than in `socktimeout.rs`, whose module
// documentation places it there for types belonging to neither caller;
// `Teardown` is this module's own.
impl SocketTimeout for Teardown {
    fn set_socket_read_timeout(&self, timeout: Option<Duration>) {
        let _ = self.conn.set_read_timeout(timeout);
    }

    fn set_socket_write_timeout(&self, timeout: Option<Duration>) {
        let _ = self.conn.set_write_timeout(timeout);
    }
}

/// Server-wide wire byte totals (dcrd's `bytesReceived`/`bytesSent`
/// atomic pair on the server, fed by every peer's reads and writes and
/// served by the getnettotals RPC).
#[derive(Default)]
pub struct NetByteTotals {
    /// Total wire bytes received from all peers.
    pub bytes_received: std::sync::atomic::AtomicU64,
    /// Total wire bytes sent to all peers.
    pub bytes_sent: std::sync::atomic::AtomicU64,
}

impl NetByteTotals {
    /// A zeroed totals pair.
    pub fn new() -> NetByteTotals {
        NetByteTotals::default()
    }
}

/// How long a single message write may take before the peer counts as
/// stalled: a base allowance plus one second per `bytes_per_sec` bytes
/// of the framed message (dcrd `writeStallTimeout` /
/// `writeStallBytesPerSec`, applied at `peer/peer.go:1013-1016`).
///
/// Configurable rather than hard-wired to dcrd's constants so tests can
/// drive the same arithmetic at millisecond scale; the daemon always
/// passes the upstream values.
#[derive(Clone, Copy, Debug)]
pub struct WriteStallPolicy {
    /// dcrd `writeStallTimeout`.
    pub base: Duration,
    /// dcrd `writeStallBytesPerSec`.
    pub bytes_per_sec: usize,
}

impl WriteStallPolicy {
    /// dcrd's constants (`peer/peer.go:84`, `:90`).
    pub fn dcrd() -> WriteStallPolicy {
        WriteStallPolicy {
            base: Duration::from_nanos(dcroxide_peer::WRITE_STALL_TIMEOUT as u64),
            bytes_per_sec: dcroxide_peer::WRITE_STALL_BYTES_PER_SEC,
        }
    }

    /// The deadline a framed message of `msg_size` bytes gets.
    ///
    /// The division truncates, matching Go's
    /// `time.Duration(msgSize/writeStallBytesPerSec) * time.Second`: one
    /// byte short of the next multiple buys nothing, so 262,143 bytes
    /// gets the base alone and 262,144 gets one extra second.  A zero
    /// `bytes_per_sec` would divide by zero, so it yields no allowance
    /// rather than panicking on a misconfiguration.
    pub fn deadline_for(&self, msg_size: usize) -> Duration {
        // `checked_div` covers the divide-by-zero a misconfigured
        // policy would otherwise cause; dcrd cannot hit it because its
        // divisor is a constant.
        let allowance = msg_size.checked_div(self.bytes_per_sec).unwrap_or(0) as u64;
        self.base.saturating_add(Duration::from_secs(allowance))
    }
}

/// Frames [`Message`]s over a byte stream using dcrd's wire encoding.
pub struct WireTransport<S> {
    stream: S,
    pver: u32,
    net: CurrencyNet,
    bytes_read: u64,
    bytes_written: u64,
    /// The absolute budget covering each whole message read (dcrd's
    /// per-`readMessage` `SetReadDeadline`); `None` leaves the
    /// stream's own timeout, if any, to govern each receive.
    read_budget: Option<Duration>,
    /// How long each whole message write may take before the peer
    /// counts as stalled.  A peer that stops reading otherwise parks
    /// this thread forever while its outbound queue is held.  The bound
    /// scales with the message, as dcrd's does since `62fd529a`: a flat
    /// budget either cuts off a large block on a slow-but-honest link
    /// or gives a peer stalling a tiny message far too long.
    write_stall: Option<WriteStallPolicy>,
    /// The server-wide totals this transport contributes to, when the
    /// daemon's accounting is wired (dcrd's `OnRead`/`OnWrite`
    /// listeners adding into the server's atomic counters).
    net_totals: Option<std::sync::Arc<NetByteTotals>>,
    /// Raised when some other loop has decided the connection is over,
    /// so a read in progress gives up instead of waiting out its budget.
    cancel: Option<Cancel>,
    /// The receive timeout this transport last armed on the stream, so
    /// a budgeted receive re-arms only when the slice it needs differs.
    /// That slice is [`READ_POLL_INTERVAL`] for every receive but those
    /// in a budget's final second, and each arming is a `setsockopt`
    /// where Go's `SetReadDeadline` is a runtime timer.  `None` until
    /// the first budgeted receive: the stream arrives with whatever
    /// timeout it had.  Only a connection's read transport receives, so
    /// nothing else re-arms the timeout behind this record.
    read_timeout_armed: Option<Duration>,
    /// Whether a bounded write left the stream's send timeout armed.
    /// It stays armed between messages, because the next bounded write
    /// re-arms it before every send anyway; an unbounded write clears
    /// it first, so it still runs with no timeout at all.
    write_timeout_armed: bool,
}

impl<S> WireTransport<S> {
    /// Wrap a stream, framing messages for the given protocol version
    /// and network.
    pub fn new(stream: S, pver: u32, net: CurrencyNet) -> WireTransport<S> {
        WireTransport {
            stream,
            pver,
            net,
            bytes_read: 0,
            bytes_written: 0,
            read_budget: None,
            write_stall: None,
            net_totals: None,
            cancel: None,
            read_timeout_armed: None,
            write_timeout_armed: false,
        }
    }

    /// Share the connection's cancellation flag with this transport, so
    /// a read in progress stops when another loop tears the connection
    /// down instead of waiting out the idle budget.
    pub fn set_cancel(&mut self, cancel: Cancel) {
        self.cancel = Some(cancel);
    }

    /// The cancellation flag shared with this transport, if any.
    pub fn cancel_flag(&self) -> Option<&Cancel> {
        self.cancel.as_ref()
    }

    /// Contribute this transport's reads and writes to the server-wide
    /// byte totals.
    pub fn set_net_totals(&mut self, totals: std::sync::Arc<NetByteTotals>) {
        self.net_totals = Some(totals);
    }

    /// Set the protocol version future messages are framed at.  The
    /// handshake runs at the local maximum; the daemon lowers this to the
    /// negotiated version once it is known, matching dcrd's per-message
    /// use of the peer's current protocol version.
    pub fn set_protocol_version(&mut self, pver: u32) {
        self.pver = pver;
    }

    /// The total wire bytes read from the stream so far (header and
    /// payload).  The peer loop snapshots this around a read to feed
    /// dcrd's per-message receive accounting.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// The total wire bytes written to the stream so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Borrow the underlying stream (for setting a read deadline, say).
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Mutably borrow the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Recover the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Set the absolute budget each whole message read must complete
    /// within (dcrd's `SetReadDeadline(now + IdleTimeout)` before each
    /// `readMessage`).
    pub fn set_read_budget(&mut self, budget: Option<Duration>) {
        self.read_budget = budget;
    }

    /// Set the write-stall policy each whole message write is bounded
    /// by; `None` leaves writes unbounded.
    pub fn set_write_stall_policy(&mut self, policy: Option<WriteStallPolicy>) {
        self.write_stall = policy;
    }
}

/// Fill the buffer under an absolute deadline, in receives of at most
/// [`READ_POLL_INTERVAL`] so `cancel` is honoured promptly; with no
/// deadline the reads run under the stream's own settings.
///
/// The deadline is the bound that can fail the read.  A slice expiring
/// is not a failure — it is the loop coming back up to look at the clock
/// and the flag — so `WouldBlock`/`TimedOut` continues rather than
/// ending the connection.  That distinction matters for an honest peer
/// too: a large block arriving in dribbles used to die on the first
/// receive that returned nothing, where now only the whole-message
/// budget can end it, which is what dcrd's per-message
/// `SetReadDeadline` actually means.
///
/// `got` is advanced by every byte received, so a caller learns what a
/// failed read took off the wire as well as a whole one (dcrd's
/// `ReadMessageN` returns its `totalBytes` on every path).
///
/// `armed` is the receive timeout last armed on the stream (see
/// `WireTransport::read_timeout_armed`).  Each receive runs under
/// `remaining.min(READ_POLL_INTERVAL)`; the timeout is set only when
/// that differs from the one already armed.
fn read_exact_by_deadline<S: Read + SocketTimeout>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel: Option<&Cancel>,
    got: &mut usize,
    armed: &mut Option<Duration>,
) -> std::io::Result<()> {
    let cancelled = || {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "the connection was torn down locally",
        )
    };
    let unexpected_eof = || {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        )
    };
    let mut filled = 0usize;
    let Some(deadline) = deadline else {
        // With no budget there is nothing to slice against, so the
        // flag can only be checked before parking in the read.  The
        // peer loop always sets a budget; this is the in-memory test
        // path and the pre-handshake path.  The loop is `read_exact`'s,
        // counting as it goes.
        if cancel.is_some_and(Cancel::is_cancelled) {
            return Err(cancelled());
        }
        while filled < buf.len() {
            match stream.read(&mut buf[filled..]) {
                Ok(0) => return Err(unexpected_eof()),
                Ok(n) => {
                    filled = filled.saturating_add(n);
                    *got = got.saturating_add(n);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        return Ok(());
    };
    while filled < buf.len() {
        if cancel.is_some_and(Cancel::is_cancelled) {
            return Err(cancelled());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timed out",
            ));
        }
        // Compared by value, not by "shorter than": a slice clamped in
        // one budget's final second must be raised again for the next.
        let slice = remaining.min(READ_POLL_INTERVAL);
        if *armed != Some(slice) {
            stream.set_socket_read_timeout(Some(slice));
            *armed = Some(slice);
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(unexpected_eof()),
            Ok(n) => {
                filled = filled.saturating_add(n);
                *got = got.saturating_add(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A poll slice elapsed with nothing to read.  Only the
            // deadline check above may end this read; loop back to it.
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Write the whole buffer under an absolute deadline, re-arming the
/// stream's write timeout with the remaining budget before every send;
/// with no deadline the writes run under the stream's own settings.
///
/// The re-arming is the point.  `SO_SNDTIMEO` bounds a single `send(2)`,
/// and the kernel restarts that timer whenever the call makes progress,
/// so arming it once around `write_all` — which loops on every partial
/// write — bounds nothing: a peer that reopens its receive window by a
/// few bytes just inside the budget keeps the writer parked
/// indefinitely.  Computing the deadline once and charging the elapsed
/// time against it makes the budget cover the whole message, exactly as
/// [`read_exact_by_deadline`] does for the read side.
///
/// `sent` is advanced by every byte the stream accepts, so a caller
/// learns what a failed write put on the wire (dcrd's `WriteMessageN`
/// returns the partial count `Write` reports alongside its error).
fn write_all_by_deadline<S: Write + SocketTimeout>(
    stream: &mut S,
    buf: &[u8],
    deadline: Option<Instant>,
    sent: &mut usize,
) -> std::io::Result<()> {
    let write_zero = || {
        std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "failed to write whole buffer",
        )
    };
    let mut written = 0usize;
    let Some(deadline) = deadline else {
        // `write_all`'s loop, counting as it goes.
        while written < buf.len() {
            match stream.write(&buf[written..]) {
                Ok(0) => return Err(write_zero()),
                Ok(n) => {
                    written = written.saturating_add(n);
                    *sent = sent.saturating_add(n);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        return stream.flush();
    };
    while written < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timed out",
            ));
        }
        stream.set_socket_write_timeout(Some(remaining));
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(write_zero()),
            Ok(n) => {
                written = written.saturating_add(n);
                *sent = sent.saturating_add(n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    // The flush shares the budget: a TLS stream can still have buffered
    // record bytes to push at this point.
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write timed out",
        ));
    }
    stream.set_socket_write_timeout(Some(remaining));
    stream.flush()
}

impl<S: Read + Write + SocketTimeout> WireTransport<S> {
    /// Read and decode the next message, advancing `got` by every byte
    /// taken off the stream on the way, whether or not a message results
    /// (dcrd `wire.ReadMessageN` and the `totalBytes` it returns on every
    /// path).
    fn read_framed(&mut self, got: &mut usize) -> Result<Message, dcroxide_peer::ReadError> {
        // One absolute deadline covers the whole message — header and
        // payload (dcrd's single `SetReadDeadline` before
        // `ReadMessageN`).
        let now = Instant::now();
        let deadline = self.read_budget.map(|b| now.checked_add(b).unwrap_or(now));
        // Read the fixed-size header first so the payload length is
        // known before any payload allocation (dcrd `readMessageHeader`
        // then the payload read).
        let mut buf = vec![0u8; MESSAGE_HEADER_SIZE];
        read_exact_by_deadline(
            &mut self.stream,
            &mut buf,
            deadline,
            self.cancel.as_ref(),
            got,
            &mut self.read_timeout_armed,
        )
        .map_err(|e| dcroxide_peer::ReadError::io(e.to_string()))?;

        // Validate the header before reserving anything for the
        // payload.  dcrd's `readMessageN` checks the global cap, the
        // network magic, the command form, that the command is known,
        // and the command's own maximum payload before it reaches
        // `make([]byte, hdr.length)`.  Reserving on the global cap
        // alone would let a peer name 32 MiB in 24 bytes and then
        // never send the payload, holding that memory for the whole
        // read budget on every one of `maxpeers` connections; the
        // per-command maxima keep it to the message type's real bound.
        let header = wire_read_message_header(&buf, self.pver, self.net)
            .map_err(|e| dcroxide_peer::ReadError::wire(e.to_string()))?;
        let payload_len = header.payload_len as usize;
        if payload_len > 0 {
            buf.resize(MESSAGE_HEADER_SIZE.saturating_add(payload_len), 0);
            read_exact_by_deadline(
                &mut self.stream,
                &mut buf[MESSAGE_HEADER_SIZE..],
                deadline,
                self.cancel.as_ref(),
                got,
                &mut self.read_timeout_armed,
            )
            .map_err(|e| dcroxide_peer::ReadError::io(e.to_string()))?;
        }

        // A codec failure is a wire-protocol violation the daemon bans
        // on -- but only when it carries a dcrd `wire.ErrorCode`.
        // dcrd's `wire/message.go` returns `BtcDecode`'s error raw, so a
        // truncated or malformed payload body surfaces as Go's
        // `io.ErrUnexpectedEOF`, `errors.As(err, &errCode)` fails, and
        // the peer is dropped without a ban.  Only dcrd's own
        // `messageError` paths -- checksum, trailing bytes, the header
        // checks, the coded limits inside the decoders -- ban.
        //
        // `kind_name()` is that test: it is empty exactly for
        // `WireError::Eof` and `WireError::UnexpectedEof`, the two Go io
        // errors.  Over-banning here would cost an honest peer 24 hours
        // over a decoder parity gap, and the handshake reads below are
        // unauthenticated.
        let (msg, _) = wire_read_message(&buf, self.pver, self.net).map_err(|e| {
            if e.kind_name().is_empty() {
                dcroxide_peer::ReadError::io(e.to_string())
            } else {
                dcroxide_peer::ReadError::wire(e.to_string())
            }
        })?;
        Ok(msg)
    }
}

impl<S: Read + Write + SocketTimeout> MsgTransport for WireTransport<S> {
    fn set_protocol_version(&mut self, pver: u32) {
        WireTransport::set_protocol_version(self, pver);
    }

    fn read_message(&mut self) -> Result<Message, dcroxide_peer::ReadError> {
        // Every byte taken off the wire counts, including those of a
        // read that fails: a bad checksum, an unknown command, a payload
        // cut short.  dcrd's `readMessage` adds `ReadMessageN`'s `n` to
        // `bytesReceived`, and its `OnRead` adds it to the server's
        // total, before either looks at the error (`peer/peer.go`,
        // `server.go` `serverPeer.OnRead`).
        let mut got = 0usize;
        let result = self.read_framed(&mut got);
        self.bytes_read = self.bytes_read.saturating_add(got as u64);
        if let Some(totals) = &self.net_totals {
            totals
                .bytes_received
                .fetch_add(got as u64, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    fn write_message(&mut self, msg: &Message) -> Result<(), String> {
        let bytes = wire_write_message(msg, self.pver, self.net).map_err(|e| e.to_string())?;
        // One absolute deadline covers the whole message, so a peer
        // that drip-feeds its receive window cannot park this thread
        // past the budget; a timeout surfaces as a write error and
        // disconnects the peer.
        //
        // `bytes` is the framed message — header plus payload — which is
        // exactly dcrd's `wire.MessageHeaderSize + msg.SerializeSize()`
        // (`peer/peer.go:1014`).  dcrd's `SerializeSize` is the encoded
        // payload length, asserted against `len(buf.Bytes())` by its own
        // wire tests, so the two sizes agree by construction and no
        // separate size calculation is needed here.
        let now = Instant::now();
        let deadline = self
            .write_stall
            .map(|p| now.checked_add(p.deadline_for(bytes.len())).unwrap_or(now));
        // A bounded write arms the send timeout before every send, so
        // what an earlier one left armed never governs it, and it leaves
        // the timeout armed rather than spend a `setsockopt` clearing it
        // after every message.  An unbounded write clears it first, so
        // it still runs with no timeout at all.
        if deadline.is_none() && self.write_timeout_armed {
            self.stream.set_socket_write_timeout(None);
            self.write_timeout_armed = false;
        }
        let mut sent = 0usize;
        let result = write_all_by_deadline(&mut self.stream, &bytes, deadline, &mut sent);
        if deadline.is_some() {
            self.write_timeout_armed = true;
        }
        // What reached the stream counts even when the write then fails
        // (dcrd's `writeMessage` adds `WriteMessageN`'s partial `n` to
        // `bytesSent`, and its `OnWrite` to the server's total, whatever
        // the error).  An encoding failure above wrote nothing, as
        // `WriteMessageN` returns zero for it.
        self.bytes_written = self.bytes_written.saturating_add(sent as u64);
        if let Some(totals) = &self.net_totals {
            totals
                .bytes_sent
                .fetch_add(sent as u64, std::sync::atomic::Ordering::Relaxed);
        }
        result.map_err(|e| e.to_string())
    }

    fn total_bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn total_bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cloned teardown handle shares one flag, and `disconnect` does
    /// both halves.
    ///
    /// This is the foundation every disconnect site rests on: the flag
    /// is raised from a handle other than the one the reader holds,
    /// which is the geometry of all six of them.
    ///
    /// What it cannot pin: that a raised flag actually returns a
    /// blocked `recv` under Winsock. That is the platform behaviour
    /// this whole mechanism exists for and it is unobservable here.
    #[test]
    fn a_cloned_teardown_shares_one_flag_and_disconnect_does_both_halves() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        let conn = Teardown::new(server);
        let flag = conn.cancel();
        let _first = conn.try_clone().expect("clone");
        let second = conn.try_clone().expect("clone");

        assert!(!flag.is_cancelled(), "the flag starts down");
        second.disconnect();
        assert!(
            flag.is_cancelled(),
            "a clone must share the original's flag, not mint its own"
        );

        let mut buf = [0u8; 1];
        assert_eq!(
            (&client).read(&mut buf).expect("read"),
            0,
            "the FIN must still go out: disconnect is not flag-only"
        );
    }

    /// Two independently minted handles over one socket do NOT share a
    /// flag -- the pre-fix shape, and the regression this guards.
    #[test]
    fn separately_minted_teardowns_do_not_share_a_flag() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let _client = std::net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        let one = Teardown::new(server.try_clone().expect("clone"));
        let two = Teardown::new(server);
        let flag = one.cancel();

        two.disconnect();
        assert!(
            !flag.is_cancelled(),
            "a separately minted handle raises a flag nobody reads -- \
             the bug this type exists to make unrepresentable"
        );
    }
    use std::io::Cursor;

    use dcroxide_peer::MAX_PROTOCOL_VERSION;
    use dcroxide_wire::{MAX_MESSAGE_PAYLOAD, MsgPing};

    // Any consistent network magic works for a round trip; the mainnet
    // value keeps the framed bytes recognizable.
    const NET: CurrencyNet = CurrencyNet(0xd9b4_00f9);

    /// The byte offset of the little-endian payload length field within
    /// a message header (after the 4-byte magic and 12-byte command).
    const PAYLOAD_LEN_OFFSET: usize = 16;

    /// Build a bare 24-byte header for `command` declaring `payload_len`
    /// bytes of payload that will never arrive.
    fn lone_header(command: &[u8], payload_len: u32) -> Vec<u8> {
        let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&NET.0.to_le_bytes());
        header[4..4usize.saturating_add(command.len())].copy_from_slice(command);
        header[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
            .copy_from_slice(&payload_len.to_le_bytes());
        header
    }

    /// A payload that runs out mid-decode is an I/O failure, not a
    /// bannable wire violation.
    ///
    /// dcrd's `wire/message.go` returns `BtcDecode`'s error raw, so a
    /// short body surfaces as Go's `io.ErrUnexpectedEOF`,
    /// `errors.As(err, &errCode)` finds no `wire.ErrorCode`, and
    /// `serverPeer.OnRead` drops the peer without banning it.  The
    /// framing here is entirely well-formed -- correct magic, known
    /// command, honest length, matching checksum -- so the only thing
    /// that can fail is the decoder running out of bytes, which is
    /// exactly the case a from-scratch decoder is most likely to
    /// disagree with dcrd about.  Banning on it would cost an honest
    /// peer 24 hours, and the handshake reads are unauthenticated.
    #[test]
    fn a_payload_that_ends_mid_decode_is_io_not_a_wire_violation() {
        // A `ping` is an 8-byte nonce; hand the decoder 4 of them.
        let framed = dcroxide_wire::write_message(
            &dcroxide_wire::Message::Ping(MsgPing {
                nonce: 0x0123_4567_89ab_cdef,
            }),
            MAX_PROTOCOL_VERSION,
            NET,
        )
        .expect("frame a ping");
        let short_payload = &framed[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 4];

        let mut frame = framed[..MESSAGE_HEADER_SIZE].to_vec();
        frame[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
            .copy_from_slice(&(short_payload.len() as u32).to_le_bytes());
        let checksum = dcroxide_chainhash::hash_b(short_payload);
        frame[PAYLOAD_LEN_OFFSET + 4..MESSAGE_HEADER_SIZE].copy_from_slice(&checksum[..4]);
        frame.extend_from_slice(short_payload);

        let mut transport = WireTransport::new(Cursor::new(frame), MAX_PROTOCOL_VERSION, NET);
        let err = transport
            .read_message()
            .expect_err("a short ping payload cannot decode");
        assert!(
            !err.wire_violation,
            "a short body must not ban; dcrd surfaces it untyped: {err}",
        );
    }

    /// The write deadline follows dcrd's formula exactly: a twenty-second
    /// base plus one whole second per 256 KiB of the *framed* message
    /// (`peer/peer.go:1013-1016`, constants at `:84` and `:90`).
    ///
    /// The rows are computed from the constants rather than captured from
    /// dcrd, because the arithmetic is the whole content of the change —
    /// the boundary pair is what distinguishes a truncating division from
    /// a rounding one, and the header term is what distinguishes the
    /// framed size from the payload size.
    #[test]
    fn the_write_deadline_matches_dcrds_formula() {
        let p = WriteStallPolicy::dcrd();
        assert_eq!(p.base, Duration::from_secs(20), "dcrd writeStallTimeout");
        assert_eq!(p.bytes_per_sec, 256 * 1024, "dcrd writeStallBytesPerSec");

        let secs = |n: usize| p.deadline_for(n).as_secs();
        // An empty framed message is the header alone.
        assert_eq!(secs(MESSAGE_HEADER_SIZE), 20, "header only");
        // The truncating boundary: one byte short buys nothing.
        assert_eq!(secs(262_143), 20, "one byte below 256 KiB");
        assert_eq!(secs(262_144), 21, "exactly 256 KiB");
        assert_eq!(secs(524_287), 21, "one byte below 512 KiB");
        assert_eq!(secs(524_288), 22, "exactly 512 KiB");
        // The largest possible message gets roughly two extra minutes,
        // which is the allowance dcrd's comment describes.
        assert_eq!(secs(32 * 1024 * 1024), 148, "32 MiB");
        // A misconfigured zero divisor yields no allowance, not a panic.
        let degenerate = WriteStallPolicy {
            base: Duration::from_secs(20),
            bytes_per_sec: 0,
        };
        assert_eq!(degenerate.deadline_for(1 << 20).as_secs(), 20);
    }

    /// The size fed to the deadline is the framed message — header plus
    /// payload — which is what makes it equal dcrd's
    /// `wire.MessageHeaderSize + msg.SerializeSize()`.
    #[test]
    fn the_deadline_input_is_the_framed_length() {
        for msg in [
            Message::Ping(MsgPing { nonce: 1 }),
            Message::VerAck,
            Message::GetAddr,
        ] {
            let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");
            let payload = framed.len().saturating_sub(MESSAGE_HEADER_SIZE);
            assert_eq!(
                framed.len(),
                MESSAGE_HEADER_SIZE.saturating_add(payload),
                "the framed length is the header plus the encoded payload"
            );
        }
    }

    #[test]
    fn writes_framed_bytes_matching_the_wire_codec() {
        let mut transport = WireTransport::new(Cursor::new(Vec::new()), MAX_PROTOCOL_VERSION, NET);
        let msg = Message::Ping(MsgPing { nonce: 0x0102_0304 });
        transport.write_message(&msg).expect("write ping");

        let expected = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame ping");
        assert_eq!(transport.bytes_written(), expected.len() as u64);
        // Header (24) + 8-byte ping nonce.
        assert_eq!(expected.len(), MESSAGE_HEADER_SIZE + 8);
        assert_eq!(transport.into_inner().into_inner(), expected);
    }

    #[test]
    fn round_trips_a_message_through_the_stream() {
        let msg = Message::Ping(MsgPing {
            nonce: 0xdead_beef_cafe_f00d,
        });
        let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");

        let mut transport =
            WireTransport::new(Cursor::new(framed.clone()), MAX_PROTOCOL_VERSION, NET);
        let got = transport.read_message().expect("read back the message");
        assert_eq!(got, msg);
        assert_eq!(transport.bytes_read(), framed.len() as u64);
    }

    #[test]
    fn round_trips_an_empty_payload_message() {
        let msg = Message::VerAck;
        let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");
        let mut transport = WireTransport::new(Cursor::new(framed), MAX_PROTOCOL_VERSION, NET);
        assert_eq!(
            transport.read_message().expect("read verack"),
            Message::VerAck
        );
    }

    #[test]
    fn rejects_a_header_declaring_an_oversized_payload_without_reading_it() {
        // A header whose length field exceeds the global cap; no payload
        // follows, proving the transport rejects it from the header
        // alone rather than trying to read the declared bytes.
        let header = lone_header(b"ping", (MAX_MESSAGE_PAYLOAD + 1) as u32);
        let mut transport = WireTransport::new(Cursor::new(header), MAX_PROTOCOL_VERSION, NET);
        let err = transport
            .read_message()
            .expect_err("oversized payload rejected");
        assert!(
            err.message.to_lowercase().contains("payload"),
            "error: {err}"
        );
    }

    /// A length under the global 32 MiB cap but over the command's own
    /// maximum must be rejected from the header, before anything is
    /// reserved for the payload.  Bounding the reservation by the global
    /// cap alone lets a peer name 32 MiB in 24 bytes and never send it,
    /// parking that memory for the whole read budget on every
    /// connection; dcrd checks `msg.MaxPayloadLength(pver)` before
    /// `make([]byte, hdr.length)` for exactly this reason.
    ///
    /// The check is observable in the error class: rejecting from the
    /// header is a wire-protocol violation (which bans), while reading
    /// first and hitting the closed stream would surface as plain I/O.
    #[test]
    fn rejects_a_length_over_the_per_command_maximum_before_reserving() {
        // `ping` carries an 8-byte nonce and nothing else.
        // Under the global cap, so the per-command bound is what must
        // reject it; a `ping` carries an 8-byte nonce and nothing else.
        const UNDER_GLOBAL_CAP: u32 = 8 * 1024 * 1024;
        const _: () = assert!((UNDER_GLOBAL_CAP as u64) < MAX_MESSAGE_PAYLOAD);
        let header = lone_header(b"ping", UNDER_GLOBAL_CAP);

        let mut transport = WireTransport::new(Cursor::new(header), MAX_PROTOCOL_VERSION, NET);
        let err = transport
            .read_message()
            .expect_err("over-long ping rejected");
        // The stream holds only the 24 header bytes.  Reading the
        // payload first would hit end-of-stream and surface as I/O;
        // only a pre-read header check can classify this as a wire
        // violation.  The magic is correct and `ping` is a known
        // command, so the per-command maximum is the check that
        // rejected it — the global cap sits far above 8 MiB.
        assert!(
            err.wire_violation,
            "must be a bannable wire violation, not an I/O error: {err}"
        );
        assert_eq!(err.message, "ErrPayloadTooLarge", "error: {err}");
    }

    /// The declared length of a well-formed message is still honoured:
    /// the header check must bound the reservation, not replace the
    /// payload read.
    #[test]
    fn accepts_a_length_at_the_per_command_maximum() {
        let msg = Message::Ping(MsgPing { nonce: 42 });
        let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");
        assert_eq!(framed.len(), MESSAGE_HEADER_SIZE + 8);
        let mut transport = WireTransport::new(Cursor::new(framed), MAX_PROTOCOL_VERSION, NET);
        assert_eq!(transport.read_message().expect("read ping"), msg);
    }

    /// The write budget must bound the whole message, not each
    /// `send(2)`.
    ///
    /// This is the case a single `SO_SNDTIMEO` around `write_all` cannot
    /// catch: the kernel restarts that timer whenever a send makes
    /// progress, and `write_all` loops on partial writes, so a peer that
    /// reopens its receive window by a trickle just inside the budget
    /// keeps the writer parked for arbitrarily long. A peer that stops
    /// reading *entirely* would trip either implementation, which is why
    /// the reader here drains slowly rather than not at all.
    ///
    /// With the deadline charged across the whole write, this fails at
    /// roughly the budget. With the budget re-armed per send it takes
    /// (bytes / chunk) * interval — minutes for these numbers — so the
    /// elapsed-time bound is what makes this a real negative.
    #[cfg(unix)]
    #[test]
    fn the_write_budget_bounds_the_whole_message_not_each_send() {
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        const BUDGET: Duration = Duration::from_millis(300);
        // More than any loopback socket-buffer pair, so the write cannot
        // finish without the reader's cooperation.
        const PAYLOAD: usize = 8 * 1024 * 1024;
        // Drained continuously and promptly, so every `send(2)` makes
        // progress well inside the budget and the per-send form never
        // simply blocks — it just grinds. At this rate the whole payload
        // takes roughly 20s, so the elapsed bound below separates the
        // two implementations by an order of magnitude.
        const DRAIN_CHUNK: usize = 8 * 1024;
        const DRAIN_EVERY: Duration = Duration::from_millis(20);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        // The drip-feeding peer.
        let reader_stop = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            ready_tx.send(()).expect("signal ready");
            let mut buf = vec![0u8; DRAIN_CHUNK];
            while !reader_stop.load(Ordering::SeqCst) {
                if sock.read(&mut buf).unwrap_or(0) == 0 {
                    break;
                }
                std::thread::sleep(DRAIN_EVERY);
            }
        });

        let sock = TcpStream::connect(addr).expect("connect");
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("reader accepted");

        let mut transport = WireTransport::new(sock, MAX_PROTOCOL_VERSION, NET);
        transport.set_write_stall_policy(Some(WriteStallPolicy {
            base: BUDGET,
            // Large enough that this message's allowance is zero, so the
            // test measures the base bound alone.
            bytes_per_sec: usize::MAX,
        }));

        let started = Instant::now();
        let result = write_all_by_deadline(
            transport.get_mut(),
            &vec![0xa5u8; PAYLOAD],
            Some(started.checked_add(BUDGET).expect("deadline")),
            &mut 0,
        );
        let elapsed = started.elapsed();

        stop.store(true, Ordering::SeqCst);
        drop(transport);
        let _ = reader.join();

        assert!(
            result.is_err(),
            "a drip-fed peer must not be written to forever"
        );
        // The load-bearing assertion: the budget covered the whole
        // message rather than each send. Measured on this fixture, the
        // absolute deadline finishes in ~309ms (1.03x the budget) while
        // arming SO_SNDTIMEO once around `write_all` takes ~1.83s
        // (6.1x), so a 3x bound separates them with roughly 3x margin
        // below and 2x above.
        assert!(
            elapsed < BUDGET.saturating_mul(3),
            "the budget must cover the whole message, not each send: took \
             {elapsed:?} for a {BUDGET:?} budget"
        );
    }

    /// With no budget the write is unbounded, exactly as before, so the
    /// deadline is opt-in and the handshake path is unaffected.
    #[test]
    fn no_write_budget_leaves_the_write_unbounded() {
        let mut sink = Cursor::new(Vec::new());
        write_all_by_deadline(&mut sink, b"hello", None, &mut 0).expect("unbounded write");
        assert_eq!(sink.into_inner(), b"hello");
    }

    /// The bytes a failed read took off the wire still count, for the
    /// peer and server-wide.  dcrd's `readMessage` adds
    /// `ReadMessageN`'s `n` to `bytesReceived`, and `serverPeer.OnRead`
    /// adds it to the getnettotals total, before either looks at the
    /// error; `ReadMessageN` returns what it read on every path.
    #[test]
    fn a_failed_read_counts_the_bytes_it_consumed() {
        let msg = Message::Ping(MsgPing { nonce: 7 });
        let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");

        // A whole message with a bad checksum: read in full, then refused.
        let mut bad_checksum = framed.clone();
        bad_checksum[PAYLOAD_LEN_OFFSET + 4] ^= 0xff;
        // Another network's magic: refused from the header alone, so the
        // payload behind it is never read.
        let mut wrong_net = framed.clone();
        wrong_net[0] ^= 0xff;
        // A stream that ends three bytes into the payload.
        let truncated = framed[..MESSAGE_HEADER_SIZE + 3].to_vec();
        let cases = [
            (bad_checksum, framed.len()),
            (wrong_net, MESSAGE_HEADER_SIZE),
            (truncated, MESSAGE_HEADER_SIZE + 3),
        ];

        // Both the budgeted read the peer loop uses and the unbudgeted one.
        for budget in [None, Some(Duration::from_secs(5))] {
            for (stream, want) in cases.clone() {
                let totals = std::sync::Arc::new(NetByteTotals::new());
                let mut transport =
                    WireTransport::new(Cursor::new(stream), MAX_PROTOCOL_VERSION, NET);
                transport.set_net_totals(std::sync::Arc::clone(&totals));
                transport.set_read_budget(budget);
                transport.read_message().expect_err("the read fails");
                assert_eq!(transport.bytes_read(), want as u64, "{budget:?}");
                assert_eq!(
                    totals
                        .bytes_received
                        .load(std::sync::atomic::Ordering::Relaxed),
                    want as u64,
                    "{budget:?}"
                );
            }
        }
    }

    /// A stream that records each socket timeout armed on it and the
    /// timeout in force at each receive and send, handing out its input
    /// a few bytes per receive so one message takes several.
    struct TimeoutProbe {
        input: Cursor<Vec<u8>>,
        chunk: usize,
        read_timeout: std::cell::Cell<Option<Duration>>,
        write_timeout: std::cell::Cell<Option<Duration>>,
        read_arms: std::cell::Cell<usize>,
        write_arms: std::cell::Cell<usize>,
        reads_under: Vec<Option<Duration>>,
        writes_under: Vec<Option<Duration>>,
    }

    impl TimeoutProbe {
        fn new(input: Vec<u8>, chunk: usize) -> TimeoutProbe {
            TimeoutProbe {
                input: Cursor::new(input),
                chunk,
                read_timeout: std::cell::Cell::new(None),
                write_timeout: std::cell::Cell::new(None),
                read_arms: std::cell::Cell::new(0),
                write_arms: std::cell::Cell::new(0),
                reads_under: Vec::new(),
                writes_under: Vec::new(),
            }
        }
    }

    impl Read for TimeoutProbe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads_under.push(self.read_timeout.get());
            let n = buf.len().min(self.chunk);
            self.input.read(&mut buf[..n])
        }
    }

    impl Write for TimeoutProbe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes_under.push(self.write_timeout.get());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SocketTimeout for TimeoutProbe {
        fn set_socket_read_timeout(&self, timeout: Option<Duration>) {
            self.read_arms.set(self.read_arms.get().saturating_add(1));
            self.read_timeout.set(timeout);
        }

        fn set_socket_write_timeout(&self, timeout: Option<Duration>) {
            self.write_arms.set(self.write_arms.get().saturating_add(1));
            self.write_timeout.set(timeout);
        }
    }

    /// Every budgeted receive runs under the remaining budget,
    /// capped at [`READ_POLL_INTERVAL`], but the timeout is armed only
    /// when that slice changes rather than before every receive: the
    /// slice is the same second for every receive outside a budget's
    /// final second, and each arming is a `setsockopt`.  A slice clamped
    /// in one budget's final second is raised again for the next.
    #[test]
    fn a_budgeted_read_arms_the_receive_timeout_only_when_it_changes() {
        let msg = Message::Ping(MsgPing { nonce: 9 });
        let framed = wire_write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame");
        let input: Vec<u8> = std::iter::repeat_n(framed.as_slice(), 5)
            .flatten()
            .copied()
            .collect();
        // Five bytes a receive: seven receives for each 32-byte ping.
        let mut transport =
            WireTransport::new(TimeoutProbe::new(input, 5), MAX_PROTOCOL_VERSION, NET);

        // A budget far longer than the test: every slice is the poll
        // interval, armed once for all three messages.
        transport.set_read_budget(Some(Duration::from_secs(600)));
        for _ in 0..3 {
            assert_eq!(transport.read_message().expect("read"), msg);
        }
        let probe = transport.get_ref();
        assert_eq!(probe.reads_under.len(), 21, "seven receives a message");
        assert!(
            probe
                .reads_under
                .iter()
                .all(|t| *t == Some(READ_POLL_INTERVAL)),
            "{:?}",
            probe.reads_under
        );
        assert_eq!(probe.read_arms.get(), 1, "armed once, not per receive");

        // Inside its final second a budget clamps the slice, which is
        // then re-armed at every receive as the clock runs down.
        let short = Duration::from_millis(500);
        transport.set_read_budget(Some(short));
        assert_eq!(transport.read_message().expect("read"), msg);
        let clamped = &transport.get_ref().reads_under[21..];
        assert_eq!(clamped.len(), 7);
        assert!(
            clamped
                .iter()
                .all(|t| t.is_some_and(|t| !t.is_zero() && t <= short)),
            "{clamped:?}"
        );

        // The next long budget raises the slice back to the interval.
        transport.set_read_budget(Some(Duration::from_secs(600)));
        assert_eq!(transport.read_message().expect("read"), msg);
        let raised = &transport.get_ref().reads_under[28..];
        assert!(
            raised.iter().all(|t| *t == Some(READ_POLL_INTERVAL)),
            "{raised:?}"
        );
    }

    /// Every bounded write still sends under an armed timeout and every
    /// unbounded one under none, but a bounded write no longer clears
    /// the timeout after itself: it arms once for its send and once for
    /// its flush, where it used to spend a third `setsockopt` resetting
    /// the timeout that the next write re-arms anyway.
    #[test]
    fn a_bounded_write_leaves_its_send_timeout_armed() {
        let msg = Message::Ping(MsgPing { nonce: 9 });
        let mut transport =
            WireTransport::new(TimeoutProbe::new(Vec::new(), 0), MAX_PROTOCOL_VERSION, NET);

        transport.set_write_stall_policy(Some(WriteStallPolicy::dcrd()));
        for _ in 0..3 {
            transport.write_message(&msg).expect("write");
        }
        let probe = transport.get_ref();
        let base = WriteStallPolicy::dcrd().base;
        assert_eq!(probe.writes_under.len(), 3);
        assert!(
            probe
                .writes_under
                .iter()
                .all(|t| t.is_some_and(|t| !t.is_zero() && t <= base)),
            "{:?}",
            probe.writes_under
        );
        assert_eq!(probe.write_arms.get(), 6, "a send and a flush each");

        // Unbounded writes run with no timeout: the first clears what
        // the bounded ones left armed, and the rest find it cleared.
        transport.set_write_stall_policy(None);
        for _ in 0..2 {
            transport.write_message(&msg).expect("write");
        }
        let probe = transport.get_ref();
        assert_eq!(&probe.writes_under[3..], &[None, None]);
        assert_eq!(probe.write_arms.get(), 7, "cleared once");
    }

    /// The bytes a failed write put on the wire still count (dcrd's
    /// `writeMessage` adds `WriteMessageN`'s partial `n` to `bytesSent`,
    /// and `serverPeer.OnWrite` to the server's total, whatever the
    /// error).
    #[test]
    fn a_failed_write_counts_the_bytes_it_sent() {
        let msg = Message::Ping(MsgPing { nonce: 7 });
        for policy in [None, Some(WriteStallPolicy::dcrd())] {
            // Room for ten of the message's thirty-two bytes.
            let mut room = [0u8; 10];
            let totals = std::sync::Arc::new(NetByteTotals::new());
            let mut transport =
                WireTransport::new(Cursor::new(&mut room[..]), MAX_PROTOCOL_VERSION, NET);
            transport.set_net_totals(std::sync::Arc::clone(&totals));
            transport.set_write_stall_policy(policy);
            transport
                .write_message(&msg)
                .expect_err("the stream fills after ten bytes");
            assert_eq!(transport.bytes_written(), 10, "{policy:?}");
            assert_eq!(
                totals.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
                10,
                "{policy:?}"
            );
        }
    }

    /// A read must give up when the connection's [`Cancel`] flag goes up,
    /// without waiting out its budget.
    ///
    /// This is the property Windows CI failed on: the stall detector
    /// logged a peer as disconnected and shut the socket down through a
    /// cloned handle, but the input loop stayed parked in its receive, so
    /// `run_peer_connection_with_stall` — which drives that loop on the
    /// caller's own thread — could not return its reason until the idle
    /// budget expired.  Go's `Conn.Close` makes a blocked `Read` return
    /// on every platform and dcrd relies on exactly that; the port has to
    /// poll instead.
    ///
    /// The socket is deliberately left alone here: this holds a peer that
    /// simply never speaks, so the ONLY thing that can end the read is
    /// the flag.  Reverting to a single receive armed with the whole
    /// remaining budget makes this wait the full budget and fail.
    #[test]
    fn a_cancelled_read_returns_without_waiting_out_its_budget() {
        // A budget far longer than the test may take, so finishing early
        // can only be the flag's doing.
        const BUDGET: Duration = Duration::from_secs(600);

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");

        // A remote that connects and then says nothing at all.  It holds
        // the socket open until told to let go, with a long backstop:
        // without that, its close would hand the reader an EOF and the
        // read would end for a reason that has nothing to do with the
        // flag — which would make this test pass against the very bug it
        // exists to catch.
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let mute = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let _ = stop_rx.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });

        let stream = std::net::TcpStream::connect(addr).expect("connect");
        let mut transport = WireTransport::new(stream, 0, CurrencyNet::TEST_NET3);
        transport.set_read_budget(Some(BUDGET));
        let cancel = Cancel::new();
        transport.set_cancel(cancel.clone());

        // Raise the flag once the read is certainly parked in a receive.
        let raiser = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                std::thread::sleep(READ_POLL_INTERVAL / 4);
                cancel.cancel();
            })
        };

        let started = Instant::now();
        let err = MsgTransport::read_message(&mut transport)
            .expect_err("a cancelled read must not return a message");
        let waited = started.elapsed();

        raiser.join().expect("raiser");
        let _ = stop_tx.send(());
        let _ = mute.join();

        // One poll interval to notice, plus slack for a loaded machine —
        // and far, far short of the budget.
        let bound = READ_POLL_INTERVAL * 4;
        assert!(
            waited < bound,
            "the read waited {waited:?} for a cancellation it should have seen within \
             {READ_POLL_INTERVAL:?} (bound {bound:?}, budget {BUDGET:?}): the receive is \
             not being sliced, so teardown waits out the whole idle budget"
        );
        assert!(
            err.message.contains("torn down locally"),
            "the failure must name the local teardown, got: {}",
            err.message
        );
    }

    /// A poll slice elapsing is not a failure: only the whole-message
    /// budget may end a read.
    ///
    /// Slicing the receive introduced a new way to get a `WouldBlock` or
    /// `TimedOut` back from the stream that has nothing to do with the
    /// budget being spent.  Treating those as fatal — which the
    /// pre-slicing loop did, correctly, because its timeout WAS the
    /// budget — would disconnect any peer that went quiet for a second
    /// mid-message, which an honest peer on a slow link does routinely.
    #[test]
    fn a_quiet_peer_survives_longer_than_one_poll_slice() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");

        // A remote that sends a ping only after several poll intervals
        // have gone by with nothing on the wire.
        let sender = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut out = WireTransport::new(stream, 0, CurrencyNet::TEST_NET3);
            std::thread::sleep(READ_POLL_INTERVAL * 2 + READ_POLL_INTERVAL / 2);
            MsgTransport::write_message(
                &mut out,
                &Message::Ping(dcroxide_wire::MsgPing { nonce: 42 }),
            )
            .expect("write ping");
            // Hold the socket open until the reader has taken it.
            std::thread::sleep(Duration::from_millis(200));
        });

        let stream = std::net::TcpStream::connect(addr).expect("connect");
        let mut transport = WireTransport::new(stream, 0, CurrencyNet::TEST_NET3);
        // A budget comfortably longer than the silence, so the silence is
        // the only thing under test.
        transport.set_read_budget(Some(READ_POLL_INTERVAL * 20));
        transport.set_cancel(Cancel::new());

        let msg = MsgTransport::read_message(&mut transport)
            .expect("silence longer than a poll slice must not fail the read");
        assert!(
            matches!(&msg, Message::Ping(p) if p.nonce == 42),
            "got {msg:?}"
        );
        sender.join().expect("sender");
    }
}
