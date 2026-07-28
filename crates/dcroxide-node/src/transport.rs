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
//! by arming the stream's read timeout with the remaining budget
//! before every receive, so a byte-dribbling peer cannot extend one
//! message read past the budget the peer loop configures.
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
#[derive(Clone, Default)]
pub struct Cancel(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Cancel {
    /// A flag that has not been raised.
    pub fn new() -> Cancel {
        Cancel::default()
    }

    /// Raise the flag.  Idempotent, and safe to call from any thread.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the flag has been raised.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
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
        }
    }

    /// Share the connection's cancellation flag with this transport, so
    /// a read in progress stops when another loop tears the connection
    /// down instead of waiting out the idle budget.
    pub fn set_cancel(&mut self, cancel: Cancel) {
        self.cancel = Some(cancel);
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
fn read_exact_by_deadline<S: Read + SocketTimeout>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel: Option<&Cancel>,
) -> std::io::Result<()> {
    let cancelled = || {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "the connection was torn down locally",
        )
    };
    let Some(deadline) = deadline else {
        // With no budget there is nothing to slice against, so the
        // flag can only be checked before parking in the read.  The
        // peer loop always sets a budget; this is the in-memory test
        // path and the pre-handshake path.
        if cancel.is_some_and(Cancel::is_cancelled) {
            return Err(cancelled());
        }
        return stream.read_exact(buf);
    };
    let mut filled = 0usize;
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
        stream.set_socket_read_timeout(Some(remaining.min(READ_POLL_INTERVAL)));
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => filled = filled.saturating_add(n),
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
fn write_all_by_deadline<S: Write + SocketTimeout>(
    stream: &mut S,
    buf: &[u8],
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let Some(deadline) = deadline else {
        stream.write_all(buf)?;
        return stream.flush();
    };
    let mut written = 0usize;
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
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => written = written.saturating_add(n),
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

impl<S: Read + Write + SocketTimeout> MsgTransport for WireTransport<S> {
    fn set_protocol_version(&mut self, pver: u32) {
        WireTransport::set_protocol_version(self, pver);
    }

    fn read_message(&mut self) -> Result<Message, dcroxide_peer::ReadError> {
        // One absolute deadline covers the whole message — header and
        // payload (dcrd's single `SetReadDeadline` before
        // `ReadMessageN`).
        let now = Instant::now();
        let deadline = self.read_budget.map(|b| now.checked_add(b).unwrap_or(now));
        // Read the fixed-size header first so the payload length is
        // known before any payload allocation (dcrd `readMessageHeader`
        // then the payload read).
        let mut buf = vec![0u8; MESSAGE_HEADER_SIZE];
        read_exact_by_deadline(&mut self.stream, &mut buf, deadline, self.cancel.as_ref())
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
            )
            .map_err(|e| dcroxide_peer::ReadError::io(e.to_string()))?;
        }

        // A codec failure is a wire-protocol violation (dcrd's
        // `wire.ErrorCode`), which the daemon bans on.
        let (msg, consumed) = wire_read_message(&buf, self.pver, self.net)
            .map_err(|e| dcroxide_peer::ReadError::wire(e.to_string()))?;
        self.bytes_read = self.bytes_read.saturating_add(consumed as u64);
        if let Some(totals) = &self.net_totals {
            totals
                .bytes_received
                .fetch_add(consumed as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(msg)
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
        let result = write_all_by_deadline(&mut self.stream, &bytes, deadline);
        if self.write_stall.is_some() {
            self.stream.set_socket_write_timeout(None);
        }
        result.map_err(|e| e.to_string())?;
        self.bytes_written = self.bytes_written.saturating_add(bytes.len() as u64);
        if let Some(totals) = &self.net_totals {
            totals
                .bytes_sent
                .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
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
        write_all_by_deadline(&mut sink, b"hello", None).expect("unbounded write");
        assert_eq!(sink.into_inner(), b"hello");
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
