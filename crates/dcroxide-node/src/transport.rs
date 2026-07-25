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

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use crate::socktimeout::SocketTimeout;

use dcroxide_peer::MsgTransport;
use dcroxide_wire::{
    CurrencyNet, MESSAGE_HEADER_SIZE, Message, read_message as wire_read_message,
    read_message_header as wire_read_message_header, write_message as wire_write_message,
};

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
    /// The budget each whole message write must complete within.  A
    /// peer that stops reading otherwise parks this thread forever
    /// while its outbound queue is held; dcrd never blocks
    /// indefinitely on a send because `outHandler` drains an
    /// unbuffered channel behind a bounded send semaphore.
    write_budget: Option<Duration>,
    /// The server-wide totals this transport contributes to, when the
    /// daemon's accounting is wired (dcrd's `OnRead`/`OnWrite`
    /// listeners adding into the server's atomic counters).
    net_totals: Option<std::sync::Arc<NetByteTotals>>,
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
            write_budget: None,
            net_totals: None,
        }
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

    /// Set the budget each whole message write must complete within.
    pub fn set_write_budget(&mut self, budget: Option<Duration>) {
        self.write_budget = budget;
    }
}

/// Fill the buffer under an absolute deadline, re-arming the stream's
/// read timeout with the remaining budget before every receive; with
/// no deadline the reads run under the stream's own settings.
fn read_exact_by_deadline<S: Read + SocketTimeout>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let Some(deadline) = deadline else {
        return stream.read_exact(buf);
    };
    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timed out",
            ));
        }
        stream.set_socket_read_timeout(Some(remaining));
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => filled = filled.saturating_add(n),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
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
        read_exact_by_deadline(&mut self.stream, &mut buf, deadline)
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
            read_exact_by_deadline(&mut self.stream, &mut buf[MESSAGE_HEADER_SIZE..], deadline)
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
        let now = Instant::now();
        let deadline = self.write_budget.map(|b| now.checked_add(b).unwrap_or(now));
        let result = write_all_by_deadline(&mut self.stream, &bytes, deadline);
        if self.write_budget.is_some() {
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
        transport.set_write_budget(Some(BUDGET));

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
}
