// SPDX-License-Identifier: ISC
//! The RFC 6455 WebSocket server frame transport for the RPC endpoint
//! (the wire layer dcrd gets from gorilla/websocket).
//!
//! A [`WsConn`] wraps a byte stream and exposes the two operations the
//! JSON-RPC-over-websocket loop needs: read the next complete text
//! message (reassembling fragments, answering pings, honoring the
//! cumulative read limit) and write a reply as a single unmasked text
//! frame.  Client frames must be masked and use zero reserved bits, and
//! protocol violations are answered with a close frame before the
//! connection ends, exactly as gorilla enforces for dcrd's clients.

use std::io::{Read, Write};

use dcroxide_rpc::http::base64_std_encode;
use sha1::{Digest, Sha1};

/// The GUID appended to the client key before hashing to form the
/// accept key (RFC 6455 section 1.3).
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`
/// (RFC 6455: base64 of the SHA-1 of the key concatenated with the
/// GUID).
pub fn accept_key(sec_websocket_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(sec_websocket_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64_std_encode(&hasher.finalize())
}

/// A close status code (RFC 6455 section 7.4.1).
mod close_code {
    /// A protocol error terminated the connection.
    pub const PROTOCOL_ERROR: u16 = 1002;
    /// A message exceeded the read limit.
    pub const TOO_BIG: u16 = 1009;
}

/// Whether gorilla accepts a close code received from the peer
/// (`isValidReceivedCloseCode`, `gorilla/websocket@v1.5.1
/// conn.go:211-232`): the registered codes a peer may send and the
/// private range.  1004, 1005, 1006, 1014 and 1015 are refused, the
/// three RFC 6455 reserves for local use among them.
fn valid_received_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1013 | 3000..=4999)
}

/// The error for a read gorilla fails with `ErrReadLimit` and no close
/// frame: a declared length that is negative as its `int64`, or one
/// that overflows the message's running total (`setReadRemaining`,
/// `conn.go:335-338`, and `:935-939`).
const SILENT_READ_LIMIT: &str = "websocket: read limit exceeded";

/// A complete message read from the client.
pub enum WsIn {
    /// A text (or binary — dcrd treats them identically) message.
    Text(Vec<u8>),
    /// The client sent a close frame or the connection ended.
    Close,
    /// No frame arrived within the stream's read timeout.  The serving
    /// loop uses this to interleave notification writes with reads on
    /// one thread — the poll-loop translation of dcrd's separate in
    /// and out handler goroutines.
    Idle,
}

/// One attempt to read a frame.
enum FrameRead {
    /// A decoded frame.
    Frame(Frame),
    /// The connection ended cleanly at a frame boundary.
    Eof,
    /// The read timed out before any frame byte arrived.
    Idle,
}

/// Whether an I/O error is a read-timeout expiry (`WouldBlock` on
/// Unix sockets, `TimedOut` on Windows).
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// A WebSocket connection over a byte stream, after the handshake.
pub struct WsConn<S> {
    stream: S,
    /// Set once a close frame has gone out, after which every write
    /// fails: gorilla's `writeFatal(ErrCloseSent)` (`conn.go:410-412`,
    /// `:482-484`), which is what keeps dcrd's writer from putting a
    /// data frame on the wire after the close frame its reader sent.
    close_sent: bool,
}

impl<S: Read + Write> WsConn<S> {
    /// Wrap a stream whose handshake has completed.
    pub fn new(stream: S) -> WsConn<S> {
        WsConn {
            stream,
            close_sent: false,
        }
    }

    /// Read the next complete client message, reassembling fragments,
    /// answering pings with pongs, ignoring pongs, and enforcing
    /// `read_limit` cumulatively across a message's fragments (dcrd's
    /// authenticated/unauthenticated websocket read limits).  A
    /// protocol violation or an oversized message is answered with the
    /// matching close frame and returns an error.
    pub fn read_message(&mut self, read_limit: usize) -> Result<WsIn, String> {
        // The reassembled payload, and whether a data frame without FIN
        // has left it open: the inverse of gorilla's `readFinal`.
        let mut message: Vec<u8> = Vec::new();
        let mut in_message = false;

        loop {
            let frame = match self.read_frame(read_limit, in_message, message.len())? {
                FrameRead::Frame(frame) => frame,
                // A clean EOF between messages is a normal disconnect.
                FrameRead::Eof => return Ok(WsIn::Close),
                FrameRead::Idle => {
                    // Idleness between a message's fragments keeps
                    // waiting for the rest; between messages it
                    // surfaces so the caller can write pending
                    // notifications.
                    if in_message {
                        continue;
                    }
                    return Ok(WsIn::Idle);
                }
            };

            match frame.opcode {
                // Continuation, text or binary: `read_frame` has already
                // held the frame to the message's sequencing and to the
                // read limit.  dcrd discards the frame type.
                0x0..=0x2 => {
                    message.extend_from_slice(&frame.payload);
                    in_message = !frame.fin;
                    if frame.fin {
                        return Ok(WsIn::Text(message));
                    }
                }
                // Close: gorilla refuses a code the peer may not send and
                // a reason that is not UTF-8 (`conn.go:978-990`), then
                // its default handler echoes the code alone -- or an
                // empty payload for a close that carried none, since
                // `FormatCloseMessage(CloseNoStatusReceived, "")` is
                // empty (`:1164-1166`, `:1257-1261`).
                0x8 => {
                    let echo = match frame.payload.get(..2) {
                        Some(&[hi, lo]) => {
                            let code = u16::from_be_bytes([hi, lo]);
                            if !valid_received_close_code(code) {
                                return self.fail(
                                    close_code::PROTOCOL_ERROR,
                                    &format!("bad close code {code}"),
                                );
                            }
                            if std::str::from_utf8(&frame.payload[2..]).is_err() {
                                return self.fail(
                                    close_code::PROTOCOL_ERROR,
                                    "invalid utf8 payload in close frame",
                                );
                            }
                            vec![hi, lo]
                        }
                        _ => Vec::new(),
                    };
                    let _ = self.write_control(0x8, &echo);
                    return Ok(WsIn::Close);
                }
                // Ping: answer with a pong echoing the payload.
                0x9 => self.write_control(0xA, &frame.payload)?,
                // Pong: ignored (dcrd never pings, so this only arrives
                // unsolicited).  No other opcode gets past `read_frame`.
                _ => {}
            }
        }
    }

    /// Write a reply as a single unmasked text frame (gorilla's server
    /// fast path; server frames are never masked or fragmented).
    pub fn write_text(&mut self, payload: &[u8]) -> Result<(), String> {
        self.write_frame(0x1, payload)
    }

    /// A decoded frame header and its unmasked payload.  Only the
    /// first header byte may report idleness: once a frame has begun,
    /// the remaining reads absorb timeouts so a frame split across
    /// segments is never lost.
    ///
    /// The checks run in gorilla's order (`advanceFrame`,
    /// `conn.go:810-990`): everything the first two bytes can show is
    /// judged before the length is read, and a data frame is held to the
    /// read limit by its declared length before its payload is read.
    /// `in_message` says whether an earlier data frame left a message
    /// open, and `message_len` how much of it has been read.
    fn read_frame(
        &mut self,
        read_limit: usize,
        in_message: bool,
        message_len: usize,
    ) -> Result<FrameRead, String> {
        let first = loop {
            let mut byte = [0u8; 1];
            match self.stream.read(&mut byte) {
                // A clean EOF right at a frame boundary is a disconnect.
                Ok(0) => return Ok(FrameRead::Eof),
                Ok(_) => break byte[0],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if is_timeout(&e) => return Ok(FrameRead::Idle),
                Err(e) => return Err(e.to_string()),
            }
        };
        let mut second = [0u8; 1];
        self.read_full(&mut second)?;
        let header = [first, second[0]];

        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0F;
        let masked = header[1] & 0x80 != 0;
        let len_code = header[1] & 0x7F;

        // gorilla collects every fault the two bytes show and reports
        // them together, in this order (`conn.go:846-884`).  No
        // extension is negotiated, so each reserved bit is one.
        let mut faults: Vec<String> = Vec::new();
        for (bit, name) in [(0x40, "RSV1 set"), (0x20, "RSV2 set"), (0x10, "RSV3 set")] {
            if header[0] & bit != 0 {
                faults.push(name.to_string());
            }
        }
        match opcode {
            // Control frames must be final and carry at most 125 bytes,
            // judged by the 7-bit length code.
            0x8..=0xA => {
                if len_code > 125 {
                    faults.push("len > 125 for control".to_string());
                }
                if !fin {
                    faults.push("FIN not set on control".to_string());
                }
            }
            0x1 | 0x2 => {
                if in_message {
                    faults.push("data before FIN".to_string());
                }
            }
            0x0 => {
                if !in_message {
                    faults.push("continuation after FIN".to_string());
                }
            }
            other => faults.push(format!("bad opcode {other}")),
        }
        // Every client frame must be masked (RFC 6455 section 5.1).
        if !masked {
            faults.push("bad MASK".to_string());
        }
        if !faults.is_empty() {
            return self
                .fail(close_code::PROTOCOL_ERROR, &faults.join(", "))
                .map(|_| FrameRead::Eof);
        }

        let declared: u64 = match len_code {
            126 => {
                let mut ext = [0u8; 2];
                self.read_full(&mut ext)?;
                u64::from(u16::from_be_bytes(ext))
            }
            127 => {
                let mut ext = [0u8; 8];
                self.read_full(&mut ext)?;
                u64::from_be_bytes(ext)
            }
            other => u64::from(other),
        };
        // Judged as gorilla's `int64` before anything is cast, so a
        // hostile length can neither drive an allocation nor truncate on
        // a 32-bit target.
        let Ok(declared) = i64::try_from(declared) else {
            return Err(SILENT_READ_LIMIT.to_string());
        };

        let mut mask = [0u8; 4];
        self.read_full(&mut mask)?;

        // A data frame is held to the limit by the message's running
        // total of declared lengths, before its payload is read, and an
        // oversized message draws a 1009 close with no reason
        // (`conn.go:928-946`).
        if opcode <= 0x2 {
            let total = i64::try_from(message_len)
                .ok()
                .and_then(|so_far| so_far.checked_add(declared));
            let Some(total) = total else {
                return Err(SILENT_READ_LIMIT.to_string());
            };
            if total > i64::try_from(read_limit).unwrap_or(i64::MAX) {
                return self.fail(close_code::TOO_BIG, "").map(|_| FrameRead::Eof);
            }
        }
        // Within the read limit, or a control frame's 125 bytes, so this
        // fits a `usize` on every target.
        let payload_len = usize::try_from(declared).map_err(|_| SILENT_READ_LIMIT.to_string())?;

        let mut payload = vec![0u8; payload_len];
        self.read_full(&mut payload)?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }

        Ok(FrameRead::Frame(Frame {
            fin,
            opcode,
            payload,
        }))
    }

    /// Fill the buffer completely, retrying across read timeouts and
    /// interrupts; an EOF mid-fill is an error since it can only occur
    /// inside a frame.
    fn read_full(&mut self, mut buf: &mut [u8]) -> Result<(), String> {
        while !buf.is_empty() {
            match self.stream.read(buf) {
                Ok(0) => return Err("connection ended mid-frame".to_string()),
                Ok(n) => {
                    let rest = core::mem::take(&mut buf);
                    buf = &mut rest[n..];
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if is_timeout(&e) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    /// Write a frame with the given opcode and unmasked payload.
    ///
    /// The header and payload leave in a single write, as gorilla's
    /// server fast path copies the payload in behind the header and
    /// hands the socket one buffer (`conn.go:775-785`, `:402-403`).  Two
    /// writes are two TLS records, and on a socket with Nagle's
    /// algorithm on, the payload segment can wait out the peer's delayed
    /// ACK of the header's.
    ///
    /// Nothing is written once a close frame has gone out.
    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        if self.close_sent {
            return Err("websocket: close sent".to_string());
        }
        let len = payload.len();
        let mut frame = Vec::with_capacity(len.saturating_add(10));
        frame.push(0x80 | opcode);
        if len < 126 {
            frame.push(len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        // Whether or not the close goes out, gorilla fails every later
        // write: with `ErrCloseSent` after it, or with the write's own
        // error.
        if opcode == 0x8 {
            self.close_sent = true;
        }
        self.stream.write_all(&frame).map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())
    }

    /// Write a control frame (pong or close).
    fn write_control(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        self.write_frame(opcode, payload)
    }

    /// Send a close frame with the given code and reason, then report
    /// the failure so the connection ends (gorilla's
    /// `handleProtocolError`, `conn.go:1003-1010`, which cuts the
    /// payload to a control frame's 125 bytes).
    fn fail(&mut self, code: u16, reason: &str) -> Result<WsIn, String> {
        let mut body = code.to_be_bytes().to_vec();
        // The reason is truncated to fit a control frame.
        let reason = &reason.as_bytes()[..reason.len().min(123)];
        body.extend_from_slice(reason);
        let _ = self.write_control(0x8, &body);
        Err(format!("websocket protocol error: {code}"))
    }
}

/// A decoded frame.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn accept_key_matches_the_rfc_example() {
        // RFC 6455 section 1.3 worked example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// A stream whose reads follow a script: a byte chunk delivers
    /// data, `Timeout` simulates a read-timeout expiry, and an
    /// exhausted script reads EOF.
    struct Scripted {
        reads: VecDeque<ScriptedRead>,
    }
    enum ScriptedRead {
        Data(Vec<u8>),
        Timeout,
    }
    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.reads.pop_front() {
                Some(ScriptedRead::Data(chunk)) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.reads
                            .push_front(ScriptedRead::Data(chunk[n..].to_vec()));
                    }
                    Ok(n)
                }
                Some(ScriptedRead::Timeout) => Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "timed out",
                )),
                None => Ok(0),
            }
        }
    }
    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A masked text frame carrying the payload.
    fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut frame = vec![0x81, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[i & 3]);
        }
        frame
    }

    #[test]
    fn an_oversized_frame_is_rejected_before_allocating() {
        // A masked text frame whose 127 length code declares a payload
        // far larger than the read limit.  read_frame must reject it by
        // the declared length rather than allocating the buffer (which
        // would abort the process), so the read returns gracefully.
        let mut frame = vec![0x81u8, 0x80 | 127];
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let mut conn = WsConn::new(Scripted {
            reads: VecDeque::from([ScriptedRead::Data(frame)]),
        });
        let graceful = matches!(conn.read_message(1 << 12), Ok(WsIn::Close) | Err(_));
        assert!(
            graceful,
            "oversized frame must be rejected gracefully, not allocated"
        );
    }

    #[test]
    fn a_timeout_between_frames_reads_idle() {
        let mut conn = WsConn::new(Scripted {
            reads: VecDeque::from([
                ScriptedRead::Timeout,
                ScriptedRead::Data(masked_text_frame(b"hi")),
            ]),
        });
        assert!(matches!(conn.read_message(1 << 12), Ok(WsIn::Idle)));
        match conn.read_message(1 << 12) {
            Ok(WsIn::Text(payload)) => assert_eq!(payload, b"hi"),
            _ => panic!("expected the text message after the idle read"),
        }
    }

    #[test]
    fn a_timeout_mid_frame_keeps_reading() {
        // The frame arrives split across segments with timeouts in
        // between; no byte may be lost.
        let frame = masked_text_frame(b"split");
        let (a, rest) = frame.split_at(1);
        let (b, c) = rest.split_at(3);
        let mut conn = WsConn::new(Scripted {
            reads: VecDeque::from([
                ScriptedRead::Data(a.to_vec()),
                ScriptedRead::Timeout,
                ScriptedRead::Data(b.to_vec()),
                ScriptedRead::Timeout,
                ScriptedRead::Data(c.to_vec()),
            ]),
        });
        match conn.read_message(1 << 12) {
            Ok(WsIn::Text(payload)) => assert_eq!(payload, b"split"),
            _ => panic!("expected the split frame to reassemble"),
        }
    }

    #[test]
    fn an_exhausted_stream_reads_close() {
        let mut conn = WsConn::new(Scripted {
            reads: VecDeque::new(),
        });
        assert!(matches!(conn.read_message(1 << 12), Ok(WsIn::Close)));
    }

    /// A stream that reads the given bytes once, then EOF, and keeps
    /// every write call apart so a test can count them.
    struct Recording {
        input: VecDeque<u8>,
        writes: Vec<Vec<u8>>,
    }
    impl Recording {
        fn new(input: &[u8]) -> Recording {
            Recording {
                input: input.iter().copied().collect(),
                writes: Vec::new(),
            }
        }
    }
    impl Read for Recording {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.input.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.input.pop_front().expect("counted");
            }
            Ok(n)
        }
    }
    impl Write for Recording {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A masked client frame with a raw first header byte and a
    /// payload short enough for the 7-bit length.
    fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut frame = vec![first, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (i, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[i & 3]);
        }
        frame
    }

    /// Read one message from `input` under `limit`, returning whether it
    /// failed and the frames written back.
    fn answer(input: &[u8], limit: usize) -> (bool, Vec<Vec<u8>>) {
        let mut conn = WsConn::new(Recording::new(input));
        let failed = conn.read_message(limit).is_err();
        (failed, conn.stream.writes)
    }

    /// The close frame a protocol error answers with.
    fn protocol_error_close(reason: &str) -> Vec<u8> {
        let mut frame = vec![0x88, (reason.len() as u8).saturating_add(2), 0x03, 0xEA];
        frame.extend_from_slice(reason.as_bytes());
        frame
    }

    /// gorilla's server fast path puts the header and payload on the
    /// wire in one write; two writes cost a TLS record each and, with
    /// Nagle's algorithm on, a delayed-ACK stall for the second.
    #[test]
    fn a_frame_goes_out_in_one_write() {
        let mut conn = WsConn::new(Recording::new(&[]));
        conn.write_text(b"hello").expect("write");
        let big = vec![b'x'; 70_000];
        conn.write_text(&big).expect("write");
        let writes = &conn.stream.writes;
        assert_eq!(writes.len(), 2, "one write per frame");
        assert_eq!(writes[0], b"\x81\x05hello");
        assert_eq!(writes[1][..10], [0x81, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70]);
        assert_eq!(writes[1].len(), 10 + 70_000);
    }

    /// After the close frame, nothing more reaches the wire: gorilla
    /// fails every later write with `ErrCloseSent`, which is what stops
    /// dcrd's writer from sending a queued notification after it.
    #[test]
    fn nothing_is_written_after_the_close_frame() {
        let mut conn = WsConn::new(Recording::new(&client_frame(0x88, &[0x03, 0xE8])));
        assert!(matches!(conn.read_message(1 << 12), Ok(WsIn::Close)));
        assert!(
            conn.write_text(b"late notification").is_err(),
            "a write after the close frame must fail"
        );
        assert_eq!(
            conn.stream.writes,
            vec![vec![0x88, 0x02, 0x03, 0xE8]],
            "only the close echo is on the wire"
        );
    }

    /// A protocol error's close frame ends writing just the same.
    #[test]
    fn nothing_is_written_after_a_protocol_error() {
        let mut conn = WsConn::new(Recording::new(&[0x81, 0x05]));
        assert!(conn.read_message(1 << 12).is_err());
        assert!(conn.write_text(b"late").is_err());
        assert_eq!(conn.stream.writes, vec![protocol_error_close("bad MASK")]);
    }

    /// gorilla echoes a received close's code without its reason, and
    /// answers a close with no code (or a one-byte payload) with an
    /// empty close, since `FormatCloseMessage(1005, "")` is empty.
    #[test]
    fn a_received_close_is_echoed_as_gorilla_echoes_it() {
        let (failed, writes) = answer(&client_frame(0x88, b"\x0f\xa0bye"), 1 << 12);
        assert!(!failed);
        assert_eq!(
            writes,
            vec![vec![0x88, 0x02, 0x0f, 0xa0]],
            "4000, no reason"
        );

        for payload in [&b""[..], &b"\x03"[..]] {
            let (failed, writes) = answer(&client_frame(0x88, payload), 1 << 12);
            assert!(!failed);
            assert_eq!(writes, vec![vec![0x88, 0x00]], "no code: an empty close");
        }
    }

    /// A close code a peer may not send, or a reason that is not UTF-8,
    /// is a protocol error rather than something to echo.
    #[test]
    fn an_invalid_received_close_is_a_protocol_error() {
        for code in [1004u16, 1005, 1006, 1014, 1015, 999, 2999, 5000] {
            let (failed, writes) = answer(&client_frame(0x88, &code.to_be_bytes()), 1 << 12);
            assert!(failed, "{code}");
            assert_eq!(
                writes,
                vec![protocol_error_close(&format!("bad close code {code}"))],
                "{code}"
            );
        }
        for code in [1000u16, 1003, 1007, 1013, 3000, 4999] {
            let (failed, writes) = answer(&client_frame(0x88, &code.to_be_bytes()), 1 << 12);
            assert!(!failed, "{code}");
            assert_eq!(
                writes,
                vec![[&[0x88, 0x02][..], &code.to_be_bytes()].concat()]
            );
        }
        let (failed, writes) = answer(&client_frame(0x88, b"\x03\xe8\xff"), 1 << 12);
        assert!(failed);
        assert_eq!(
            writes,
            vec![protocol_error_close("invalid utf8 payload in close frame")]
        );
    }

    /// Everything the first two bytes show is judged before the length
    /// is read, all of it reported at once in gorilla's order -- so an
    /// unmasked frame declaring a huge length is a `bad MASK`, not a
    /// 1009, and a bad opcode's payload is never read.
    #[test]
    fn the_first_two_bytes_are_judged_before_the_length() {
        // Unmasked, declaring its length in the 64-bit field.
        let (failed, writes) = answer(&[0x81, 127], 1 << 12);
        assert!(failed);
        assert_eq!(writes, vec![protocol_error_close("bad MASK")]);

        // A bad opcode: only the two header bytes exist, so reading the
        // length, mask or payload would end mid-frame with no close.
        let (failed, writes) = answer(&[0x83, 0x80 | 126], 1 << 12);
        assert!(failed);
        assert_eq!(writes, vec![protocol_error_close("bad opcode 3")]);

        // Every fault at once, in gorilla's order.
        let (failed, writes) = answer(&[0x79, 126], 1 << 12);
        assert!(failed);
        assert_eq!(
            writes,
            vec![protocol_error_close(
                "RSV1 set, RSV2 set, RSV3 set, len > 125 for control, FIN not set on control, bad MASK"
            )]
        );

        // Sequencing, from the header alone.
        let (failed, writes) = answer(&[0x80, 0x80 | 126], 1 << 12);
        assert!(failed);
        assert_eq!(writes, vec![protocol_error_close("continuation after FIN")]);
        let mut input = client_frame(0x01, b"part");
        input.extend_from_slice(&[0x81, 0x80 | 126]);
        let (failed, writes) = answer(&input, 1 << 12);
        assert!(failed);
        assert_eq!(writes, vec![protocol_error_close("data before FIN")]);
    }

    /// The read limit is enforced on the message's running total of
    /// declared lengths, before a frame's payload is read, and the 1009
    /// carries no reason (`FormatCloseMessage(CloseMessageTooBig, "")`).
    #[test]
    fn the_read_limit_is_judged_on_declared_lengths() {
        let too_big = vec![vec![0x88, 0x02, 0x03, 0xF1]];

        // One frame declaring a byte past the limit, with no payload
        // behind it to read.
        let mut input = vec![0x81, 0x80 | 126];
        input.extend_from_slice(&4097u16.to_be_bytes());
        input.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let (failed, writes) = answer(&input, 1 << 12);
        assert!(failed);
        assert_eq!(writes, too_big);

        // Two fragments, the second pushing the total past the limit.
        let mut input = client_frame(0x01, &[b'a'; 100]);
        input.extend_from_slice(&[0x80, 0x80 | 126]);
        input.extend_from_slice(&3997u16.to_be_bytes());
        input.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let (failed, writes) = answer(&input, 1 << 12);
        assert!(failed);
        assert_eq!(writes, too_big);

        // Exactly at the limit is fine.
        let mut input = client_frame(0x01, &[b'a'; 100]);
        input.extend_from_slice(&[0x80, 0x80 | 126]);
        input.extend_from_slice(&3996u16.to_be_bytes());
        input.extend_from_slice(&[0, 0, 0, 0]);
        input.extend_from_slice(&[b'b'; 3996]);
        let mut conn = WsConn::new(Recording::new(&input));
        match conn.read_message(1 << 12) {
            Ok(WsIn::Text(message)) => assert_eq!(message.len(), 1 << 12),
            _ => panic!("a message at the limit is read"),
        }
    }

    /// A length with the top bit set is negative as gorilla's `int64`:
    /// `ErrReadLimit`, with no close frame at all.
    #[test]
    fn a_negative_length_fails_without_a_close_frame() {
        let mut input = vec![0x81, 0x80 | 127];
        input.extend_from_slice(&(1u64 << 63).to_be_bytes());
        let (failed, writes) = answer(&input, 1 << 24);
        assert!(failed);
        assert!(writes.is_empty(), "{writes:?}");
    }
}
