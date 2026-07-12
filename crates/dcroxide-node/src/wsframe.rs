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
}

impl<S: Read + Write> WsConn<S> {
    /// Wrap a stream whose handshake has completed.
    pub fn new(stream: S) -> WsConn<S> {
        WsConn { stream }
    }

    /// Read the next complete client message, reassembling fragments,
    /// answering pings with pongs, ignoring pongs, and enforcing
    /// `read_limit` cumulatively across a message's fragments (dcrd's
    /// authenticated/unauthenticated websocket read limits).  A
    /// protocol violation or an oversized message is answered with the
    /// matching close frame and returns an error.
    pub fn read_message(&mut self, read_limit: usize) -> Result<WsIn, String> {
        // The reassembled payload and the data opcode that started it.
        let mut message: Vec<u8> = Vec::new();
        let mut in_message = false;

        loop {
            let frame = match self.read_frame(read_limit)? {
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
                // Continuation.
                0x0 => {
                    if !in_message {
                        return self.fail(close_code::PROTOCOL_ERROR, "continuation after FIN");
                    }
                    message.extend_from_slice(&frame.payload);
                }
                // Text or binary; dcrd discards the frame type.
                0x1 | 0x2 => {
                    if in_message {
                        return self.fail(close_code::PROTOCOL_ERROR, "data before FIN");
                    }
                    in_message = true;
                    message.extend_from_slice(&frame.payload);
                }
                // Close.
                0x8 => {
                    // Echo the client's close code back, then treat the
                    // connection as ended.
                    let code = if frame.payload.len() >= 2 {
                        u16::from_be_bytes([frame.payload[0], frame.payload[1]])
                    } else {
                        1000
                    };
                    let _ = self.write_control(0x8, &code.to_be_bytes());
                    return Ok(WsIn::Close);
                }
                // Ping: answer with a pong echoing the payload.
                0x9 => {
                    self.write_control(0xA, &frame.payload)?;
                    continue;
                }
                // Pong: ignored (dcrd never pings, so this only arrives
                // unsolicited).
                0xA => continue,
                other => {
                    return self.fail(close_code::PROTOCOL_ERROR, &format!("bad opcode {other}"));
                }
            }

            if message.len() > read_limit {
                return self.fail(close_code::TOO_BIG, "message exceeds the read limit");
            }

            if frame.fin {
                return Ok(WsIn::Text(message));
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
    fn read_frame(&mut self, read_limit: usize) -> Result<FrameRead, String> {
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
        // The reserved bits must be zero (no extensions are negotiated).
        if header[0] & 0x70 != 0 {
            return self
                .fail(close_code::PROTOCOL_ERROR, "reserved bits set")
                .map(|_| FrameRead::Eof);
        }
        let opcode = header[0] & 0x0F;
        let masked = header[1] & 0x80 != 0;
        let len_code = (header[1] & 0x7F) as usize;

        // Control frames must be final and carry at most 125 bytes.
        let is_control = opcode & 0x08 != 0;
        if is_control && (!fin || len_code > 125) {
            return self
                .fail(close_code::PROTOCOL_ERROR, "invalid control frame")
                .map(|_| FrameRead::Eof);
        }

        let payload_len = match len_code {
            126 => {
                let mut ext = [0u8; 2];
                self.read_full(&mut ext)?;
                u16::from_be_bytes(ext) as usize
            }
            127 => {
                let mut ext = [0u8; 8];
                self.read_full(&mut ext)?;
                u64::from_be_bytes(ext) as usize
            }
            other => other,
        };

        // Reject a frame whose declared length exceeds the read limit
        // before allocating its payload buffer, so a hostile length field
        // (up to 2^63 with the 127 length code) cannot drive an
        // out-of-memory abort ahead of the reassembled-message limit
        // check (gorilla/dcrd reject by the declared length too).
        if payload_len > read_limit {
            return self
                .fail(close_code::TOO_BIG, "frame exceeds the read limit")
                .map(|_| FrameRead::Eof);
        }

        // Every client frame must be masked (RFC 6455 section 5.1).
        if !masked {
            return self
                .fail(close_code::PROTOCOL_ERROR, "client frame not masked")
                .map(|_| FrameRead::Eof);
        }
        let mut mask = [0u8; 4];
        self.read_full(&mut mask)?;

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

    /// Write a data frame with the given opcode and unmasked payload.
    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut header = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            header.push(len as u8);
        } else if len <= u16::MAX as usize {
            header.push(126);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }
        self.stream.write_all(&header).map_err(|e| e.to_string())?;
        self.stream.write_all(payload).map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())
    }

    /// Write a control frame (pong or close).
    fn write_control(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        self.write_frame(opcode, payload)
    }

    /// Send a close frame with the given code and reason, then report
    /// the failure so the connection ends.
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
}
