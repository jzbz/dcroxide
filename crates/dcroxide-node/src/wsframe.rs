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
            let frame = match self.read_frame()? {
                Some(frame) => frame,
                // A clean EOF between messages is a normal disconnect.
                None => return Ok(WsIn::Close),
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

    /// A decoded frame header and its unmasked payload.
    fn read_frame(&mut self) -> Result<Option<Frame>, String> {
        let mut header = [0u8; 2];
        match self.stream.read_exact(&mut header) {
            Ok(()) => {}
            // A clean EOF right at a frame boundary is a disconnect.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.to_string()),
        }

        let fin = header[0] & 0x80 != 0;
        // The reserved bits must be zero (no extensions are negotiated).
        if header[0] & 0x70 != 0 {
            return self
                .fail(close_code::PROTOCOL_ERROR, "reserved bits set")
                .map(|_| None);
        }
        let opcode = header[0] & 0x0F;
        let masked = header[1] & 0x80 != 0;
        let len_code = (header[1] & 0x7F) as usize;

        // Control frames must be final and carry at most 125 bytes.
        let is_control = opcode & 0x08 != 0;
        if is_control && (!fin || len_code > 125) {
            return self
                .fail(close_code::PROTOCOL_ERROR, "invalid control frame")
                .map(|_| None);
        }

        let payload_len = match len_code {
            126 => {
                let mut ext = [0u8; 2];
                self.stream
                    .read_exact(&mut ext)
                    .map_err(|e| e.to_string())?;
                u16::from_be_bytes(ext) as usize
            }
            127 => {
                let mut ext = [0u8; 8];
                self.stream
                    .read_exact(&mut ext)
                    .map_err(|e| e.to_string())?;
                u64::from_be_bytes(ext) as usize
            }
            other => other,
        };

        // Every client frame must be masked (RFC 6455 section 5.1).
        if !masked {
            return self
                .fail(close_code::PROTOCOL_ERROR, "client frame not masked")
                .map(|_| None);
        }
        let mut mask = [0u8; 4];
        self.stream
            .read_exact(&mut mask)
            .map_err(|e| e.to_string())?;

        let mut payload = vec![0u8; payload_len];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| e.to_string())?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }

        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
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

    #[test]
    fn accept_key_matches_the_rfc_example() {
        // RFC 6455 section 1.3 worked example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
