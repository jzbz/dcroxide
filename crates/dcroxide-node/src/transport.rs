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
//! The idle read deadline dcrd sets before each read is applied by the
//! peer loop on the underlying stream (for a TCP connection,
//! `TcpStream::set_read_timeout`); the transport itself is deadline
//! agnostic.

use std::io::{Read, Write};

use dcroxide_peer::MsgTransport;
use dcroxide_wire::{
    CurrencyNet, MAX_MESSAGE_PAYLOAD, MESSAGE_HEADER_SIZE, Message,
    read_message as wire_read_message, write_message as wire_write_message,
};

/// The byte offset of the little-endian payload length field within a
/// message header (after the 4-byte network magic and 12-byte command).
const PAYLOAD_LEN_OFFSET: usize = 16;

/// Frames [`Message`]s over a byte stream using dcrd's wire encoding.
pub struct WireTransport<S> {
    stream: S,
    pver: u32,
    net: CurrencyNet,
    bytes_read: u64,
    bytes_written: u64,
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
        }
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
}

impl<S: Read + Write> MsgTransport for WireTransport<S> {
    fn read_message(&mut self) -> Result<Message, String> {
        // Read the fixed-size header first so the payload length is
        // known before any payload allocation (dcrd `readMessageHeader`
        // then the payload read).
        let mut buf = vec![0u8; MESSAGE_HEADER_SIZE];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| e.to_string())?;

        let payload_len = u32::from_le_bytes(
            buf[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
                .try_into()
                .expect("four bytes"),
        ) as usize;

        // Only read the payload when the header-declared length is
        // within the global cap; an oversized length is left for the
        // codec below to reject from the header alone (its first check),
        // so a hostile peer cannot force a huge allocation.
        if payload_len as u64 <= MAX_MESSAGE_PAYLOAD {
            buf.resize(MESSAGE_HEADER_SIZE.saturating_add(payload_len), 0);
            self.stream
                .read_exact(&mut buf[MESSAGE_HEADER_SIZE..])
                .map_err(|e| e.to_string())?;
        }

        let (msg, consumed) =
            wire_read_message(&buf, self.pver, self.net).map_err(|e| e.to_string())?;
        self.bytes_read = self.bytes_read.saturating_add(consumed as u64);
        Ok(msg)
    }

    fn write_message(&mut self, msg: &Message) -> Result<(), String> {
        let bytes = wire_write_message(msg, self.pver, self.net).map_err(|e| e.to_string())?;
        self.stream.write_all(&bytes).map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())?;
        self.bytes_written = self.bytes_written.saturating_add(bytes.len() as u64);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use dcroxide_peer::MAX_PROTOCOL_VERSION;
    use dcroxide_wire::MsgPing;

    // Any consistent network magic works for a round trip; the mainnet
    // value keeps the framed bytes recognizable.
    const NET: CurrencyNet = CurrencyNet(0xd9b4_00f9);

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
        let mut header = vec![0u8; MESSAGE_HEADER_SIZE];
        header[0..4].copy_from_slice(&NET.0.to_le_bytes());
        header[4..8].copy_from_slice(b"ping");
        let oversized = (MAX_MESSAGE_PAYLOAD + 1) as u32;
        header[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 4]
            .copy_from_slice(&oversized.to_le_bytes());

        let mut transport = WireTransport::new(Cursor::new(header), MAX_PROTOCOL_VERSION, NET);
        let err = transport
            .read_message()
            .expect_err("oversized payload rejected");
        assert!(err.to_lowercase().contains("payload"), "error: {err}");
    }
}
