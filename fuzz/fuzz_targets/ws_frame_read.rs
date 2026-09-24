// SPDX-License-Identifier: ISC
//! Websocket frame fuzz target: `WsConn::read_message` over an arbitrary
//! client byte stream, at dcrd's unauthenticated and authenticated read
//! limits, for every message the stream holds.
//!
//! This reader runs before authentication -- a client may send
//! `authenticate` as its first message, so its frames are read first --
//! and under `panic = "abort"` a panic in it is a pre-auth abort.  Beyond
//! not panicking, no message it returns may exceed the read limit, which
//! it enforces across a message's fragments by their declared lengths.

#![no_main]

use std::io::{self, Read, Write};

use libfuzzer_sys::fuzz_target;

use dcroxide_node::wsframe::{WsConn, WsIn};

/// dcrd's websocket read limits before and after authentication
/// (`websocketReadLimitUnauthenticated`, `websocketReadLimitAuthenticated`).
const READ_LIMITS: [usize; 2] = [1 << 12, 1 << 24];

/// The client's side of the connection: what it sent, and a sink for the
/// pongs and close frames the server writes back.
struct Client<'a> {
    sent: &'a [u8],
}

impl Read for Client<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sent.read(buf)
    }
}

impl Write for Client<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, sent)) = data.split_first() else {
        return;
    };
    let limit = READ_LIMITS[usize::from(selector & 1)];
    let mut conn = WsConn::new(Client { sent });
    // Every frame consumes input, so this ends at the stream's EOF if a
    // close or a protocol error does not end it first.
    while let Ok(WsIn::Text(message)) = conn.read_message(limit) {
        assert!(
            message.len() <= limit,
            "{} B message over the {limit} B limit",
            message.len()
        );
    }
});
