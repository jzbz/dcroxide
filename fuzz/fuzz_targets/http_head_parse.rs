// SPDX-License-Identifier: ISC
//! RPC HTTP request fuzz target: the request head parser and everything
//! the server derives from a head before it authenticates, over an
//! arbitrary client byte stream.
//!
//! Every connection to the RPC port goes through this first, so under
//! `panic = "abort"` a panic anywhere in it is a pre-auth abort: the
//! head reader (`read_http_head`, with its request-line, target and
//! version parsers), the `Expect` test, the mux's route and redirect, the
//! websocket handshake's header and origin checks, and the discard of a
//! refused request's declared body, chunked decoding included
//! (`rpcrun::fuzz_pre_auth_request`).  Beyond not panicking, the head
//! reader must stop exactly at the first blank line, since whatever
//! follows is the body or the first websocket frame.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The length of `data` up to and including its first blank line, which
/// Go's line reader ends at a bare LF as well as at CRLF.
fn head_end(data: &[u8]) -> Option<usize> {
    (1..=data.len()).find(|&end| {
        let head = &data[..end];
        head.ends_with(b"\n\n") || head.ends_with(b"\n\r\n")
    })
}

fuzz_target!(|data: &[u8]| {
    if let Some(len) = dcroxide_node::rpcrun::fuzz_pre_auth_request(data) {
        assert_eq!(
            Some(len),
            head_end(data),
            "the head reader stopped somewhere other than the first blank line"
        );
    }
});
