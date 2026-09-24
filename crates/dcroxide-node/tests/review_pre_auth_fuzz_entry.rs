// SPDX-License-Identifier: ISC
//! The `http_head_parse` fuzz target's entry point into the RPC server's
//! request head parser, `rpcrun::fuzz_pre_auth_request`, pinned on stable
//! so a change that breaks it shows up in the ordinary test run rather
//! than only in the nightly fuzz job.

use dcroxide_node::rpcrun::fuzz_pre_auth_request;

#[test]
fn a_parsed_head_ends_at_its_blank_line() {
    let head = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nOrigin: http://127.0.0.1\r\n\r\n";
    let mut raw = head.as_bytes().to_vec();
    raw.extend_from_slice(b"\x81\x85frame bytes");
    assert_eq!(fuzz_pre_auth_request(&raw), Some(head.len()));

    // Go's line reader ends a line, and the head, at a bare LF too.
    let head = "POST / HTTP/1.0\n\n";
    assert_eq!(
        fuzz_pre_auth_request(format!("{head}{{}}").as_bytes()),
        Some(head.len())
    );
}

#[test]
fn a_declared_body_is_discarded_after_the_head() {
    // Chunked, then a redirect (the doubled slash cleans to `/`) with a
    // declared length the stream runs out before.
    for (head, body) in [
        (
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            "5\r\nhello\r\n0\r\n\r\n",
        ),
        (
            "POST //x?q HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n",
            "{}",
        ),
    ] {
        assert_eq!(
            fuzz_pre_auth_request(format!("{head}{body}").as_bytes()),
            Some(head.len()),
            "{head:?}"
        );
    }
}

#[test]
fn a_refused_head_is_none() {
    for raw in [
        &b""[..],
        b"GET / HTTP/1.1\r\n",
        b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.10\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"\xff / HTTP/1.1\r\nHost: h\r\n\r\n",
    ] {
        assert_eq!(fuzz_pre_auth_request(raw), None, "{raw:?}");
    }
}
