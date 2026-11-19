// SPDX-License-Identifier: ISC
//! RPC record checks fuzz target: Go's checks on what a client sends
//! after its first ClientHello, which the RPC listener runs before rustls
//! sees those bytes (`dcroxide_gotls::GoRecordChecks`), never panic.
//!
//! Anyone who can reach the RPC port reaches them, before any
//! authentication: the record walk over the client's bytes, the reader of
//! a second ClientHello after a HelloRetryRequest, which follows Go's
//! `clientHelloMsg.unmarshal`, and the comparison with the first.  The
//! input is laid after a fixed first ClientHello and a HelloRetryRequest or
//! a TLS 1.2 ServerHello, read as the opening bytes themselves, or given
//! as the server's bytes (`dcroxide_gotls::fuzz_record_checks`), and fed
//! in pieces of a size it picks.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcroxide_gotls::fuzz_record_checks(data);
});
