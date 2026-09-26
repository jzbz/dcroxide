// SPDX-License-Identifier: ISC
//! A seeder response decoded the way dcrd's `SeedAddrs` decodes it: a
//! `json.Decoder` over the byte-limited body, `dec.More()` then
//! `dec.Decode(&node)` per value.  The port framed each value by
//! counting brackets and then insisted on UTF-8, where the peers file
//! already went through the crate's scanner-driven model of the same
//! decoder.  Every row was checked against Go 1.26.5's `encoding/json`,
//! the toolchain dcrd's release image uses, running dcrd's loop.

// Test scaffolding uses bounded counters.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_addrmgr::{HttpsSeederFilters, SeedEnv, SeederTransport, seed_addrs};

struct Body(Vec<u8>);

impl SeederTransport for Body {
    fn get(&mut self, _url: &str) -> Result<(u32, Vec<u8>), String> {
        Ok((200, self.0.clone()))
    }
}

#[derive(Default)]
struct Env {
    warnings: Vec<String>,
}

impl SeedEnv for Env {
    fn now_nanos(&mut self) -> i64 {
        1_700_000_000 * 1_000_000_000
    }

    fn rand_duration(&mut self, _max: i64) -> i64 {
        0
    }

    fn log_warn(&mut self, msg: &str) {
        self.warnings.push(msg.to_string());
    }
}

/// The ports of the addresses a response yields, and the warnings.
fn seed(body: &[u8]) -> (Result<Vec<u16>, String>, Vec<String>) {
    let mut env = Env::default();
    let addrs = seed_addrs(
        "seed.example.org",
        &mut Body(body.to_vec()),
        &mut env,
        &HttpsSeederFilters::default(),
    );
    (
        addrs.map(|addrs| addrs.iter().map(|a| a.port).collect()),
        env.warnings,
    )
}

/// A byte that is not UTF-8 inside a string becomes U+FFFD, as Go's
/// decoder unquotes it: the node it spoils is skipped by `ParseIP` and
/// the rest of the response is kept.  The port rejected the whole
/// response, and with it every address that seeder returned.
#[test]
fn invalid_utf8_in_a_string_costs_only_its_node() {
    let body = b"{\"host\":\"1.2.3.4:9101\",\"services\":1,\"pver\":1}\n\
        {\"host\":\"5.6.7.8\xff:9102\",\"services\":1,\"pver\":1}\n\
        {\"host\":\"9.9.9.9:9103\",\"services\":1,\"pver\":1,\"pad\":\"\xfe\"}";
    let (addrs, warnings) = seed(body);
    assert_eq!(addrs, Ok(vec![9101, 9103]));
    assert_eq!(
        warnings,
        vec![
            "seeder returned a hostname that is not an IP address \"5.6.7.8\u{fffd}\"".to_string()
        ]
    );
}

/// Go's decoder reports a syntax error where its scanner meets it, even
/// inside a value the response (or the 4096-byte limit) cuts short, and
/// a byte outside a string that begins no value names itself.  A comma
/// between values is not a separator to it.  The port reported the
/// first two as `unexpected EOF`, the stray byte as invalid UTF-8, and
/// the comma as `unexpected end of JSON input`.
#[test]
fn decode_errors_carry_gos_text() {
    let mut cut = b"{\"host\":\"1.2.3.4:9108\"}\n{\"host\":\"5.6.7.8:9108\",\"pad\":\"".to_vec();
    cut.resize(5000, b'a');
    cut[100] = b'\n';
    for (name, body, want) in [
        (
            "syntax error before the end",
            b"{\"host\":\"1.2.3.4:9108\"}\n{\"host\":\"5.6.7.8:9108\" \"services\":1".to_vec(),
            "invalid character '\"' after object key:value pair",
        ),
        (
            "syntax error before the limit",
            cut,
            "invalid character '\\n' in string literal",
        ),
        (
            "comma between values",
            b"{\"host\":\"1.2.3.4:9108\"},{\"host\":\"5.6.7.8:9108\"}".to_vec(),
            "invalid character ',' looking for beginning of value",
        ),
        (
            "stray byte between values",
            b"{\"host\":\"1.2.3.4:9108\"}\n\xff".to_vec(),
            "invalid character '\u{ff}' looking for beginning of value",
        ),
        (
            "a number after a value",
            b"{\"host\":\"1.2.3.4:9108\"}123".to_vec(),
            "json: cannot unmarshal number into Go value of type addrmgr.node",
        ),
    ] {
        assert_eq!(
            seed(&body).0,
            Err(format!("unable to parse response: {want}")),
            "{name}"
        );
    }

    // A closing bracket ends the stream (`dec.More()` is false there),
    // keeping what was decoded before it.
    assert_eq!(
        seed(b"{\"host\":\"1.2.3.4:9108\"} ] {\"host\":\"5.6.7.8:9109\"}").0,
        Ok(vec![9108])
    );
}
