// SPDX-License-Identifier: ISC
//! JSON-RPC request fuzz target: the parsing a request body or websocket
//! message goes through before any handler runs, over arbitrary bytes.
//!
//! Much of it runs without authentication: a websocket client's first
//! message is parsed, as a batch or a single request, before the server
//! looks at whether it is `authenticate` (dcrd `inHandler`), so a panic
//! anywhere here is a pre-auth abort under `panic = "abort"`.  The path
//! is the one `websocket.rs` and `rpcrun.rs` take: Go's handling of the
//! raw bytes (`gojson::unmarshal_input`), the batch test on the first raw
//! byte, the Go `encoding/json` validator and the array splitter for a
//! batch, `unmarshal_request` for each request, then the reply envelope
//! around the request's id, and the parameters decoded against the
//! registered method's Go types (`dcrjson.ParseParams`), which is most of
//! `gojson`'s decoder.
//!
//! Neither the method nor the envelope's keys are something the fuzzer
//! can find alone: a method is a hash-map key it has no comparison to
//! steer by, and the keys are matched case-insensitively, which nine
//! minutes of fuzzing never got past to write `params`.  So the first
//! byte picks a registered method, against which the parameters are
//! decoded too, and one of two modes.  In the first the rest is the whole
//! message.  In the second the rest is the `params` value of a request
//! for the picked method that the target writes around it, so every input
//! reaches that method's Go types.  (The selector leads rather than
//! trails: any message that unmarshals ends in `}`, `]` or JSON
//! whitespace, six byte values that would reach six methods of the
//! hundred or so.)

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;

use dcroxide_dcrjson::{Registry, gojson, marshal_response, parse_params};
use dcroxide_rpc::http::{split_raw_array, unmarshal_request};

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut registry = Registry::new();
    dcroxide_rpctypes::register_all(&mut registry);
    registry
});

static METHODS: LazyLock<Vec<String>> =
    LazyLock::new(|| REGISTRY.registered_methods(dcroxide_rpctypes::METHOD_TYPE_NAME));

fn request(body: &str, picked: &str) {
    let Ok(req) = unmarshal_request(body) else {
        return;
    };
    let _ = marshal_response(&req.jsonrpc, &req.id, Some("null"), None);
    let params: Vec<&str> = req.params.iter().map(String::as_str).collect();
    let _ = parse_params(&REGISTRY, &dcroxide_rpctypes::method(&req.method), &params);
    let _ = parse_params(&REGISTRY, &dcroxide_rpctypes::method(picked), &params);
}

fn message(message: &[u8], picked: &str) {
    // dcrd tests the raw first byte, so a leading space makes an array a
    // single request that fails to unmarshal, not a batch.
    let batched = message.first() == Some(&b'[');
    let Ok(body) = gojson::unmarshal_input(message) else {
        return;
    };
    if !batched {
        request(&body, picked);
        return;
    }
    if gojson::validate(&body).is_err() {
        return;
    }
    for entry in split_raw_array(body.trim_start_matches([' ', '\t', '\n', '\r'])) {
        request(&entry, picked);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let picked = &METHODS[usize::from(selector >> 1) % METHODS.len()];
    if selector & 1 == 0 {
        message(rest, picked);
    } else {
        let mut built =
            format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{picked}","params":"#).into_bytes();
        built.extend_from_slice(rest);
        built.push(b'}');
        message(&built, picked);
    }
});
