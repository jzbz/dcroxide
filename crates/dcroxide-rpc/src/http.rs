// SPDX-License-Identifier: ISC
//! The HTTP-facing request surface of the RPC server (dcrd
//! internal/rpcserver `checkAuth`/`checkAuthMAC`/`checkAuthUserPass`
//! and the request-body processing inside `jsonRPCRead`): Basic auth
//! decisions over the HMAC'd credential strings, Go-faithful request
//! unmarshalling, and the single/batched response assembly.  The live
//! HTTP shell (listener setup, the authenticated read limit, and header
//! writing) is the daemon's, in dcroxide-node `rpcrun.rs`.

// Scanner index arithmetic and base64 packing mirror Go.
#![allow(clippy::arithmetic_side_effects)]

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use dcroxide_dcrjson::{
    RPCError, RpcId, err_rpc_invalid_request, err_rpc_parse, gojson, marshal_response,
};

use crate::dispatch::process_request;
use crate::server::{RpcChain, Server};

/// Encode bytes with Go's standard base64 alphabet and padding.
pub fn base64_std_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The HMAC of the provided auth string under the server key (dcrd
/// `Server.authMAC`).
pub fn auth_mac(key: &[u8; 32], auth: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(auth);
    mac.finalize().into_bytes().into()
}

/// Constant-time byte equality (dcrd relies on
/// `subtle.ConstantTimeCompare`).
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl<C: RpcChain> Server<C> {
    /// Check the HTTP Basic authentication string against the stored
    /// credential MACs; the first result is auth success and the
    /// second whether the user is an admin (dcrd `checkAuthMAC`).  A
    /// mismatch is logged with the client's address, as dcrd warns
    /// "RPC authentication failure from `<addr>`".
    pub fn check_auth_mac(&self, auth: &str, remote_addr: &str) -> (bool, bool) {
        let mac = auth_mac(&self.hmac_key, auth.as_bytes());
        let cmp = ct_eq(&mac, &self.authsha);
        let limitcmp = ct_eq(&mac, &self.limitauthsha);
        if !cmp && !limitcmp {
            // Request's auth doesn't match either user.
            crate::log::warn(&format!("RPC authentication failure from {remote_addr}"));
            return (false, false);
        }
        (true, cmp)
    }

    /// Check a username and password by generating the corresponding
    /// HTTP Basic authentication string (dcrd `checkAuthUserPass`); the
    /// websocket `authenticate` command's check.
    pub fn check_auth_user_pass(&self, user: &str, pass: &str, remote_addr: &str) -> (bool, bool) {
        let login = format!("{user}:{pass}");
        let auth = format!("Basic {}", base64_std_encode(login.as_bytes()));
        self.check_auth_mac(&auth, remote_addr)
    }

    /// Check the HTTP Basic authentication supplied with a request from
    /// `remote_addr` (Go's `r.RemoteAddr`); the error only signals the
    /// auth failure (dcrd `checkAuth`).
    pub fn check_auth(
        &self,
        auth_header: Option<&str>,
        require: bool,
        remote_addr: &str,
    ) -> Result<(bool, bool), String> {
        // With no Basic credentials configured, authentication rests
        // entirely on the TLS layer having required and verified a
        // client certificate (dcrd's `--authtype=clientcert`).  If the
        // transport does not enforce that, deny: an endpoint with no
        // credentials and no client verification must never be served
        // as an authenticated admin.
        if self.authsha == [0u8; 32] && self.limitauthsha == [0u8; 32] {
            if self.cfg.client_cert_auth {
                return Ok((true, true));
            }
            return Err("auth failure".to_string());
        }

        let Some(auth) = auth_header else {
            if require {
                crate::log::warn(&format!("RPC authentication failure from {remote_addr}"));
                return Err("auth failure".to_string());
            }
            return Ok((false, false));
        };

        let (authed, is_admin) = self.check_auth_mac(auth, remote_addr);
        if !authed {
            return Err("auth failure".to_string());
        }
        Ok((authed, is_admin))
    }
}

/// A JSON-RPC request unmarshalled from a raw body exactly like Go's
/// `json.Unmarshal` into `dcrjson.Request`.
#[derive(Clone, Debug, PartialEq)]
pub struct RawRequest {
    /// The JSON-RPC protocol version.
    pub jsonrpc: String,
    /// The requested method.
    pub method: String,
    /// The raw JSON texts of the parameters.
    pub params: Vec<String>,
    /// Whether the request carried a `params` array at all.
    ///
    /// Go's `Params []json.RawMessage` is nil when the key is absent or
    /// null and a non-nil empty slice for `[]`, and dcrd's websocket
    /// batch arm tests that difference (`rpcwebsocket.go:1635`).
    /// `params` alone cannot express it, since both cases leave it
    /// empty.
    pub params_present: bool,
    /// The request id.
    pub id: RpcId,
}

/// The Go `encoding/json` kind word for a JSON value, as it appears
/// in unmarshal type errors.
fn json_value_kind(raw: &str) -> &'static str {
    match raw.as_bytes().first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't') | Some(b'f') => "bool",
        _ => "number",
    }
}

/// Split a JSON array into the raw JSON text of its elements.  The
/// input must be a syntax-valid array.
pub fn split_raw_array(data: &str) -> Vec<String> {
    let bytes = data.as_bytes();
    let mut elems = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                if start.is_none() {
                    start = Some(i);
                }
            }
            b'[' | b'{' => {
                if depth > 0 && start.is_none() {
                    start = Some(i);
                }
                depth += 1;
            }
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        elems.push(data[s..i].trim().to_string());
                    }
                    break;
                }
            }
            b',' if depth == 1 => {
                if let Some(s) = start {
                    elems.push(data[s..i].trim().to_string());
                }
                start = None;
            }
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => {
                if depth == 1 && start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    elems
}

/// Whether a decoded JSON key names the given ASCII struct field, the
/// way Go's `foldName` does: the shared matcher the struct decoder uses
/// too ([`gojson::go_fold_eq`]).
fn fold_eq(key: &str, field: &str) -> bool {
    gojson::go_fold_eq(key, field)
}

/// Split a JSON object into raw (key, value) text pairs.  The input
/// must be a syntax-valid object.
fn split_raw_object(data: &str) -> Vec<(String, String)> {
    let inner = data.trim();
    let inner = &inner[1..inner.len() - 1];
    // Reuse the array splitter over "key: value" runs by scanning
    // members manually: keys are JSON strings followed by a colon.
    let mut members = Vec::new();
    let bytes = inner.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                members.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if !inner[start..].trim().is_empty() {
        members.push(&inner[start..]);
    }

    let mut pairs = Vec::new();
    for member in members {
        // The key is a JSON string; find its closing quote and the
        // colon that follows.
        let member = member.trim_start();
        let bytes = member.as_bytes();
        let mut end = 1usize;
        let mut escaped = false;
        while end < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[end] == b'\\' {
                escaped = true;
            } else if bytes[end] == b'"' {
                break;
            }
            end += 1;
        }
        // Decoded, not raw: Go unmarshals the key before matching it to a
        // struct field, so `"\u006dethod"` names `method` there. Taking
        // the escaped text verbatim silently ignored such a member -- and
        // with it, the command the caller asked for.
        let key = match gojson::decode(&dcroxide_dcrjson::GoType::String, &member[..=end]) {
            Ok(dcroxide_dcrjson::GoValue::String(decoded)) => decoded,
            _ => member[1..end].to_string(),
        };
        let colon = member[end..].find(':').expect("valid object member") + end;
        pairs.push((key, member[colon + 1..].trim().to_string()));
    }
    pairs
}

/// Unmarshal a JSON-RPC request body exactly like Go's
/// `json.Unmarshal` into `dcrjson.Request`: syntax errors carry Go's
/// scanner texts, field type mismatches carry the struct-field error
/// texts, field names match case-insensitively with the last
/// duplicate winning, and unknown fields are ignored (dcrd
/// `jsonRPCRead`'s single-request parse).
pub fn unmarshal_request(body: &str) -> Result<RawRequest, String> {
    gojson::validate(body).map_err(|e| e.go_message())?;

    let trimmed = body.trim_start_matches([' ', '\t', '\n', '\r']);
    if !trimmed.starts_with('{') {
        if trimmed.starts_with("null") {
            // Unmarshalling null into a struct leaves it zeroed.
            return Ok(RawRequest {
                jsonrpc: String::new(),
                method: String::new(),
                params: Vec::new(),
                params_present: false,
                id: RpcId::Null,
            });
        }
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type dcrjson.Request",
            json_value_kind(trimmed)
        ));
    }

    let mut req = RawRequest {
        jsonrpc: String::new(),
        method: String::new(),
        params: Vec::new(),
        params_present: false,
        id: RpcId::Null,
    };
    for (key, raw) in split_raw_object(trimmed) {
        // Go matches JSON keys to struct fields case-insensitively.
        if fold_eq(&key, "jsonrpc") || fold_eq(&key, "method") {
            if raw == "null" {
                // Go ignores null for a string field (`literalStore`),
                // so an earlier duplicate key's value survives.
                continue;
            }
            let value = match gojson::decode(&dcroxide_dcrjson::GoType::String, &raw) {
                Ok(dcroxide_dcrjson::GoValue::String(s)) => s,
                Ok(_) => String::new(),
                Err(_) => {
                    let field = if fold_eq(&key, "jsonrpc") {
                        "jsonrpc"
                    } else {
                        "method"
                    };
                    return Err(format!(
                        "json: cannot unmarshal {} into Go struct field Request.{} of type string",
                        json_value_kind(&raw),
                        field
                    ));
                }
            };
            if fold_eq(&key, "jsonrpc") {
                req.jsonrpc = value;
            } else {
                req.method = value;
            }
        } else if fold_eq(&key, "params") {
            match raw.as_bytes().first() {
                Some(b'[') => {
                    req.params = split_raw_array(&raw);
                    req.params_present = true;
                }
                Some(b'n') => {
                    // null sets the slice back to nil, even after an
                    // earlier duplicate key's array.
                    req.params = Vec::new();
                    req.params_present = false;
                }
                _ => {
                    return Err(format!(
                        "json: cannot unmarshal {} into Go struct field Request.params of type \
                         []json.RawMessage",
                        json_value_kind(&raw)
                    ));
                }
            }
        } else if fold_eq(&key, "id") {
            // Go unmarshals into interface{}: numbers become float64,
            // strings and null map directly, and every other kind is
            // rejected later by the response id validity check.  An
            // array or object is decoded into `[]interface{}` or
            // `map[string]interface{}` first, and each number nested in
            // it goes through the same `convertNumber` range check as a
            // scalar id, whose failure is saved against the id field
            // and fails the whole unmarshal.
            if matches!(raw.as_bytes().first(), Some(b'[') | Some(b'{'))
                && let Some(literal) = first_out_of_range_number(&raw)
            {
                return Err(format!(
                    "json: cannot unmarshal number {literal} into Go struct field Request.id of \
                     type float64"
                ));
            }
            req.id = match raw.as_bytes().first() {
                Some(b'"') => match gojson::decode(&dcroxide_dcrjson::GoType::String, &raw) {
                    Ok(dcroxide_dcrjson::GoValue::String(s)) => RpcId::Str(s),
                    _ => RpcId::Invalid("string".to_string()),
                },
                Some(b'n') => RpcId::Null,
                Some(b't') | Some(b'f') => RpcId::Invalid("bool".to_string()),
                Some(b'[') => RpcId::Invalid("[]interface {}".to_string()),
                Some(b'{') => RpcId::Invalid("map[string]interface {}".to_string()),
                _ => {
                    // Go's `convertNumber` runs the literal through
                    // `strconv.ParseFloat`, which reports `ErrRange`
                    // for a magnitude past float64 and makes the whole
                    // unmarshal fail.  Rust's `f64::from_str` instead
                    // returns `Ok(inf)`, so reject the non-finite
                    // results here; an id of `1e999` must be a parse
                    // error, never an infinite float that later
                    // marshalling has no way to render.
                    let literal = raw.trim();
                    let value: f64 = literal.parse().unwrap_or(0.0);
                    if !value.is_finite() {
                        return Err(format!(
                            "json: cannot unmarshal number {literal} into Go struct field \
                             Request.id of type float64"
                        ));
                    }
                    RpcId::Float(value)
                }
            };
        }
    }
    Ok(req)
}

/// The first number literal in a composite JSON value, in document
/// order, that Go's `strconv.ParseFloat` rejects as out of range for
/// float64 (`convertNumber`).  The value has already passed
/// validation, so every number outside a string is a well-formed
/// literal; underflow rounds to zero in both languages and is not an
/// error.
fn first_out_of_range_number(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                // Skip the string, honouring escapes.
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < bytes.len()
                    && matches!(bytes[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    i += 1;
                }
                let literal = &raw[start..i];
                let value: f64 = literal.parse().unwrap_or(0.0);
                if !value.is_finite() {
                    return Some(literal);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// A reply `jsonRPCRead` built with `dcrjson.MarshalResponse` itself, or
/// `None` after logging why it failed (`log.Errorf("Failed to create
/// reply: %v", err)`).
fn created_or_logged<E: core::fmt::Display>(reply: Result<String, E>) -> Option<String> {
    match reply {
        Ok(reply) => Some(reply),
        Err(err) => {
            crate::log::error(&format!("Failed to create reply: {err}"));
            None
        }
    }
}

/// Process a JSON-RPC request body and return the full response body
/// including the Bitcoin Core compatibility newline (the request
/// handling inside dcrd `jsonRPCRead`; the connection handling and
/// read-limit plumbing are the daemon's, in dcroxide-node `rpcrun.rs`).
pub fn process_body<C: RpcChain>(server: &Server<C>, body: &str, is_admin: bool) -> Vec<u8> {
    let mut results: Vec<String> = Vec::new();
    let mut batch_size = 0usize;

    // Determine the request type.
    let batched_request = body.as_bytes().first() == Some(&b'[');

    // Process a single request.
    if !batched_request {
        let resp = match unmarshal_request(body) {
            Err(err_text) => {
                let json_err = RPCError::new(
                    err_rpc_parse().code,
                    &format!("Failed to parse request: {err_text}"),
                );
                created_or_logged(marshal_response("1.0", &RpcId::Null, None, Some(&json_err)))
            }
            Ok(req) => {
                let param_refs: Vec<&str> = req.params.iter().map(|s| s.as_str()).collect();
                process_request(
                    server,
                    &req.jsonrpc,
                    &req.method,
                    &param_refs,
                    &req.id,
                    is_admin,
                )
            }
        };
        if let Some(resp) = resp {
            results.push(resp);
        }
    }

    // Process a batched request.
    if batched_request {
        match gojson::validate(body) {
            Err(err) => {
                let json_err = RPCError::new(
                    err_rpc_parse().code,
                    &format!("Failed to parse request: {}", err.go_message()),
                );
                if let Some(resp) =
                    created_or_logged(marshal_response("2.0", &RpcId::Null, None, Some(&json_err)))
                {
                    results.push(resp);
                }
            }
            Ok(()) => {
                let entries = split_raw_array(body.trim_start_matches([' ', '\t', '\n', '\r']));

                // Respond with an empty batch error if the batch size
                // is zero.
                if entries.is_empty() {
                    let json_err = RPCError::new(
                        err_rpc_invalid_request().code,
                        "Invalid request: empty batch",
                    );
                    match marshal_response("2.0", &RpcId::Null, None, Some(&json_err)) {
                        Ok(resp) => results.push(resp),
                        Err(err) => crate::log::error(&format!("Failed to marshal reply: {err}")),
                    }
                }

                // Process each batch entry individually.
                if !entries.is_empty() {
                    batch_size = entries.len();
                    for entry in entries {
                        match unmarshal_request(&entry) {
                            Err(err_text) => {
                                let json_err = RPCError::new(
                                    err_rpc_invalid_request().code,
                                    &format!("Invalid request: {err_text}"),
                                );
                                if let Some(resp) = created_or_logged(marshal_response(
                                    "",
                                    &RpcId::Null,
                                    None,
                                    Some(&json_err),
                                )) {
                                    results.push(resp);
                                }
                            }
                            Ok(req) => {
                                let param_refs: Vec<&str> =
                                    req.params.iter().map(|s| s.as_str()).collect();
                                if let Some(resp) = process_request(
                                    server,
                                    &req.jsonrpc,
                                    &req.method,
                                    &param_refs,
                                    &req.id,
                                    is_admin,
                                ) {
                                    results.push(resp);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut msg: Vec<u8> = Vec::new();
    if batched_request && batch_size > 0 && !results.is_empty() {
        // Form the batched response json.
        msg.push(b'[');
        for (idx, reply) in results.iter().enumerate() {
            msg.extend_from_slice(reply.as_bytes());
            if idx == results.len() - 1 {
                msg.push(b']');
            } else {
                msg.push(b',');
            }
        }
    }
    if (!batched_request || batch_size == 0) && !results.is_empty() {
        // Respond with the first results entry for single requests,
        // moved out rather than copied: nothing reads `results` after.
        msg = results.swap_remove(0).into_bytes();
    }

    // Terminate with a newline to maintain compatibility with Bitcoin
    // Core.
    msg.push(b'\n');
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's `convertNumber` runs an `interface{}` id through
    /// `strconv.ParseFloat`, which reports `ErrRange` for a magnitude
    /// past `float64` and fails the whole unmarshal.  Rust's
    /// `f64::from_str` instead returns `Ok(inf)`, which used to become
    /// an `RpcId::Float(inf)` that no formatter could render — a panic
    /// reachable by any credential, limited included.  The id must be
    /// rejected here with Go's exact text instead.
    #[test]
    fn an_out_of_range_id_is_a_parse_error_with_gos_text() {
        for (body, literal) in [
            (
                r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1e999}"#,
                "1e999",
            ),
            (
                r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":-1e999}"#,
                "-1e999",
            ),
            (r#"{"id":1e309}"#, "1e309"),
            (
                r#"{"id":  1.7976931348623159e308  }"#,
                "1.7976931348623159e308",
            ),
        ] {
            let err = unmarshal_request(body).expect_err("an infinite id must be rejected");
            assert_eq!(
                err,
                format!(
                    "json: cannot unmarshal number {literal} into Go struct field Request.id of \
                     type float64"
                ),
                "{body}"
            );
        }
    }

    /// Only the out-of-range ids are refused: everything Go accepts as
    /// an id still parses to the same value, including underflow to
    /// zero, which Go's `ParseFloat` reports no error for.
    #[test]
    fn in_range_ids_are_unchanged() {
        let cases: [(&str, RpcId); 6] = [
            (r#"{"id":1}"#, RpcId::Float(1.0)),
            (r#"{"id":-2.5}"#, RpcId::Float(-2.5)),
            (r#"{"id":1e308}"#, RpcId::Float(1e308)),
            (r#"{"id":1e-999}"#, RpcId::Float(0.0)),
            (r#"{"id":"abc"}"#, RpcId::Str("abc".to_string())),
            (r#"{"id":null}"#, RpcId::Null),
        ];
        for (body, want) in cases {
            let req = unmarshal_request(body).expect("a valid id");
            assert_eq!(req.id, want, "{body}");
        }
    }

    /// The first error in document order wins, as it does in Go, where
    /// `saveError` keeps only the earliest.
    #[test]
    fn an_earlier_field_error_still_wins_over_the_id() {
        let err = unmarshal_request(r#"{"method":5,"id":1e999}"#)
            .expect_err("the method type error comes first");
        assert_eq!(
            err,
            "json: cannot unmarshal number into Go struct field Request.method of type string"
        );
    }

    /// Go ignores a null for a string field (`decode.go:907`, "ignore
    /// null for primitives/string"), so an earlier duplicate key's value
    /// survives.  The port overwrote it with the empty string, turning a
    /// runnable request into "Invalid request: malformed".  Outputs from
    /// Go 1.26 `json.Unmarshal` into `dcrjson.Request`.
    #[test]
    fn a_null_string_field_keeps_the_earlier_duplicate() {
        let req = unmarshal_request(r#"{"method":"getblockcount","id":1,"method":null}"#)
            .expect("valid request");
        assert_eq!(req.method, "getblockcount");
        let req = unmarshal_request(r#"{"jsonrpc":"2.0","jsonrpc":null,"method":"x"}"#)
            .expect("valid request");
        assert_eq!(req.jsonrpc, "2.0");
        let req = unmarshal_request(r#"{"method":null}"#).expect("valid request");
        assert_eq!(req.method, "");
    }

    /// A later `"params": null` sets Go's slice back to nil, which the
    /// websocket batch arm tests as `req.Params == nil`; the port kept
    /// `params_present` from the earlier array.
    #[test]
    fn a_later_null_params_clears_the_earlier_array() {
        let req = unmarshal_request(r#"{"method":"x","params":[1],"params":null}"#).expect("valid");
        assert!(req.params.is_empty());
        assert!(!req.params_present, "Go leaves Params nil");

        let req = unmarshal_request(r#"{"method":"x","params":null,"params":[1]}"#).expect("valid");
        assert_eq!(req.params, vec!["1".to_string()]);
        assert!(req.params_present);
    }

    /// Go decodes an array or object id into `[]interface{}` or
    /// `map[string]interface{}`, running every nested number through
    /// `convertNumber`, so an out-of-range one fails the whole unmarshal
    /// with the id field's context -- the command never runs.  The port
    /// mapped any composite id straight to an invalid id and executed
    /// the command.
    #[test]
    fn an_out_of_range_number_nested_in_the_id_fails_the_unmarshal() {
        for (body, want) in [
            (
                r#"{"method":"stop","id":[1e999]}"#,
                "json: cannot unmarshal number 1e999 into Go struct field Request.id of type \
                 float64",
            ),
            (
                r#"{"method":"stop","id":{"a":[2,{"b":-1e400}]}}"#,
                "json: cannot unmarshal number -1e400 into Go struct field Request.id of type \
                 float64",
            ),
            (
                r#"{"method":"stop","id":[1e999],"params":5}"#,
                "json: cannot unmarshal number 1e999 into Go struct field Request.id of type \
                 float64",
            ),
            (
                r#"{"method":"stop","id":[1e999],"id":1}"#,
                "json: cannot unmarshal number 1e999 into Go struct field Request.id of type \
                 float64",
            ),
            // The first error in document order still wins.
            (
                r#"{"method":5,"id":[1e999]}"#,
                "json: cannot unmarshal number into Go struct field Request.method of type string",
            ),
        ] {
            assert_eq!(unmarshal_request(body).expect_err(body), want, "{body}");
        }

        // In-range and non-numeric members, including a number inside a
        // string and an underflow, leave the id merely invalid.
        for (body, kind) in [
            (
                r#"{"id":[1,"1e999","\"1e999",true,null,{"x":1e-999}]}"#,
                "[]interface {}",
            ),
            (r#"{"id":{"1e999":-2.5}}"#, "map[string]interface {}"),
        ] {
            let req = unmarshal_request(body).expect(body);
            assert_eq!(req.id, RpcId::Invalid(kind.to_string()), "{body}");
        }
    }
}
