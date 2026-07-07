// SPDX-License-Identifier: ISC
//! The HTTP-facing request surface of the RPC server (dcrd
//! internal/rpcserver `checkAuth`/`checkAuthMAC`/`checkAuthUserPass`
//! and the request-body processing inside `jsonRPCRead`): Basic auth
//! decisions over the HMAC'd credential strings, Go-faithful request
//! unmarshalling, and the single/batched response assembly.  The live
//! HTTP shell (listener setup, connection hijacking, and header
//! writing) arrives with the daemon.

// Scanner index arithmetic and base64 packing mirror Go.
#![allow(clippy::arithmetic_side_effects)]

use hmac::{Hmac, Mac};
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
    /// second whether the user is an admin (dcrd `checkAuthMAC`).
    pub fn check_auth_mac(&self, auth: &str) -> (bool, bool) {
        let mac = auth_mac(&self.hmac_key, auth.as_bytes());
        let cmp = ct_eq(&mac, &self.authsha);
        let limitcmp = ct_eq(&mac, &self.limitauthsha);
        if !cmp && !limitcmp {
            return (false, false);
        }
        (true, cmp)
    }

    /// Check a username and password by generating the corresponding
    /// HTTP Basic authentication string (dcrd `checkAuthUserPass`).
    pub fn check_auth_user_pass(&self, user: &str, pass: &str) -> (bool, bool) {
        let login = format!("{user}:{pass}");
        let auth = format!("Basic {}", base64_std_encode(login.as_bytes()));
        self.check_auth_mac(&auth)
    }

    /// Check the HTTP Basic authentication supplied with a request;
    /// the error only signals the auth failure (dcrd `checkAuth`).
    pub fn check_auth(
        &self,
        auth_header: Option<&str>,
        require: bool,
    ) -> Result<(bool, bool), String> {
        // If no RPC credentials are set this always succeeds (TLS
        // client certificates are being used for authentication).
        if self.authsha == [0u8; 32] && self.limitauthsha == [0u8; 32] {
            return Ok((true, true));
        }

        let Some(auth) = auth_header else {
            if require {
                return Err("auth failure".to_string());
            }
            return Ok((false, false));
        };

        let (authed, is_admin) = self.check_auth_mac(auth);
        if !authed {
            return Err("auth failure".to_string());
        }
        Ok((authed, is_admin))
    }
}

/// A JSON-RPC request unmarshalled from a raw body exactly like Go's
/// `json.Unmarshal` into `dcrjson.Request`.
pub struct RawRequest {
    /// The JSON-RPC protocol version.
    pub jsonrpc: String,
    /// The requested method.
    pub method: String,
    /// The raw JSON texts of the parameters.
    pub params: Vec<String>,
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
fn split_raw_array(data: &str) -> Vec<String> {
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
        let key = member[1..end].to_string();
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
        id: RpcId::Null,
    };
    for (key, raw) in split_raw_object(trimmed) {
        // Go matches JSON keys to struct fields case-insensitively.
        if key.eq_ignore_ascii_case("jsonrpc") || key.eq_ignore_ascii_case("method") {
            let value = match gojson::decode(&dcroxide_dcrjson::GoType::String, &raw) {
                Ok(dcroxide_dcrjson::GoValue::String(s)) => s,
                Ok(_) => String::new(), // null leaves the field zeroed
                Err(_) => {
                    let field = if key.eq_ignore_ascii_case("jsonrpc") {
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
            if key.eq_ignore_ascii_case("jsonrpc") {
                req.jsonrpc = value;
            } else {
                req.method = value;
            }
        } else if key.eq_ignore_ascii_case("params") {
            match raw.as_bytes().first() {
                Some(b'[') => req.params = split_raw_array(&raw),
                Some(b'n') => req.params = Vec::new(),
                _ => {
                    return Err(format!(
                        "json: cannot unmarshal {} into Go struct field Request.params of type \
                         []json.RawMessage",
                        json_value_kind(&raw)
                    ));
                }
            }
        } else if key.eq_ignore_ascii_case("id") {
            // Go unmarshals into interface{}: numbers become float64,
            // strings and null map directly, and every other kind is
            // rejected later by the response id validity check.
            req.id = match raw.as_bytes().first() {
                Some(b'"') => match gojson::decode(&dcroxide_dcrjson::GoType::String, &raw) {
                    Ok(dcroxide_dcrjson::GoValue::String(s)) => RpcId::Str(s),
                    _ => RpcId::Invalid("string".to_string()),
                },
                Some(b'n') => RpcId::Null,
                Some(b't') | Some(b'f') => RpcId::Invalid("bool".to_string()),
                Some(b'[') => RpcId::Invalid("[]interface {}".to_string()),
                Some(b'{') => RpcId::Invalid("map[string]interface {}".to_string()),
                _ => RpcId::Float(raw.trim().parse().unwrap_or(0.0)),
            };
        }
    }
    Ok(req)
}

/// Process a JSON-RPC request body and return the full response body
/// including the Bitcoin Core compatibility newline (the request
/// handling inside dcrd `jsonRPCRead`; the connection hijacking and
/// read-limit plumbing arrive with the daemon).
pub fn process_body<C: RpcChain>(server: &mut Server<C>, body: &str, is_admin: bool) -> Vec<u8> {
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
                marshal_response("1.0", &RpcId::Null, None, Some(&json_err)).ok()
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
                if let Ok(resp) = marshal_response("2.0", &RpcId::Null, None, Some(&json_err)) {
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
                    if let Ok(resp) = marshal_response("2.0", &RpcId::Null, None, Some(&json_err)) {
                        results.push(resp);
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
                                if let Ok(resp) =
                                    marshal_response("", &RpcId::Null, None, Some(&json_err))
                                {
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
        // Respond with the first results entry for single requests.
        msg = results[0].clone().into_bytes();
    }

    // Terminate with a newline to maintain compatibility with Bitcoin
    // Core.
    msg.push(b'\n');
    msg
}
