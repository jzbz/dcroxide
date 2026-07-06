// SPDX-License-Identifier: ISC
//! PEM encoding matching Go's `encoding/pem` output.

// Bounded chunk arithmetic.
#![allow(clippy::arithmetic_side_effects)]

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_std(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Encode a PEM block exactly as Go's `pem.Encode` does: 64-column
/// base64 lines between BEGIN/END markers, each line ending with a
/// newline.
pub fn encode(block_type: &str, der: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(block_type);
    out.push_str("-----\n");
    let b64 = base64_std(der);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).expect("ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(block_type);
    out.push_str("-----\n");
    out.into_bytes()
}
