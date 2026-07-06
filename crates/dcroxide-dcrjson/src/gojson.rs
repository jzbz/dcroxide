// SPDX-License-Identifier: ISC
//! JSON encoding and decoding with Go `encoding/json` semantics.
//!
//! dcrjson's observable output is produced by Go's `encoding/json`
//! package, whose behavior differs from common Rust JSON libraries in
//! ways that matter for byte-for-byte parity: HTML-unsafe characters
//! are escaped (`<`, `>`, `&` become `<` etc.), floats use Go's
//! shortest-round-trip formatting with an exponent-form cutoff and an
//! `e-0X` cleanup, map keys are sorted bytewise, struct fields honor
//! `json` tags in declaration order, and decode errors carry Go's
//! exact message text.  This module reimplements that behavior over
//! [`GoType`]/[`GoValue`] trees.

// Bounded index arithmetic over scanned buffers mirrors Go.
#![allow(clippy::arithmetic_side_effects)]
// Range comparisons are written in the exact shape of the Go source
// they port so they can be checked against it side by side.
#![allow(clippy::manual_range_contains)]
// The strconv-style parsers discard Go's error contents because no
// caller observes them, matching assignField's err != nil checks.
#![allow(clippy::result_unit_err)]

use crate::gotype::{GoType, GoValue, Kind, resolve};

// ---------------------------------------------------------------------
// Float formatting.
// ---------------------------------------------------------------------

/// Decompose a float's shortest-round-trip representation into its
/// negative flag, decimal digits, and decimal point position (the
/// number of digits before the decimal point; may be negative or
/// exceed the digit count).
fn shortest_digits(repr: String) -> (bool, String, i32) {
    // `format!("{:e}")` yields `d.ddd...e<exp>` (shortest digits).
    let neg = repr.starts_with('-');
    let s = repr.trim_start_matches('-');
    let (mantissa, exp) = s.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exp digits");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    // Strip trailing zeros; the mantissa of a shortest form has none,
    // except the plain "0".
    (neg, digits, exp + 1)
}

/// Render the `%f`-style form from digits and decimal point position
/// (Go `strconv` `fmtF` with shortest digits).
fn fmt_f(neg: bool, digits: &str, dp: i32) -> String {
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if dp <= 0 {
        out.push_str("0.");
        for _ in 0..(-dp) {
            out.push('0');
        }
        out.push_str(digits);
    } else {
        let dp = dp as usize;
        if dp >= digits.len() {
            out.push_str(digits);
            for _ in 0..(dp - digits.len()) {
                out.push('0');
            }
        } else {
            out.push_str(&digits[..dp]);
            out.push('.');
            out.push_str(&digits[dp..]);
        }
    }
    out
}

/// Render the `%e`-style form from digits and decimal point position
/// (Go `strconv` `fmtE` with shortest digits: two-digit minimum
/// exponent with an explicit sign).
fn fmt_e(neg: bool, digits: &str, dp: i32) -> String {
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let mut chars = digits.chars();
    out.push(chars.next().unwrap_or('0'));
    let rest: String = chars.collect();
    if !rest.is_empty() {
        out.push('.');
        out.push_str(&rest);
    }
    out.push('e');
    let exp = dp - 1;
    if exp < 0 {
        out.push('-');
    } else {
        out.push('+');
    }
    let abs = exp.unsigned_abs();
    if abs < 10 {
        out.push('0');
    }
    out.push_str(&abs.to_string());
    out
}

fn format_float_json_parts(neg: bool, digits: String, dp: i32, use_e: bool) -> String {
    if use_e {
        let mut s = fmt_e(neg, &digits, dp);
        // Go's encoding/json cleans up e-09 to e-9.
        let b = s.as_bytes();
        let n = b.len();
        if n >= 4 && b[n - 4] == b'e' && b[n - 3] == b'-' && b[n - 2] == b'0' {
            let last = b[n - 1] as char;
            s.truncate(n - 2);
            s.push(last);
        }
        s
    } else {
        fmt_f(neg, &digits, dp)
    }
}

/// Format a `float64` exactly as Go's `encoding/json` does.
pub fn format_float_json(v: f64) -> String {
    let abs = v.abs();
    let use_e = abs != 0.0 && (abs < 1e-6 || abs >= 1e21);
    let (neg, digits, dp) = shortest_digits(format!("{v:e}"));
    format_float_json_parts(neg, digits, dp, use_e)
}

/// Format a `float32` exactly as Go's `encoding/json` does.
pub fn format_float_json32(v: f32) -> String {
    let abs = v.abs();
    let use_e = abs != 0.0 && (abs < 1e-6 || abs >= 1e21);
    let (neg, digits, dp) = shortest_digits(format!("{v:e}"));
    format_float_json_parts(neg, digits, dp, use_e)
}

/// Format a `float64` like Go's `fmt` verb `%v` (shortest `%g`).
pub fn format_float_g(v: f64) -> String {
    let (neg, digits, dp) = shortest_digits(format!("{v:e}"));
    let exp = dp - 1;
    if exp < -4 || exp >= 6 {
        fmt_e(neg, &digits, dp)
    } else {
        fmt_f(neg, &digits, dp)
    }
}

/// Format a `float32` like Go's `fmt` verb `%v` (shortest `%g`).
pub fn format_float_g32(v: f32) -> String {
    let (neg, digits, dp) = shortest_digits(format!("{v:e}"));
    let exp = dp - 1;
    if exp < -4 || exp >= 6 {
        fmt_e(neg, &digits, dp)
    } else {
        fmt_f(neg, &digits, dp)
    }
}

// ---------------------------------------------------------------------
// String quoting.
// ---------------------------------------------------------------------

/// Append a JSON string with Go `encoding/json` escaping (HTML-unsafe
/// characters and U+2028/U+2029 escaped; other valid UTF-8 emitted
/// verbatim).
pub fn append_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Quote a string like Go's `strconv.Quote` (the `%q` verb) for the
/// ASCII shapes that appear in dcrjson messages and usage text.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Quote a character like Go's json scanner `quoteChar` helper.
fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".to_string(),
        b'"' => "'\"'".to_string(),
        c if (0x20..0x7f).contains(&c) => format!("'{}'", c as char),
        c => {
            // Go quotes the rune and swaps the quote characters.
            let q = format!("{:?}", c as char); // e.g. '\u{1}'
            let _ = q;
            format!("'\\x{c:02x}'")
        }
    }
}

// ---------------------------------------------------------------------
// Go strconv parsers.
// ---------------------------------------------------------------------

/// Parse a boolean like Go's `strconv.ParseBool`.
pub fn go_parse_bool(s: &str) -> Result<bool, ()> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(()),
    }
}

/// Whether the underscores in a Go numeric literal are syntactically
/// valid (Go `strconv` `underscoreOK`).
fn underscore_ok(s: &str) -> bool {
    let mut saw = '^';
    let mut b = s.as_bytes();
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        b = &b[1..];
    }
    let mut hex = false;
    if b.len() >= 2
        && b[0] == b'0'
        && (b[1] == b'x'
            || b[1] == b'X'
            || b[1] == b'o'
            || b[1] == b'O'
            || b[1] == b'b'
            || b[1] == b'B')
    {
        saw = '0';
        hex = b[1] == b'x' || b[1] == b'X';
        b = &b[2..];
    }
    for &c in b {
        if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
            saw = '0';
            continue;
        }
        if c == b'_' {
            if saw != '0' {
                return false;
            }
            saw = '_';
            continue;
        }
        if saw == '_' {
            return false;
        }
        saw = '!';
    }
    saw != '_'
}

/// Parse a signed integer like Go's `strconv.ParseInt(s, 0, 64)`.
pub fn go_parse_int(s: &str) -> Result<i64, ()> {
    if s.is_empty() {
        return Err(());
    }
    let neg = s.starts_with('-');
    let mag = go_parse_uint_mag(s.trim_start_matches(['+', '-']), s)?;
    if neg {
        if mag > (i64::MAX as u64) + 1 {
            return Err(());
        }
        Ok((mag as i64).wrapping_neg())
    } else {
        if mag > i64::MAX as u64 {
            return Err(());
        }
        Ok(mag as i64)
    }
}

/// Parse an unsigned integer like Go's `strconv.ParseUint(s, 0, 64)`.
pub fn go_parse_uint(s: &str) -> Result<u64, ()> {
    if s.starts_with(['+', '-']) {
        return Err(());
    }
    go_parse_uint_mag(s, s)
}

/// Parse the magnitude of an integer literal with base detection and
/// underscore rules (base 0 semantics).  `full` is the original string
/// including any sign, used for the underscore validity check.
fn go_parse_uint_mag(s: &str, full: &str) -> Result<u64, ()> {
    if s.is_empty() || (s.len() > 1 && s.starts_with(['+', '-'])) {
        return Err(());
    }
    let has_underscore = full.contains('_');
    if has_underscore && !underscore_ok(full) {
        return Err(());
    }
    let (base, digits) = if s.len() >= 2 && s.starts_with('0') {
        match s.as_bytes()[1] {
            b'x' | b'X' => (16u32, &s[2..]),
            b'o' | b'O' => (8u32, &s[2..]),
            b'b' | b'B' => (2u32, &s[2..]),
            _ => (8u32, &s[1..]),
        }
    } else {
        (10u32, s)
    };
    let digits: String = if has_underscore {
        digits.chars().filter(|c| *c != '_').collect()
    } else {
        digits.to_string()
    };
    if digits.is_empty() {
        // "0" reaches here with base 8 and no remaining digits.
        if s == "0" {
            return Ok(0);
        }
        return Err(());
    }
    let mut n: u64 = 0;
    for c in digits.chars() {
        let d = c.to_digit(base).ok_or(())?;
        n = n.checked_mul(base as u64).ok_or(())?;
        n = n.checked_add(d as u64).ok_or(())?;
    }
    Ok(n)
}

/// Parse a float like Go's `strconv.ParseFloat(s, 64)`, including the
/// special names, underscores, and range errors.
pub fn go_parse_float(s: &str) -> Result<f64, ()> {
    if s.is_empty() {
        return Err(());
    }
    let lower = s.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    let neg = lower.starts_with('-');
    if body == "inf" || body == "infinity" {
        return Ok(if neg {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    if body == "nan" {
        if lower.starts_with(['+', '-']) {
            return Err(());
        }
        return Ok(f64::NAN);
    }
    if s.contains('_') && !underscore_ok(s) {
        return Err(());
    }
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    if cleaned.to_ascii_lowercase().contains("0x") {
        return go_parse_hex_float(&cleaned);
    }
    // Reject shapes Rust accepts but Go does not, and vice versa: Go
    // requires digits around the exponent and accepts a trailing or
    // leading dot ("1." and ".5" are valid Go floats, as in Rust).
    let v: f64 = cleaned.parse().map_err(|_| ())?;
    if v.is_infinite() {
        // Finite literal overflowed: Go returns ErrRange.
        return Err(());
    }
    Ok(v)
}

/// Parse a hexadecimal float literal (Go `0x1.8p3` forms).
fn go_parse_hex_float(s: &str) -> Result<f64, ()> {
    let neg = s.starts_with('-');
    let body = s.trim_start_matches(['+', '-']);
    let lower = body.to_ascii_lowercase();
    let rest = lower.strip_prefix("0x").ok_or(())?;
    let (mant, exp) = match rest.split_once('p') {
        Some((m, e)) => (m, e.parse::<i32>().map_err(|_| ())?),
        None => return Err(()), // Go requires a 'p' exponent.
    };
    let (int_part, frac_part) = match mant.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mant, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(());
    }
    let mut value: f64 = 0.0;
    for c in int_part.chars() {
        value = value * 16.0 + c.to_digit(16).ok_or(())? as f64;
    }
    let mut scale = 1.0f64 / 16.0;
    for c in frac_part.chars() {
        value += c.to_digit(16).ok_or(())? as f64 * scale;
        scale /= 16.0;
    }
    let v = value * 2f64.powi(exp) * if neg { -1.0 } else { 1.0 };
    if v.is_infinite() {
        return Err(());
    }
    Ok(v)
}

// ---------------------------------------------------------------------
// Encoding.
// ---------------------------------------------------------------------

/// Encode a typed value to JSON exactly as Go's `json.Marshal` does.
pub fn encode(typ: &GoType, val: &GoValue) -> String {
    let mut out = String::new();
    encode_into(typ, val, &mut out);
    out
}

fn encode_into(typ: &GoType, val: &GoValue, out: &mut String) {
    // A raw value stands in for a custom json.Marshaler and is
    // embedded verbatim regardless of the declared type.
    if let GoValue::Raw(raw) = val {
        out.push_str(raw);
        return;
    }
    let rt = resolve(typ);
    match rt {
        GoType::Ptr(elem) => match val {
            GoValue::Null => out.push_str("null"),
            v => encode_into(elem, v, out),
        },
        GoType::Bool => match val {
            GoValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            _ => out.push_str("false"),
        },
        GoType::Int | GoType::Int8 | GoType::Int16 | GoType::Int32 | GoType::Int64 => match val {
            GoValue::Int(i) => out.push_str(&i.to_string()),
            _ => out.push('0'),
        },
        GoType::Uint | GoType::Uint8 | GoType::Uint16 | GoType::Uint32 | GoType::Uint64 => {
            match val {
                GoValue::Uint(u) => out.push_str(&u.to_string()),
                _ => out.push('0'),
            }
        }
        GoType::Float32 => match val {
            GoValue::Float32(f) => out.push_str(&format_float_json32(*f)),
            _ => out.push('0'),
        },
        GoType::Float64 => match val {
            GoValue::Float64(f) => out.push_str(&format_float_json(*f)),
            _ => out.push('0'),
        },
        GoType::String => match val {
            GoValue::String(s) => append_json_string(out, s),
            _ => out.push_str("\"\""),
        },
        GoType::Slice(elem) => match val {
            GoValue::Null => out.push_str("null"),
            GoValue::Array(items) => {
                if resolve(elem).kind() == Kind::Uint8 {
                    // Go marshals []byte as base64.
                    let bytes: Vec<u8> = items
                        .iter()
                        .map(|v| match v {
                            GoValue::Uint(u) => *u as u8,
                            _ => 0,
                        })
                        .collect();
                    append_json_string(out, &base64_std(&bytes));
                    return;
                }
                encode_seq(elem, items, out);
            }
            _ => out.push_str("null"),
        },
        GoType::Array(_, elem) => match val {
            GoValue::Array(items) => encode_seq(elem, items, out),
            _ => out.push_str("[]"),
        },
        GoType::Map(_, velem) => match val {
            GoValue::Null => out.push_str("null"),
            GoValue::Map(entries) => {
                let mut sorted: Vec<&(String, GoValue)> = entries.iter().collect();
                sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                out.push('{');
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    append_json_string(out, k);
                    out.push(':');
                    encode_into(velem, v, out);
                }
                out.push('}');
            }
            _ => out.push_str("null"),
        },
        GoType::Struct(fields) => match val {
            GoValue::Struct(values) => {
                out.push('{');
                let mut first = true;
                for (f, v) in fields.iter().zip(values.iter()) {
                    if f.unexported {
                        continue;
                    }
                    let (name, omitempty) = json_field_name(f);
                    let Some(name) = name else { continue };
                    if omitempty && is_empty_value(&f.typ, v) {
                        continue;
                    }
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    append_json_string(out, name);
                    out.push(':');
                    encode_into(&f.typ, v, out);
                }
                out.push('}');
            }
            _ => out.push_str("{}"),
        },
        _ => out.push_str("null"),
    }
}

fn encode_seq(elem: &GoType, items: &[GoValue], out: &mut String) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_into(elem, item, out);
    }
    out.push(']');
}

/// The effective JSON field name and omitempty flag for a struct
/// field; `None` when the field is skipped (tag `-`).
fn json_field_name(f: &crate::gotype::StructField) -> (Option<&str>, bool) {
    match &f.json_tag {
        Some(tag) => {
            let mut parts = tag.split(',');
            let name = parts.next().unwrap_or("");
            if name == "-" && tag == "-" {
                return (None, false);
            }
            let omitempty = parts.any(|p| p == "omitempty");
            if name.is_empty() {
                (Some(f.name.as_str()), omitempty)
            } else {
                (Some(name), omitempty)
            }
        }
        None => (Some(f.name.as_str()), false),
    }
}

/// Go `encoding/json` `isEmptyValue`.
fn is_empty_value(typ: &GoType, val: &GoValue) -> bool {
    match typ.kind() {
        Kind::Bool => matches!(val, GoValue::Bool(false)),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            matches!(val, GoValue::Int(0))
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 => {
            matches!(val, GoValue::Uint(0))
        }
        Kind::Float32 => matches!(val, GoValue::Float32(f) if *f == 0.0),
        Kind::Float64 => matches!(val, GoValue::Float64(f) if *f == 0.0),
        Kind::String => matches!(val, GoValue::String(s) if s.is_empty()),
        Kind::Ptr => matches!(val, GoValue::Null),
        Kind::Slice | Kind::Map => match val {
            GoValue::Null => true,
            GoValue::Array(items) => items.is_empty(),
            GoValue::Map(entries) => entries.is_empty(),
            _ => false,
        },
        Kind::Array => matches!(val, GoValue::Array(items) if items.is_empty()),
        _ => false,
    }
}

/// Standard base64 with padding (Go `base64.StdEncoding`).
fn base64_std(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

// ---------------------------------------------------------------------
// Decoding.
// ---------------------------------------------------------------------

/// An error from Go-semantics JSON decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// A syntax error with Go's `json.SyntaxError` message.
    Syntax(String),
    /// A type mismatch with the JSON value description and the Go type
    /// the value could not be stored into (Go `json.UnmarshalTypeError`).
    Type {
        /// Description of the offending JSON value, e.g. `string` or
        /// `number 128`.
        value: String,
        /// Display form of the Go type that could not accept it.
        type_display: String,
    },
}

impl JsonError {
    /// The message as printed by Go's error `Error` method.
    pub fn go_message(&self) -> String {
        match self {
            JsonError::Syntax(msg) => msg.clone(),
            JsonError::Type {
                value,
                type_display,
            } => {
                format!("json: cannot unmarshal {value} into Go value of type {type_display}")
            }
        }
    }
}

struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
}

const UNEXPECTED_END: &str = "unexpected end of JSON input";

impl<'a> Scanner<'a> {
    fn new(data: &'a [u8]) -> Scanner<'a> {
        Scanner { data, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.data.len()
            && matches!(self.data[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn syntax(msg: String) -> JsonError {
        JsonError::Syntax(msg)
    }

    /// Validate one JSON value starting at the current position,
    /// producing Go scanner messages on malformed input.
    fn check_value(&mut self) -> Result<(), JsonError> {
        self.skip_ws();
        let Some(c) = self.peek() else {
            return Err(Self::syntax(UNEXPECTED_END.to_string()));
        };
        match c {
            b'{' => self.check_object(),
            b'[' => self.check_array(),
            b'"' => self.check_string(),
            b't' => self.check_literal("true"),
            b'f' => self.check_literal("false"),
            b'n' => self.check_literal("null"),
            b'-' | b'0'..=b'9' => self.check_number(),
            c => Err(Self::syntax(format!(
                "invalid character {} looking for beginning of value",
                quote_char(c)
            ))),
        }
    }

    fn check_literal(&mut self, lit: &str) -> Result<(), JsonError> {
        for (i, want) in lit.bytes().enumerate() {
            match self.data.get(self.pos + i) {
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
                Some(&got) if got != want => {
                    return Err(Self::syntax(format!(
                        "invalid character {} in literal {} (expecting {})",
                        quote_char(got),
                        lit,
                        quote_char(want),
                    )));
                }
                _ => {}
            }
        }
        self.pos += lit.len();
        Ok(())
    }

    fn check_string(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // opening quote
        loop {
            let Some(c) = self.peek() else {
                return Err(Self::syntax(UNEXPECTED_END.to_string()));
            };
            self.pos += 1;
            match c {
                b'"' => return Ok(()),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err(Self::syntax(UNEXPECTED_END.to_string()));
                    };
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let Some(h) = self.peek() else {
                                    return Err(Self::syntax(UNEXPECTED_END.to_string()));
                                };
                                if !h.is_ascii_hexdigit() {
                                    return Err(Self::syntax(format!(
                                        "invalid character {} in \\u hexadecimal character escape",
                                        quote_char(h)
                                    )));
                                }
                                self.pos += 1;
                            }
                        }
                        c => {
                            return Err(Self::syntax(format!(
                                "invalid character {} in string escape code",
                                quote_char(c)
                            )));
                        }
                    }
                }
                c if c < 0x20 => {
                    return Err(Self::syntax(format!(
                        "invalid character {} in string literal",
                        quote_char(c)
                    )));
                }
                _ => {}
            }
        }
    }

    fn check_number(&mut self) -> Result<(), JsonError> {
        // The value grammar guarantees the first byte is '-' or a
        // digit.
        if self.peek() == Some(b'-') {
            self.pos += 1;
            match self.peek() {
                Some(c) if c.is_ascii_digit() => {}
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} in numeric literal",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else {
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            match self.peek() {
                Some(c) if c.is_ascii_digit() => {
                    while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} after decimal point in numeric literal",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            match self.peek() {
                Some(c) if c.is_ascii_digit() => {
                    while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} in exponent of numeric literal",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
        }
        Ok(())
    }

    fn check_array(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.check_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} after array element",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
        }
    }

    fn check_object(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // '{'
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'"') => self.check_string()?,
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} looking for beginning of object key string",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
            self.skip_ws();
            match self.peek() {
                Some(b':') => {
                    self.pos += 1;
                }
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} after object key",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
            self.check_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(c) => {
                    return Err(Self::syntax(format!(
                        "invalid character {} after object key:value pair",
                        quote_char(c)
                    )));
                }
                None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
            }
        }
    }
}

/// Validate an entire JSON document like Go's `json.Unmarshal` does
/// before decoding (`checkValid`).
pub fn validate(data: &str) -> Result<(), JsonError> {
    let mut sc = Scanner::new(data.as_bytes());
    sc.check_value()?;
    sc.skip_ws();
    if let Some(c) = sc.peek() {
        return Err(JsonError::Syntax(format!(
            "invalid character {} after top-level value",
            quote_char(c)
        )));
    }
    Ok(())
}

/// A raw JSON token produced by the reader used during decoding.
enum Token<'a> {
    Null,
    Bool(bool),
    Number(&'a str),
    String(String),
    ArrayStart,
    ObjectStart,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.data.len()
            && matches!(self.data[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Read the next token (input is known valid).
    fn next_token(&mut self) -> Token<'a> {
        self.skip_ws();
        match self.peek().expect("validated") {
            b'{' => {
                self.pos += 1;
                Token::ObjectStart
            }
            b'[' => {
                self.pos += 1;
                Token::ArrayStart
            }
            b'"' => Token::String(self.read_string()),
            b't' => {
                self.pos += 4;
                Token::Bool(true)
            }
            b'f' => {
                self.pos += 5;
                Token::Bool(false)
            }
            b'n' => {
                self.pos += 4;
                Token::Null
            }
            _ => {
                let start = self.pos;
                while let Some(c) = self.peek() {
                    if matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') || c.is_ascii_digit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Token::Number(core::str::from_utf8(&self.data[start..self.pos]).expect("utf8"))
            }
        }
    }

    fn read_string(&mut self) -> String {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = self.data[self.pos];
            self.pos += 1;
            match c {
                b'"' => return out,
                b'\\' => {
                    let esc = self.data[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex =
                                core::str::from_utf8(&self.data[self.pos..self.pos + 4]).unwrap();
                            self.pos += 4;
                            let mut cp = u32::from_str_radix(hex, 16).unwrap();
                            // Surrogate pair handling.
                            if (0xd800..0xdc00).contains(&cp)
                                && self.data.get(self.pos) == Some(&b'\\')
                                && self.data.get(self.pos + 1) == Some(&b'u')
                            {
                                let hex2 =
                                    core::str::from_utf8(&self.data[self.pos + 2..self.pos + 6])
                                        .unwrap();
                                let lo = u32::from_str_radix(hex2, 16).unwrap();
                                if (0xdc00..0xe000).contains(&lo) {
                                    self.pos += 6;
                                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                                }
                            }
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => unreachable!("validated escape"),
                    }
                }
                c if c < 0x80 => out.push(c as char),
                _ => {
                    // Multi-byte UTF-8: copy the full character.
                    let s = core::str::from_utf8(&self.data[self.pos - 1..]).expect("utf8");
                    let ch = s.chars().next().expect("char");
                    out.push(ch);
                    self.pos += ch.len_utf8() - 1;
                }
            }
        }
    }

    /// Skip one complete value (used when the target ignores it).
    fn skip_value(&mut self) {
        match self.next_token() {
            Token::ArrayStart => {
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return;
                }
                loop {
                    self.skip_value();
                    self.skip_ws();
                    if self.peek() == Some(b',') {
                        self.pos += 1;
                    } else {
                        self.pos += 1; // ']'
                        return;
                    }
                }
            }
            Token::ObjectStart => {
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return;
                }
                loop {
                    self.next_token(); // key
                    self.skip_ws();
                    self.pos += 1; // ':'
                    self.skip_value();
                    self.skip_ws();
                    if self.peek() == Some(b',') {
                        self.pos += 1;
                    } else {
                        self.pos += 1; // '}'
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Decode a JSON document into a value of the given type with Go
/// `json.Unmarshal` semantics.  The input is validated first, exactly
/// as Go does, so syntax errors take precedence over type errors.
pub fn decode(typ: &GoType, data: &str) -> Result<GoValue, JsonError> {
    validate(data)?;
    let mut r = Reader {
        data: data.as_bytes(),
        pos: 0,
    };
    let mut val = GoValue::zero(typ);
    decode_value(typ, &mut r, &mut val)?;
    Ok(val)
}

fn type_error(value: &str, typ: &GoType) -> JsonError {
    JsonError::Type {
        value: value.to_string(),
        type_display: typ.display(),
    }
}

fn decode_value(typ: &GoType, r: &mut Reader<'_>, out: &mut GoValue) -> Result<(), JsonError> {
    let rt = resolve(typ);
    if let GoType::Ptr(elem) = rt {
        // Peek for null, which sets the pointer to nil.
        let save = r.pos;
        if matches!(r.next_token(), Token::Null) {
            *out = GoValue::Null;
            return Ok(());
        }
        r.pos = save;
        let mut inner = GoValue::zero(elem);
        decode_value(elem, r, &mut inner)?;
        *out = inner;
        return Ok(());
    }
    let save = r.pos;
    let tok = r.next_token();
    match tok {
        Token::Null => {
            // null is ignored for non-pointer scalars and zeroes
            // slices and maps.
            if matches!(rt.kind(), Kind::Slice | Kind::Map) {
                *out = GoValue::Null;
            }
            Ok(())
        }
        Token::Bool(b) => match rt.kind() {
            Kind::Bool => {
                *out = GoValue::Bool(b);
                Ok(())
            }
            _ => Err(type_error("bool", typ)),
        },
        Token::Number(s) => decode_number(typ, s, out),
        Token::String(s) => match rt.kind() {
            Kind::String => {
                *out = GoValue::String(s);
                Ok(())
            }
            Kind::Slice if resolve(rt.elem()).kind() == Kind::Uint8 => {
                let bytes = base64_decode_std(&s).ok_or_else(|| type_error("string", typ))?;
                *out = GoValue::Array(bytes.into_iter().map(|b| GoValue::Uint(b as u64)).collect());
                Ok(())
            }
            _ => Err(type_error("string", typ)),
        },
        Token::ArrayStart => {
            r.pos = save;
            decode_array(typ, r, out)
        }
        Token::ObjectStart => {
            r.pos = save;
            decode_object(typ, r, out)
        }
    }
}

fn decode_number(typ: &GoType, s: &str, out: &mut GoValue) -> Result<(), JsonError> {
    match typ.kind() {
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            let n: i64 = if s.bytes().all(|c| c.is_ascii_digit() || c == b'-') {
                s.parse()
                    .map_err(|_| type_error(&format!("number {s}"), typ))?
            } else {
                return Err(type_error(&format!("number {s}"), typ));
            };
            if overflow_int(typ.kind(), n) {
                return Err(type_error(&format!("number {s}"), typ));
            }
            *out = GoValue::Int(n);
            Ok(())
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 => {
            let n: u64 = if s.bytes().all(|c| c.is_ascii_digit()) {
                s.parse()
                    .map_err(|_| type_error(&format!("number {s}"), typ))?
            } else {
                return Err(type_error(&format!("number {s}"), typ));
            };
            if overflow_uint(typ.kind(), n) {
                return Err(type_error(&format!("number {s}"), typ));
            }
            *out = GoValue::Uint(n);
            Ok(())
        }
        Kind::Float64 => {
            let f: f64 = s
                .parse()
                .map_err(|_| type_error(&format!("number {s}"), typ))?;
            if f.is_infinite() {
                return Err(type_error(&format!("number {s}"), typ));
            }
            *out = GoValue::Float64(f);
            Ok(())
        }
        Kind::Float32 => {
            let f: f32 = s
                .parse()
                .map_err(|_| type_error(&format!("number {s}"), typ))?;
            if f.is_infinite() {
                return Err(type_error(&format!("number {s}"), typ));
            }
            *out = GoValue::Float32(f);
            Ok(())
        }
        _ => Err(type_error("number", typ)),
    }
}

/// Go `reflect.Value.OverflowInt` for the given kind.
pub fn overflow_int(kind: Kind, n: i64) -> bool {
    let bits = match kind {
        Kind::Int8 => 8,
        Kind::Int16 => 16,
        Kind::Int32 => 32,
        _ => 64,
    };
    if bits == 64 {
        return false;
    }
    let trunc = (n << (64 - bits)) >> (64 - bits);
    trunc != n
}

/// Go `reflect.Value.OverflowUint` for the given kind.
pub fn overflow_uint(kind: Kind, n: u64) -> bool {
    let bits = match kind {
        Kind::Uint8 => 8,
        Kind::Uint16 => 16,
        Kind::Uint32 => 32,
        _ => 64,
    };
    if bits == 64 {
        return false;
    }
    let trunc = (n << (64 - bits)) >> (64 - bits);
    trunc != n
}

fn decode_array(typ: &GoType, r: &mut Reader<'_>, out: &mut GoValue) -> Result<(), JsonError> {
    let rt = resolve(typ);
    let (elem, fixed) = match rt {
        GoType::Slice(e) => (e.as_ref(), None),
        GoType::Array(n, e) => (e.as_ref(), Some(*n)),
        _ => {
            r.skip_value();
            return Err(type_error("array", typ));
        }
    };
    r.next_token(); // '['
    let mut items = Vec::new();
    r.skip_ws();
    if r.peek() == Some(b']') {
        r.pos += 1;
    } else {
        loop {
            let mut v = GoValue::zero(elem);
            match fixed {
                Some(n) if items.len() >= n => r.skip_value(),
                _ => decode_value(elem, r, &mut v)?,
            }
            items.push(v);
            r.skip_ws();
            if r.peek() == Some(b',') {
                r.pos += 1;
            } else {
                r.pos += 1; // ']'
                break;
            }
        }
    }
    if let Some(n) = fixed {
        items.truncate(n);
        while items.len() < n {
            items.push(GoValue::zero(elem));
        }
    }
    *out = GoValue::Array(items);
    Ok(())
}

fn decode_object(typ: &GoType, r: &mut Reader<'_>, out: &mut GoValue) -> Result<(), JsonError> {
    let rt = resolve(typ);
    match rt {
        GoType::Map(_, velem) => {
            r.next_token(); // '{'
            let mut entries: Vec<(String, GoValue)> = Vec::new();
            r.skip_ws();
            if r.peek() == Some(b'}') {
                r.pos += 1;
            } else {
                loop {
                    let key = match r.next_token() {
                        Token::String(s) => s,
                        _ => unreachable!("validated"),
                    };
                    r.skip_ws();
                    r.pos += 1; // ':'
                    let mut v = GoValue::zero(velem);
                    decode_value(velem, r, &mut v)?;
                    if let Some(slot) = entries.iter_mut().find(|(k, _)| *k == key) {
                        slot.1 = v;
                    } else {
                        entries.push((key, v));
                    }
                    r.skip_ws();
                    if r.peek() == Some(b',') {
                        r.pos += 1;
                    } else {
                        r.pos += 1; // '}'
                        break;
                    }
                }
            }
            *out = GoValue::Map(entries);
            Ok(())
        }
        GoType::Struct(fields) => {
            r.next_token(); // '{'
            let mut values = match core::mem::replace(out, GoValue::Null) {
                GoValue::Struct(v) => v,
                _ => fields.iter().map(|f| GoValue::zero(&f.typ)).collect(),
            };
            r.skip_ws();
            if r.peek() == Some(b'}') {
                r.pos += 1;
            } else {
                loop {
                    let key = match r.next_token() {
                        Token::String(s) => s,
                        _ => unreachable!("validated"),
                    };
                    r.skip_ws();
                    r.pos += 1; // ':'
                    // Field matching: exact effective-name match wins,
                    // otherwise the first ASCII-case-insensitive match
                    // in declaration order (Go `encoding/json`).
                    let idx = field_index(fields, &key);
                    match idx {
                        Some(i) => decode_value(&fields[i].typ, r, &mut values[i])?,
                        None => r.skip_value(),
                    }
                    r.skip_ws();
                    if r.peek() == Some(b',') {
                        r.pos += 1;
                    } else {
                        r.pos += 1; // '}'
                        break;
                    }
                }
            }
            *out = GoValue::Struct(values);
            Ok(())
        }
        _ => {
            r.skip_value();
            Err(type_error("object", typ))
        }
    }
}

/// The index of the struct field a JSON object key maps to.
fn field_index(fields: &[crate::gotype::StructField], key: &str) -> Option<usize> {
    let effective = |f: &crate::gotype::StructField| -> Option<String> {
        if f.unexported {
            return None;
        }
        match &f.json_tag {
            Some(tag) => {
                let name = tag.split(',').next().unwrap_or("");
                if tag == "-" {
                    return None;
                }
                if name.is_empty() {
                    Some(f.name.clone())
                } else {
                    Some(name.to_string())
                }
            }
            None => Some(f.name.clone()),
        }
    };
    for (i, f) in fields.iter().enumerate() {
        if effective(f).as_deref() == Some(key) {
            return Some(i);
        }
    }
    for (i, f) in fields.iter().enumerate() {
        if let Some(name) = effective(f) {
            if name.eq_ignore_ascii_case(key) {
                return Some(i);
            }
        }
    }
    None
}

/// Decode standard base64 (with padding), as Go's `encoding/json`
/// does for `[]byte` targets.
fn base64_decode_std(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                if i < 4 - pad {
                    return None;
                }
                0
            } else {
                val(c)?
            };
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}
