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

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::gotype::{GoType, GoValue, Kind, resolve};

mod isprint;

// ---------------------------------------------------------------------
// Float formatting.
// ---------------------------------------------------------------------

/// Go `strconv.FormatFloat`'s text for a value with no digits — `NaN`
/// and `±Inf` — or `None` when `v` is finite and does decompose into
/// digits.  Every digit-based formatter below checks this first, so
/// none of them can be handed a representation without an exponent.
fn nonfinite_text(v: f64) -> Option<&'static str> {
    if v.is_nan() {
        Some("NaN")
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            Some("-Inf")
        } else {
            Some("+Inf")
        }
    } else {
        None
    }
}

/// Decompose a float's shortest-round-trip representation into its
/// negative flag, decimal digits, and decimal point position (the
/// number of digits before the decimal point; may be negative or
/// exceed the digit count).
///
/// This is total: a representation carrying no exponent (Rust renders
/// the non-finite floats as `inf`/`NaN`, which have no `e`) decomposes
/// to a plain zero rather than panicking.  Callers guard those values
/// with [`nonfinite_text`] and never observe the fallback.
fn split_shortest(repr: String) -> (bool, String, i32) {
    // `format!("{:e}")` yields `d.ddd...e<exp>` (shortest digits).
    let neg = repr.starts_with('-');
    let s = repr.trim_start_matches('-');
    let Some((mantissa, exp)) = s.split_once('e') else {
        return (neg, "0".to_string(), 1);
    };
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    // Strip trailing zeros; the mantissa of a shortest form has none,
    // except the plain "0".
    (neg, digits, exp + 1)
}

/// The shortest round-trip digits of a `float64` as Go's `strconv`
/// picks them ([`split_shortest`]'s decomposition).
fn shortest_digits(v: f64) -> (bool, String, i32) {
    let (neg, digits, dp) = split_shortest(format!("{v:e}"));
    even_on_tie(v, neg, digits, dp, |text| {
        text.parse::<f64>().is_ok_and(|p| p == v.abs())
    })
}

/// The shortest round-trip digits of a `float32` as Go's `strconv`
/// picks them with `bitSize` 32.
fn shortest_digits32(v: f32) -> (bool, String, i32) {
    let (neg, digits, dp) = split_shortest(format!("{v:e}"));
    even_on_tie(f64::from(v), neg, digits, dp, |text| {
        text.parse::<f32>().is_ok_and(|p| p == v.abs())
    })
}

/// Resolve an exact tie between two shortest candidates the way Go
/// does.
///
/// When a value lies exactly halfway between two decimals of the
/// shortest length that both parse back to it, Go's shortest formatter
/// keeps the one whose final digit is even (Go 1.26.5's Dragonbox,
/// `internal/strconv/ftoadbox.go`: "round to nearest, tie to even"),
/// and Rust's `{:e}` takes the one away from zero.  Only an odd final
/// digit can therefore be Go's wrong choice; the halfway test is exact.
/// `v` is the value (a `float32` widened exactly), `digits`/`dp` Rust's
/// choice, and `round_trips` whether a candidate `<digits>e<exp>`
/// parses back to `|v|` at the value's own precision: Go chooses only
/// among candidates that do.
fn even_on_tie(
    v: f64,
    neg: bool,
    digits: String,
    dp: i32,
    round_trips: impl Fn(&str) -> bool,
) -> (bool, String, i32) {
    if !digits.ends_with(['1', '3', '5', '7', '9']) {
        return (neg, digits, dp);
    }
    // Shortest digits never exceed seventeen, so this cannot fail.
    let Ok(d) = digits.parse::<u64>() else {
        return (neg, digits, dp);
    };
    let n = digits.len() as i32;
    // |v| = d * 10^q with the digits Rust chose.
    let q = dp - n;

    // |v| = m * 2^e with m odd; zero has no odd final digit.
    let bits = v.abs().to_bits();
    let biased = (bits >> 52) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    let (m, e) = if biased == 0 {
        (frac, -1074)
    } else {
        (frac | (1u64 << 52), biased - 1075)
    };
    let tz = m.trailing_zeros();
    let (m, e) = (m >> tz, e + tz as i32);

    // Halfway iff m * 2^e == twice * 5^q * 2^(q-1), with twice = 2d -+ 1
    // odd: the powers of two and the odd parts must both agree.  Any
    // overflow means the odd parts differ, since each is below 2^58.
    if e != q - 1 {
        return (neg, digits, dp);
    }
    for (neighbour, twice) in [(d - 1, 2 * d - 1), (d + 1, 2 * d + 1)] {
        let odd_parts_match = if q >= 0 {
            5u128
                .checked_pow(q.unsigned_abs())
                .and_then(|p| p.checked_mul(u128::from(twice)))
                == Some(u128::from(m))
        } else {
            5u128
                .checked_pow(q.unsigned_abs())
                .and_then(|p| p.checked_mul(u128::from(m)))
                == Some(u128::from(twice))
        };
        if !odd_parts_match {
            continue;
        }
        // The even neighbour, trailing zeros trimmed; a carry into a
        // new leading digit moves the decimal point.
        let text = neighbour.to_string();
        let even_dp = dp + (text.len() as i32 - n);
        let even = text.trim_end_matches('0');
        if even.is_empty() {
            continue;
        }
        let candidate = format!("{even}e{}", even_dp - even.len() as i32);
        if round_trips(&candidate) {
            return (neg, even.to_string(), even_dp);
        }
    }
    (neg, digits, dp)
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
///
/// Go's encoder has no rendering for `NaN` and `±Inf`: it aborts the
/// whole marshal with `json: unsupported value`.  The decoder never
/// produces a non-finite `float64` (`decode_number` rejects one), but a
/// handler can compute one -- getvoteinfo's choice progress is `0/0`
/// when no vote of the version has been cast yet -- so the failure is
/// real: [`try_encode`] reports it, and a reply marshalled through it is
/// dropped as dcrd drops one.  This signature cannot fail, so for the
/// infallible [`encode`] such a value is emitted as the JSON `null`
/// literal, which keeps the document parseable instead of panicking or
/// writing a bare `+Inf` that no JSON reader accepts.
pub fn format_float_json(v: f64) -> String {
    if !v.is_finite() {
        return "null".to_string();
    }
    let abs = v.abs();
    let use_e = abs != 0.0 && (abs < 1e-6 || abs >= 1e21);
    let (neg, digits, dp) = shortest_digits(v);
    format_float_json_parts(neg, digits, dp, use_e)
}

/// Format a `float32` exactly as Go's `encoding/json` does.  Non-finite
/// values become `null`, as in [`format_float_json`].
pub fn format_float_json32(v: f32) -> String {
    if !v.is_finite() {
        return "null".to_string();
    }
    let abs = v.abs();
    let use_e = abs != 0.0 && (abs < 1e-6 || abs >= 1e21);
    let (neg, digits, dp) = shortest_digits32(v);
    format_float_json_parts(neg, digits, dp, use_e)
}

/// Format a `float64` exactly as Go's `strconv.FormatFloat(v, 'f',
/// -1, 64)` does (shortest round-trip digits, never exponent form;
/// `NaN` and `±Inf` render as Go spells them).
pub fn format_float_f(v: f64) -> String {
    if let Some(text) = nonfinite_text(v) {
        return text.to_string();
    }
    let (neg, digits, dp) = shortest_digits(v);
    fmt_f(neg, &digits, dp)
}

/// Format a `float64` like Go's `fmt` verb `%v` (shortest `%g`).
pub fn format_float_g(v: f64) -> String {
    if let Some(text) = nonfinite_text(v) {
        return text.to_string();
    }
    let (neg, digits, dp) = shortest_digits(v);
    let exp = dp - 1;
    if exp < -4 || exp >= 6 {
        fmt_e(neg, &digits, dp)
    } else {
        fmt_f(neg, &digits, dp)
    }
}

/// Format a `float32` like Go's `fmt` verb `%v` (shortest `%g`).
pub fn format_float_g32(v: f32) -> String {
    if let Some(text) = nonfinite_text(v as f64) {
        return text.to_string();
    }
    let (neg, digits, dp) = shortest_digits32(v);
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
/// verbatim).  The control characters follow `appendString`'s switch
/// (`encoding/json/encode.go`): `\b`, `\f`, `\n`, `\r` and `\t` by
/// name and the rest as `\u00XX`.  Go has named `\b` and `\f` since
/// 1.22, older than any toolchain dcrd's `go.mod` (`go 1.25.0`) builds
/// with.
pub fn append_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
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

/// Quote a string exactly like Go's `strconv.Quote` (the `%q` verb):
/// `appendQuotedWith` over `appendEscapedRune` (`strconv/quote.go`).
///
/// A double quote and a backslash are backslashed, and every rune
/// `strconv.IsPrint` accepts is kept.  Otherwise the seven C escapes
/// are named (`\a \b \f \n \r \t \v`), the other ASCII controls and DEL
/// are `\xNN`, and every other rune is `\uNNNN` or `\UNNNNNNNN` -- a
/// no-break space, a soft hyphen, a zero-width space, a private-use or
/// an unassigned rune among them.  A `&str` is well-formed UTF-8, so
/// Go's `\xNN` for a byte that begins no valid encoding never arises.
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if isprint::is_print(c) => out.push(c),
            '\u{07}' => out.push_str("\\a"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0b}' => out.push_str("\\v"),
            c if c < ' ' || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c if u32::from(c) < 0x1_0000 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push_str(&format!("\\U{:08x}", u32::from(c))),
        }
    }
    out.push('"');
    out
}

/// Quote a byte like Go's json scanner `quoteChar` helper
/// (`encoding/json/scanner.go`): `strconv.Quote(string(c))` with the
/// quote characters swapped.
///
/// `string(c)` converts the byte as an integer, so it quotes the rune
/// U+0000..U+00FF, not the byte: 0xff is `'ÿ'` and 0x80 is `'\u0080'`,
/// whatever the byte meant in the input.  `strconv.Quote` keeps what
/// `strconv.IsPrint` calls printable -- printable ASCII and U+00A1..U+00FF
/// but the soft hyphen -- names the seven C escapes, spells the other
/// ASCII controls `\xNN` and every other rune `\uNNNN`, and backslashes
/// a backslash.  This is Go 1.26's `encoding/json`, the toolchain dcrd's
/// release image builds with (`contrib/docker/Dockerfile`); a toolchain
/// that builds the package on its v2 implementation spells a high byte
/// `'\xff'` instead.
fn quote_char(c: u8) -> String {
    // The quote characters are the special cases, different from
    // quoted strings.
    match c {
        b'\'' => "'\\''".to_string(),
        b'"' => "'\"'".to_string(),
        c => {
            // The quoted string, with different quotation marks.
            let s = go_quote(char::from(c).encode_utf8(&mut [0; 4]));
            format!("'{}'", &s[1..s.len() - 1])
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
pub fn underscore_ok(s: &str) -> bool {
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
    // Pick off exactly one leading sign; a second one reaches the
    // unsigned parse and fails there, as in Go's ParseInt.
    let (neg, unsigned) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let mag = go_parse_uint_mag(unsigned, s)?;
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
    go_parse_float_checked(s).map_err(|_| ())
}

/// The `strconv` error a Go numeric parse fails with, for callers that
/// print Go's `*NumError` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoNumError {
    /// `strconv.ErrSyntax` ("invalid syntax").
    Syntax,
    /// `strconv.ErrRange` ("value out of range").
    Range,
}

/// [`go_parse_float`] with the error Go's `ParseFloat` returns: a
/// literal that is well formed but overflows `float64` (decimal or hex)
/// is `ErrRange`, anything else that fails is `ErrSyntax`.
pub fn go_parse_float_checked(s: &str) -> Result<f64, GoNumError> {
    use GoNumError::{Range, Syntax};
    if s.is_empty() {
        return Err(Syntax);
    }
    let lower = s.to_ascii_lowercase();
    // Go's `special` takes at most one sign before the name, so "+-inf"
    // names no special value and fails the numeric parse below.
    let (neg, body) = match lower.as_bytes()[0] {
        b'+' => (false, &lower[1..]),
        b'-' => (true, &lower[1..]),
        _ => (false, lower.as_str()),
    };
    if body == "inf" || body == "infinity" {
        return Ok(if neg {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    if body == "nan" {
        if body.len() != lower.len() {
            return Err(Syntax);
        }
        return Ok(f64::NAN);
    }
    if s.contains('_') && !underscore_ok(s) {
        return Err(Syntax);
    }
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    let v = if cleaned.to_ascii_lowercase().contains("0x") {
        go_parse_hex_float(&cleaned).map_err(|()| Syntax)?
    } else {
        // Reject shapes Rust accepts but Go does not, and vice versa: Go
        // requires digits around the exponent and accepts a trailing or
        // leading dot ("1." and ".5" are valid Go floats, as in Rust).
        cleaned.parse::<f64>().map_err(|_| Syntax)?
    };
    if v.is_infinite() {
        // Finite literal overflowed: Go returns ErrRange.
        return Err(Range);
    }
    Ok(v)
}

/// Parse a hexadecimal float literal (Go `0x1.8p3` forms) exactly as
/// Go's `ParseFloat` does: the hex branch of `readFloat`, which keeps
/// the first sixteen significant digits in a `uint64` and records
/// whether any later digit was non-zero, then `atofHex`, which rounds
/// that mantissa once to 53 bits -- to nearest, ties to even, through
/// the subnormal range -- rather than accumulating it in a float
/// (`internal/strconv/atof.go`).  The underscores are already checked
/// and removed.  An overflow yields the signed infinity `atofHex`
/// returns beside `ErrRange`, so an `Err` here is always a syntax
/// failure.
fn go_parse_hex_float(s: &str) -> Result<f64, ()> {
    let b = s.as_bytes();
    let mut i = 0;

    // Optional sign.
    let mut neg = false;
    match b.first() {
        Some(b'+') => i += 1,
        Some(b'-') => {
            i += 1;
            neg = true;
        }
        _ => {}
    }

    // The base prefix, with something after it.
    if !(i + 2 < b.len() && b[i] == b'0' && b[i + 1].eq_ignore_ascii_case(&b'x')) {
        return Err(());
    }
    i += 2;

    // Digits.
    const MAX_MANT_DIGITS: i64 = 16; // 16^16 fits in uint64
    let mut mantissa: u64 = 0;
    let mut trunc = false;
    let mut sawdot = false;
    let mut sawdigits = false;
    let mut nd: i64 = 0;
    let mut nd_mant: i64 = 0;
    let mut dp: i64 = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
            i += 1;
            continue;
        }
        let Some(d) = char::from(c).to_digit(16) else {
            break;
        };
        sawdigits = true;
        i += 1;
        if c == b'0' && nd == 0 {
            // Ignore leading zeros.
            dp -= 1;
            continue;
        }
        nd += 1;
        if nd_mant < MAX_MANT_DIGITS {
            mantissa = mantissa * 16 + u64::from(d);
            nd_mant += 1;
        } else if c != b'0' {
            trunc = true;
        }
    }
    if !sawdigits {
        return Err(());
    }
    if !sawdot {
        dp = nd;
    }
    dp *= 4;
    nd_mant *= 4;

    // The exponent, which a hex literal must have.
    if i >= b.len() || !b[i].eq_ignore_ascii_case(&b'p') {
        return Err(());
    }
    i += 1;
    let mut esign = 1;
    match b.get(i) {
        Some(b'+') => i += 1,
        Some(b'-') => {
            i += 1;
            esign = -1;
        }
        _ => {}
    }
    if i >= b.len() || !b[i].is_ascii_digit() {
        return Err(());
    }
    let mut e: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        if e < 10000 {
            e = e * 10 + i64::from(b[i] - b'0');
        }
        i += 1;
    }
    dp += e * esign;
    // ParseFloat refuses anything left over.
    if i != b.len() {
        return Err(());
    }
    let mut exp = 0;
    if mantissa != 0 {
        exp = dp - nd_mant;
    }

    // atofHex over float64info.
    const MANTBITS: u32 = 52;
    const EXPBITS: u32 = 11;
    const BIAS: i64 = -1023;
    let max_exp = (1 << EXPBITS) + BIAS - 2;
    let min_exp = BIAS + 1;
    exp += i64::from(MANTBITS); // mantissa now implicitly divided by 2^mantbits.

    // Bring the mantissa to a leading 1-bit, MANTBITS more bits and two
    // rounding bits, the bottom one sticky.
    while mantissa != 0 && mantissa >> (MANTBITS + 2) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while mantissa >> (1 + MANTBITS + 2) != 0 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }

    // If the exponent is too negative, denormalize in hopes of making
    // it representable (the -2 is for the rounding bits).
    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }

    // Round using the two bottom bits, to even.
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1;
    exp += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1 << (1 + MANTBITS) {
            mantissa >>= 1;
            exp += 1;
        }
    }

    if mantissa >> MANTBITS == 0 {
        // Denormal or zero.
        exp = BIAS;
    }
    if exp > max_exp {
        // Infinity and range error: Go returns the signed infinity with
        // ErrRange, which the caller reports for an infinite result.
        mantissa = 1 << MANTBITS;
        exp = max_exp + 1;
    }

    let mut bits = mantissa & ((1 << MANTBITS) - 1);
    bits |= (((exp - BIAS) & ((1 << EXPBITS) - 1)) as u64) << MANTBITS;
    if neg {
        bits |= 1 << MANTBITS << EXPBITS;
    }
    Ok(f64::from_bits(bits))
}

// ---------------------------------------------------------------------
// Encoding.
// ---------------------------------------------------------------------

/// Encode a typed value to JSON exactly as Go's `json.Marshal` does,
/// except that a non-finite float, which Go refuses, renders as `null`
/// (see [`format_float_json`]; [`try_encode`] fails instead).
pub fn encode(typ: &GoType, val: &GoValue) -> String {
    let mut out = String::new();
    encode_into(typ, val, &mut out, &mut None);
    out
}

/// Go `json.UnsupportedValueError`: the marshal failure Go's encoder
/// raises for a float it cannot represent (`floatEncoder.encode` in
/// `encoding/json/encode.go`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedValueError {
    /// The value as Go spells it (`strconv.FormatFloat(f, 'g', -1,
    /// bits)`): `NaN`, `+Inf` or `-Inf`.
    pub str: String,
}

impl std::fmt::Display for UnsupportedValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "json: unsupported value: {}", self.str)
    }
}

impl std::error::Error for UnsupportedValueError {}

/// Encode a typed value to JSON exactly as Go's `json.Marshal` does,
/// failure included: the first non-finite float the encoder reaches
/// aborts the marshal with Go's `UnsupportedValueError`.
pub fn try_encode(typ: &GoType, val: &GoValue) -> Result<String, UnsupportedValueError> {
    let mut out = String::new();
    let mut unsupported = None;
    encode_into(typ, val, &mut out, &mut unsupported);
    match unsupported {
        Some(err) => Err(err),
        None => Ok(out),
    }
}

/// Record the first non-finite float the encoder reaches, the value
/// Go's `floatEncoder` would abort the marshal on.
fn note_unsupported(v: f64, unsupported: &mut Option<UnsupportedValueError>) {
    if unsupported.is_none()
        && let Some(text) = nonfinite_text(v)
    {
        *unsupported = Some(UnsupportedValueError {
            str: text.to_string(),
        });
    }
}

fn encode_into(
    typ: &GoType,
    val: &GoValue,
    out: &mut String,
    unsupported: &mut Option<UnsupportedValueError>,
) {
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
            v => encode_into(elem, v, out, unsupported),
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
            GoValue::Float32(f) => {
                note_unsupported(f64::from(*f), unsupported);
                out.push_str(&format_float_json32(*f));
            }
            _ => out.push('0'),
        },
        GoType::Float64 => match val {
            GoValue::Float64(f) => {
                note_unsupported(*f, unsupported);
                out.push_str(&format_float_json(*f));
            }
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
                encode_seq(elem, items, out, unsupported);
            }
            _ => out.push_str("null"),
        },
        GoType::Array(_, elem) => match val {
            GoValue::Array(items) => encode_seq(elem, items, out, unsupported),
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
                    encode_into(velem, v, out, unsupported);
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
                    encode_into(&f.typ, v, out, unsupported);
                }
                out.push('}');
            }
            _ => out.push_str("{}"),
        },
        _ => out.push_str("null"),
    }
}

fn encode_seq(
    elem: &GoType,
    items: &[GoValue],
    out: &mut String,
    unsupported: &mut Option<UnsupportedValueError>,
) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_into(elem, item, out, unsupported);
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
        /// The struct field context Go records while decoding into a
        /// named struct, e.g. `node.host`: the innermost named struct
        /// type and the dotted field path.
        field: Option<String>,
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
                field,
            } => match field {
                Some(field) => format!(
                    "json: cannot unmarshal {value} into Go struct field {field} \
                     of type {type_display}"
                ),
                None => {
                    format!("json: cannot unmarshal {value} into Go value of type {type_display}")
                }
            },
        }
    }
}

struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
}

const UNEXPECTED_END: &str = "unexpected end of JSON input";

/// The maximum number of nested arrays or objects Go's scanner accepts
/// before failing (`encoding/json` `maxNestingDepth`).  The 10001st open
/// bracket errors, matching `checkValid`, so a deeply nested document is
/// rejected instead of overflowing the stack.
const MAX_NESTING_DEPTH: usize = 10000;

/// An open container on the validator's explicit walk stack.  The
/// scanner tracks nesting iteratively — like Go's `scanner` parseState —
/// so a deeply nested document is caught by the depth guard instead of
/// exhausting the native stack.
#[derive(Clone, Copy)]
enum Container {
    Array,
    Object,
}

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

    /// The error for input that ends partway through a token.  Go's
    /// `scanner.eof` steps the state machine once more with a synthetic
    /// space and reports "unexpected end of JSON input" only when that
    /// step records no error; inside a number (after `-`, `.`, `e` or the
    /// exponent sign), a literal, a string escape or a `\u` escape the
    /// space is itself invalid, so that state's own message is the one
    /// `checkValid` returns.  `context` is that message's tail, e.g.
    /// `in numeric literal`.
    fn eof_in(context: &str) -> JsonError {
        Self::syntax(format!("invalid character {} {context}", quote_char(b' ')))
    }

    /// Validate one JSON value starting at the current position,
    /// producing Go scanner messages on malformed input.
    ///
    /// Container nesting is walked with an explicit stack rather than by
    /// recursing into `check_array`/`check_object`, so a deeply nested
    /// document is rejected by the depth guard (Go's `maxNestingDepth`)
    /// instead of exhausting the native stack — Go's scanner tracks the
    /// same nesting in an explicit `parseState` slice.
    fn check_value(&mut self) -> Result<(), JsonError> {
        let mut stack: Vec<Container> = Vec::new();

        'read_value: loop {
            self.skip_ws();
            let Some(c) = self.peek() else {
                return Err(Self::syntax(UNEXPECTED_END.to_string()));
            };
            match c {
                b'[' => {
                    self.pos += 1;
                    self.enter(stack.len(), b'[')?;
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.pos += 1; // an empty array is a complete value
                    } else {
                        stack.push(Container::Array);
                        continue 'read_value; // read the first element
                    }
                }
                b'{' => {
                    self.pos += 1;
                    self.enter(stack.len(), b'{')?;
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1; // an empty object is a complete value
                    } else {
                        self.check_object_key()?;
                        stack.push(Container::Object);
                        continue 'read_value; // read the member value
                    }
                }
                b'"' => self.check_string()?,
                b't' => self.check_literal("true")?,
                b'f' => self.check_literal("false")?,
                b'n' => self.check_literal("null")?,
                b'-' | b'0'..=b'9' => self.check_number()?,
                c => {
                    return Err(Self::syntax(format!(
                        "invalid character {} looking for beginning of value",
                        quote_char(c)
                    )));
                }
            }

            // A complete value has just been scanned.  Ascend through the
            // open containers, consuming element/member separators, until
            // another value is due or the top-level value is finished.
            loop {
                let Some(container) = stack.last().copied() else {
                    return Ok(());
                };
                self.skip_ws();
                match container {
                    Container::Array => match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                            continue 'read_value;
                        }
                        Some(b']') => {
                            self.pos += 1;
                            stack.pop();
                        }
                        Some(c) => {
                            return Err(Self::syntax(format!(
                                "invalid character {} after array element",
                                quote_char(c)
                            )));
                        }
                        None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
                    },
                    Container::Object => match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                            self.check_object_key()?;
                            continue 'read_value;
                        }
                        Some(b'}') => {
                            self.pos += 1;
                            stack.pop();
                        }
                        Some(c) => {
                            return Err(Self::syntax(format!(
                                "invalid character {} after object key:value pair",
                                quote_char(c)
                            )));
                        }
                        None => return Err(Self::syntax(UNEXPECTED_END.to_string())),
                    },
                }
            }
        }
    }

    /// Fail with Go's scanner message once the number of open containers
    /// would exceed `MAX_NESTING_DEPTH`.  `open_containers` is the count
    /// already on the stack, so the new `[` or `{` is the (n+1)th level.
    fn enter(&self, open_containers: usize, open: u8) -> Result<(), JsonError> {
        if open_containers >= MAX_NESTING_DEPTH {
            return Err(Self::syntax(format!(
                "invalid character {} exceeded max depth",
                quote_char(open)
            )));
        }
        Ok(())
    }

    /// Scan an object key string and its trailing colon at the current
    /// position, producing the Go scanner messages for a missing key or
    /// colon.
    fn check_object_key(&mut self) -> Result<(), JsonError> {
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
                Ok(())
            }
            Some(c) => Err(Self::syntax(format!(
                "invalid character {} after object key",
                quote_char(c)
            ))),
            None => Err(Self::syntax(UNEXPECTED_END.to_string())),
        }
    }

    fn check_literal(&mut self, lit: &str) -> Result<(), JsonError> {
        for (i, want) in lit.bytes().enumerate() {
            // At end of input Go's eof() steps a space into the literal
            // state (stateTr and its siblings), which rejects it.
            let got = self.data.get(self.pos + i).copied().unwrap_or(b' ');
            if got != want {
                return Err(Self::syntax(format!(
                    "invalid character {} in literal {} (expecting {})",
                    quote_char(got),
                    lit,
                    quote_char(want),
                )));
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
                        return Err(Self::eof_in("in string escape code"));
                    };
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let Some(h) = self.peek() else {
                                    return Err(Self::eof_in(
                                        "in \\u hexadecimal character escape",
                                    ));
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
                None => return Err(Self::eof_in("in numeric literal")),
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
                None => return Err(Self::eof_in("after decimal point in numeric literal")),
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
                None => return Err(Self::eof_in("in exponent of numeric literal")),
            }
        }
        Ok(())
    }
}

/// Validate an entire JSON document like Go's `json.Unmarshal` does
/// before decoding (`checkValid`).
pub fn validate(data: &str) -> Result<(), JsonError> {
    validate_bytes(data.as_bytes())
}

/// [`validate`] over raw bytes, which need not be UTF-8: Go's scanner
/// takes any byte from 0x20 up inside a string literal, and names a
/// stray byte elsewhere by its own value.
pub fn validate_bytes(data: &[u8]) -> Result<(), JsonError> {
    let mut sc = Scanner::new(data);
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

/// Go's coercion of a string's bytes to well-formed UTF-8 when it is
/// unquoted (`unquoteBytes`, `encoding/json/decode.go`): every byte that
/// does not begin a valid encoding becomes one U+FFFD.  That is
/// `utf8.DecodeRune`, which reports an invalid sequence one byte at a
/// time, and not `String::from_utf8_lossy`, which replaces a maximal
/// invalid subpart with a single U+FFFD -- `"\xe2\x82"` is two
/// replacement characters in Go and one in Rust.
pub fn coerce_utf8(data: &[u8]) -> Cow<'_, str> {
    let mut valid_up_to = match std::str::from_utf8(data) {
        Ok(text) => return Cow::Borrowed(text),
        Err(e) => e.valid_up_to(),
    };
    let mut out = String::with_capacity(data.len() + 2);
    let mut rest = data;
    loop {
        let (valid, after) = rest.split_at(valid_up_to);
        // The prefix `from_utf8` vouched for, so this never defaults.
        out.push_str(std::str::from_utf8(valid).unwrap_or_default());
        // The byte that begins no valid encoding, one U+FFFD for it.
        let Some((_, after)) = after.split_first() else {
            break;
        };
        out.push('\u{FFFD}');
        rest = after;
        valid_up_to = match std::str::from_utf8(rest) {
            Ok(_) => rest.len(),
            Err(e) => e.valid_up_to(),
        };
    }
    Cow::Owned(out)
}

/// The text `json.Unmarshal` decodes from a request's raw bytes.
///
/// dcrd hands a request body or websocket frame to `json.Unmarshal` as
/// it arrived, never checking it is UTF-8.  Go's scanner validates the
/// raw bytes, accepting anything from 0x20 up inside a string literal,
/// and invalid UTF-8 there only becomes U+FFFD when the string is
/// unquoted.  So a document that is valid UTF-8 is handed back as it
/// is, for the caller's own decoding to validate; one that is not is
/// validated here, because only the raw bytes give Go's message for a
/// stray byte outside a string (`invalid character 'ÿ' ...`), and on
/// success coerced by [`coerce_utf8`].  Every invalid byte then lies
/// inside a string literal, and dcrd unquotes every string it decodes
/// from a request, so the coerced text decodes to the values Go's
/// decoder produces.
pub fn unmarshal_input(data: &[u8]) -> Result<Cow<'_, str>, JsonError> {
    if let Ok(text) = std::str::from_utf8(data) {
        return Ok(Cow::Borrowed(text));
    }
    validate_bytes(data)?;
    Ok(coerce_utf8(data))
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

/// Decode the one UTF-8 sequence starting at `data[at]` the way Go's
/// `utf8.DecodeRune` does: a well-formed sequence yields its rune and
/// its length in bytes, and anything else — a stray continuation byte,
/// a truncated or overlong sequence, an encoded surrogate half — yields
/// U+FFFD with a length of one.  That is exactly what Go's
/// `encoding/json` `unquoteBytes` does with the contents of a string:
/// it coerces to well-formed UTF-8 rather than failing, so malformed
/// bytes can never panic the decoder.
///
/// The slice handed to the UTF-8 validator is capped at the four bytes
/// a sequence can occupy, which makes this O(1) per character.
/// Validating the whole unread remainder instead would make reading a
/// non-ASCII string quadratic in its length.
fn decode_rune(data: &[u8], at: usize) -> (char, usize) {
    const MAX_SEQ_LEN: usize = 4;
    let end = data.len().min(at.saturating_add(MAX_SEQ_LEN));
    let Some(window) = data.get(at..end) else {
        return (char::REPLACEMENT_CHARACTER, 1);
    };
    // A window cut off mid-sequence at the cap fails validation even
    // though its leading character is well formed, so fall back to the
    // longest valid prefix, which always covers that character.
    let text = match core::str::from_utf8(window) {
        Ok(text) => text,
        Err(err) => match window
            .get(..err.valid_up_to())
            .and_then(|prefix| core::str::from_utf8(prefix).ok())
        {
            Some(text) => text,
            None => return (char::REPLACEMENT_CHARACTER, 1),
        },
    };
    match text.chars().next() {
        Some(ch) => (ch, ch.len_utf8()),
        None => (char::REPLACEMENT_CHARACTER, 1),
    }
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
                    // Multi-byte UTF-8: decode exactly this character.
                    // The validator only ever sees the at most four
                    // bytes one sequence can occupy, so a string of
                    // non-ASCII text costs O(n) rather than
                    // revalidating the whole remainder per character.
                    let start = self.pos - 1;
                    let (ch, size) = decode_rune(self.data, start);
                    out.push(ch);
                    self.pos = start + size;
                }
            }
        }
    }

    /// Skip one complete value (used when the target ignores it).
    ///
    /// Nesting is walked with an explicit stack rather than by recursing,
    /// so skipping a deeply nested but ignored value does not exhaust the
    /// native stack.  The input is already validated, so its depth is
    /// bounded by `MAX_NESTING_DEPTH`.
    fn skip_value(&mut self) {
        let mut stack: Vec<Container> = Vec::new();

        'read_value: loop {
            match self.next_token() {
                Token::ArrayStart => {
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.pos += 1; // an empty array is a complete value
                    } else {
                        stack.push(Container::Array);
                        continue 'read_value; // skip the first element
                    }
                }
                Token::ObjectStart => {
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1; // an empty object is a complete value
                    } else {
                        self.skip_object_key();
                        stack.push(Container::Object);
                        continue 'read_value; // skip the member value
                    }
                }
                _ => {} // a scalar was consumed by next_token
            }

            // The value is complete.  Ascend through the open containers,
            // consuming separators, until another value is due or the
            // top-level value is finished.
            loop {
                let Some(container) = stack.last().copied() else {
                    return;
                };
                self.skip_ws();
                match container {
                    Container::Array => {
                        if self.peek() == Some(b',') {
                            self.pos += 1;
                            continue 'read_value;
                        }
                        self.pos += 1; // ']'
                        stack.pop();
                    }
                    Container::Object => {
                        if self.peek() == Some(b',') {
                            self.pos += 1;
                            self.skip_object_key();
                            continue 'read_value;
                        }
                        self.pos += 1; // '}'
                        stack.pop();
                    }
                }
            }
        }
    }

    /// Skip an object key string and its trailing colon (input known
    /// valid).
    fn skip_object_key(&mut self) {
        self.next_token(); // key
        self.skip_ws();
        self.pos += 1; // ':'
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
        field: None,
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
            // Go's map decode is a hash insert per key (`encoding/json`
            // `object`), so a duplicate key costs the same as a fresh
            // one.  `entries` alone would mean rescanning every key seen
            // so far, which an 8 MiB body of distinct keys turns into
            // minutes of CPU on a request any limited-credential client
            // can make.  The vector still carries first-seen order --
            // observable through `GoValue` equality and the raw-tx
            // handlers -- and this only indexes it.
            let mut slots: HashMap<String, usize> = HashMap::new();
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
                    match slots.entry(key) {
                        // Last value wins, in the first-seen slot.
                        Entry::Occupied(slot) => entries[*slot.get()].1 = v,
                        Entry::Vacant(slot) => {
                            let idx = entries.len();
                            entries.push((slot.key().clone(), v));
                            slot.insert(idx);
                        }
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
                        Some(i) => decode_value(&fields[i].typ, r, &mut values[i])
                            .map_err(|e| add_field_context(e, typ, &effective_name(&fields[i])))?,
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
/// The effective JSON name of a struct field for error context.
fn effective_name(f: &crate::gotype::StructField) -> String {
    match &f.json_tag {
        Some(tag) => {
            let name = tag.split(',').next().unwrap_or("");
            if name.is_empty() || tag == "-" {
                f.name.clone()
            } else {
                name.to_string()
            }
        }
        None => f.name.clone(),
    }
}

/// Attach Go's struct-field error context to a type error raised while
/// decoding a named struct's field: the innermost struct type name
/// with the dotted field path (Go `UnmarshalTypeError.Struct`/`Field`).
fn add_field_context(err: JsonError, struct_type: &GoType, field_name: &str) -> JsonError {
    match err {
        JsonError::Type {
            value,
            type_display,
            field,
        } => {
            let struct_name = struct_type.name();
            let field = match field {
                // An inner struct already recorded its context; Go
                // keeps the innermost struct name and prepends the
                // outer field to the path.
                Some(existing) => match existing.split_once('.') {
                    Some((inner_struct, path)) => {
                        format!("{inner_struct}.{field_name}.{path}")
                    }
                    None => existing,
                },
                None => format!("{struct_name}.{field_name}"),
            };
            JsonError::Type {
                value,
                type_display,
                field: Some(field),
            }
        }
        other => other,
    }
}

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
        if let Some(name) = effective(f)
            && go_fold_eq(key, &name)
        {
            return Some(i);
        }
    }
    None
}

/// Whether a decoded JSON object key names the given ASCII struct field
/// under Go's case-insensitive fallback, `fields.byFoldedName[
/// foldName(key)]` (`encoding/json/decode.go`, `fold.go`).
///
/// `foldName` upper-cases ASCII and sends every other rune through
/// `foldRune`, the smallest rune of its `unicode.SimpleFold` orbit.
/// U+017F (LATIN SMALL LETTER LONG S) and U+212A (KELVIN SIGN) are the
/// only runes whose orbit reaches ASCII -- they fold to `S` and `K` --
/// so for an ASCII field name, which every registered type's is,
/// mapping those two and comparing ASCII-insensitively is exactly Go's
/// result without carrying a fold table.
pub fn go_fold_eq(key: &str, field: &str) -> bool {
    if key.is_ascii() {
        return key.eq_ignore_ascii_case(field);
    }
    let folded: String = key
        .chars()
        .map(|c| match c {
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            other => other,
        })
        .collect();
    folded.eq_ignore_ascii_case(field)
}

/// Decode standard base64 (with padding), as Go's `encoding/json`
/// does for `[]byte` targets.
///
/// Faithful to `base64.StdEncoding.Decode`: newlines (`\r`, `\n`) are
/// ignored anywhere in the input, a padded quantum must carry at least
/// two data characters (`====` and `A===` are corrupt), and padding
/// terminates the input — nothing but newlines may follow it.  Go
/// returns the partial output alongside the error, but `encoding/json`
/// discards it, so any error decodes to `None` here.
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
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut it = s.bytes().filter(|&c| c != b'\r' && c != b'\n');
    loop {
        // Assemble one 4-character quantum.  '=' is corrupt in the
        // first two positions (`val` rejects it), so a padded quantum
        // always has at least two data characters.
        let Some(c0) = it.next() else {
            return Some(out);
        };
        let n = (val(c0)? << 6) | val(it.next()?)?;
        match it.next()? {
            b'=' => {
                // "==" completes the quantum and must end the input.
                if it.next()? != b'=' || it.next().is_some() {
                    return None;
                }
                out.push((n >> 4) as u8);
                return Some(out);
            }
            c2 => {
                let n = (n << 6) | val(c2)?;
                match it.next()? {
                    b'=' => {
                        // "=" completes the quantum and must end the
                        // input.
                        if it.next().is_some() {
                            return None;
                        }
                        out.push((n >> 10) as u8);
                        out.push((n >> 2) as u8);
                        return Some(out);
                    }
                    c3 => {
                        let n = (n << 6) | val(c3)?;
                        out.push((n >> 16) as u8);
                        out.push((n >> 8) as u8);
                        out.push(n as u8);
                    }
                }
            }
        }
    }
}
