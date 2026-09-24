// SPDX-License-Identifier: ISC
//! Go `golang.org/x/net/idna.ToASCII`, which dcrd's certgen and gencerts
//! call on every non-ASCII host name (x/net v0.47.0, the version dcrd's
//! `go.mod` requires at the parity pin: `idna10.0.0.go`, `punycode.go`).
//!
//! `ToASCII` is `Punycode.process(s, true)`, and `Punycode` is an empty
//! `Profile{}`.  So there is no UTS-46 processing at all: no mapping (ASCII
//! case is kept and nothing is NFC-normalised or case-folded), no hyphen,
//! joiner or bidi checks, and no DNS length limits.  What is left is RFC
//! 3492 per label: a label with the `xn--` prefix is decoded (an invalid
//! one is an error), and every label that is then non-ASCII is encoded
//! with the prefix.  UTS-46 (the `idna` crate's `domain_to_ascii`) lowered
//! `Bücher.Example` to `xn--bcher-kva.example` where dcrd writes
//! `xn--Bcher-kva.Example`, and refused names Go converts.

// RFC 3492 arithmetic over Go's int32, with Go's own overflow checks
// (`madd`, the `delta < 0` test) reproduced where it has them.
#![allow(clippy::arithmetic_side_effects)]

/// The ASCII Compatible Encoding prefix.
const ACE_PREFIX: &str = "xn--";

// RFC 3492 section 5 parameters; Go computes in int32 throughout.
const BASE: i32 = 36;
const DAMP: i32 = 700;
const INITIAL_BIAS: i32 = 72;
const INITIAL_N: i32 = 128;
const SKEW: i32 = 38;
const TMAX: i32 = 26;
const TMIN: i32 = 1;

/// Go `idna.ToASCII`: the bare Punycode profile.
pub(crate) fn to_ascii(s: &str) -> Result<String, String> {
    let mut err: Option<String> = None;
    let mut labels: Vec<String> = s.split('.').map(str::to_string).collect();
    for label in labels.iter_mut() {
        // Go's label iterator skips empty labels, and with every profile
        // option off `validateLabel` has nothing to check.
        if let Some(encoded) = label.strip_prefix(ACE_PREFIX) {
            match decode(encoded) {
                Ok(decoded) => *label = decoded,
                // "Spec says keep the old label."
                Err(e) => {
                    err.get_or_insert(e);
                }
            }
        }
    }
    for label in labels.iter_mut() {
        if !label.is_ascii() {
            match encode(ACE_PREFIX, label) {
                Ok(encoded) => *label = encoded,
                Err(e) => {
                    err.get_or_insert(e);
                }
            }
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(labels.join(".")),
    }
}

/// Go `punyError`: a `labelError` with code A3, whose text quotes the
/// label with `%q`.
fn puny_error(label: &str) -> String {
    format!("idna: invalid label {}", go_quote(label))
}

/// Go `strconv.Quote` for a valid UTF-8 string.
///
/// Exact for ASCII.  Beyond it Go keeps a rune only when
/// `unicode.IsPrint` says so, which needs Unicode's category tables; this
/// escapes the non-ASCII control and space characters and keeps the rest,
/// so a label holding a format character (U+200B, U+00AD, ...), a
/// private-use or an unassigned code point is quoted verbatim where Go
/// writes `\u` escapes.  Only the error text of a malformed `xn--` label
/// in a non-ASCII host name can carry one.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\0'..='\u{1f}' | '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            _ if c.is_control() || c.is_whitespace() => {
                if (c as u32) < 0x10000 {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go `decode`: RFC 3492 section 6.2.
fn decode(encoded: &str) -> Result<String, String> {
    if encoded.is_empty() {
        return Ok(String::new());
    }
    let bytes = encoded.as_bytes();
    let mut pos = encoded.rfind('-').map_or(0, |i| i + 1);
    if pos == 1 {
        return Err(puny_error(encoded));
    }
    if pos == bytes.len() {
        return Ok(encoded[..bytes.len() - 1].to_string());
    }
    let mut output: Vec<i32> = Vec::with_capacity(encoded.len());
    if pos != 0 {
        output.extend(encoded[..pos - 1].chars().map(|c| c as i32));
    }
    let (mut i, mut n, mut bias) = (0i32, INITIAL_N, INITIAL_BIAS);
    while pos < bytes.len() {
        let (old_i, mut w) = (i, 1i32);
        let mut k = BASE;
        loop {
            if pos == bytes.len() {
                return Err(puny_error(encoded));
            }
            let Some(digit) = decode_digit(bytes[pos]) else {
                return Err(puny_error(encoded));
            };
            pos += 1;
            i = madd(i, digit, w).ok_or_else(|| puny_error(encoded))?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            w = madd(0, w, BASE - t).ok_or_else(|| puny_error(encoded))?;
            k = k.wrapping_add(BASE);
        }
        if output.len() >= 1024 {
            return Err(puny_error(encoded));
        }
        let x = (output.len() + 1) as i32;
        bias = adapt(i - old_i, x, old_i == 0);
        n = n.wrapping_add(i / x);
        i %= x;
        if !(0..=0x10ffff).contains(&n) {
            return Err(puny_error(encoded));
        }
        output.insert(i as usize, n);
        i += 1;
    }
    // Go's `string([]rune)` writes U+FFFD for a surrogate.
    Ok(output
        .into_iter()
        .map(|r| char::from_u32(r as u32).unwrap_or('\u{fffd}'))
        .collect())
}

/// Go `encode`: RFC 3492 section 6.3, with `prefix` prepended.
fn encode(prefix: &str, s: &str) -> Result<String, String> {
    let mut output = String::with_capacity(prefix.len() + 1 + 2 * s.len());
    output.push_str(prefix);
    let (mut delta, mut n, mut bias) = (0i32, INITIAL_N, INITIAL_BIAS);
    let (mut b, mut remaining) = (0i32, 0i32);
    for r in s.chars() {
        if r.is_ascii() {
            b += 1;
            output.push(r);
        } else {
            remaining += 1;
        }
    }
    let mut h = b;
    if b > 0 {
        output.push('-');
    }
    while remaining != 0 {
        let mut m = i32::MAX;
        for r in s.chars().map(|c| c as i32) {
            if m > r && r >= n {
                m = r;
            }
        }
        delta = madd(delta, m - n, h + 1).ok_or_else(|| puny_error(s))?;
        n = m;
        for r in s.chars().map(|c| c as i32) {
            if r < n {
                delta = delta.wrapping_add(1);
                if delta < 0 {
                    return Err(puny_error(s));
                }
                continue;
            }
            if r > n {
                continue;
            }
            let mut q = delta;
            let mut k = BASE;
            loop {
                let t = threshold(k, bias);
                if q < t {
                    break;
                }
                output.push(encode_digit(t + (q - t) % (BASE - t)));
                q = (q - t) / (BASE - t);
                k = k.wrapping_add(BASE);
            }
            output.push(encode_digit(q));
            bias = adapt(delta, h + 1, h == b);
            delta = 0;
            h += 1;
            remaining -= 1;
        }
        delta = delta.wrapping_add(1);
        n = n.wrapping_add(1);
    }
    Ok(output)
}

/// The digit threshold `t` for position `k`, clamped to `[tmin, tmax]`.
fn threshold(k: i32, bias: i32) -> i32 {
    if k <= bias {
        TMIN
    } else if k >= bias.wrapping_add(TMAX) {
        TMAX
    } else {
        k - bias
    }
}

/// Go `madd`: `a + b*c`, or `None` when that overflows int32.
fn madd(a: i32, b: i32, c: i32) -> Option<i32> {
    let p = i64::from(b) * i64::from(c);
    if p > i64::from(i32::MAX) - i64::from(a) {
        return None;
    }
    Some(a.wrapping_add(p as i32))
}

/// Go `decodeDigit`: the value of a basic code point, either case.
fn decode_digit(x: u8) -> Option<i32> {
    match x {
        b'0'..=b'9' => Some(i32::from(x) - (i32::from(b'0') - 26)),
        b'A'..=b'Z' => Some(i32::from(x - b'A')),
        b'a'..=b'z' => Some(i32::from(x - b'a')),
        _ => None,
    }
}

/// Go `encodeDigit`: lowercase letters then digits.  Every caller's
/// digit is in `0..36` by construction; Go panics otherwise, and so does
/// the index here.
fn encode_digit(digit: i32) -> char {
    char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[digit as usize])
}

/// Go `adapt`: RFC 3492 section 6.1 bias adaptation.
fn adapt(delta: i32, num_points: i32, first_time: bool) -> i32 {
    let mut delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

#[cfg(test)]
mod tests {
    use super::to_ascii;

    /// Outputs of x/net v0.47.0's `idna.ToASCII`, run under Go 1.27.
    #[test]
    fn matches_go_to_ascii() {
        for (input, want) in [
            // Case is kept: UTS-46 would lowercase every label.
            ("Bücher.Example", "xn--Bcher-kva.Example"),
            ("Wörld.Example", "xn--Wrld-5qa.Example"),
            ("héllo.example", "xn--hllo-bpa.example"),
            // A mixed-direction label and a leading combining mark,
            // both of which UTS-46 refuses.
            ("aא.example", "xn--a-0hc.example"),
            ("\u{301}x.example", "xn--x-wbb.example"),
            // `ß` is not mapped to `ss`; an `xn--` label is decoded and
            // re-encoded.
            ("xn--bcher-kva.Straße", "xn--bcher-kva.xn--Strae-oqa"),
            // Empty labels and a trailing dot pass through.
            ("ü..example.", "xn--tda..example."),
            ("日本語", "xn--wgv71a119e"),
        ] {
            assert_eq!(to_ascii(input).as_deref(), Ok(want), "{input}");
        }
    }

    /// An `xn--` label that does not decode is Go's `A3` label error.
    #[test]
    fn bad_punycode_is_an_error() {
        assert_eq!(
            to_ascii("xn---abc.bücher"),
            Err("idna: invalid label \"-abc\"".to_string())
        );
        assert_eq!(
            to_ascii("xn--a\"b-.ü"),
            Ok("a\"b.xn--tda".to_string()),
            "a trailing hyphen leaves the basic code points"
        );
        assert_eq!(
            to_ascii("xn--ab!.ü"),
            Err("idna: invalid label \"ab!\"".to_string())
        );
        // The label is quoted as Go's %q quotes it.
        for (input, label) in [
            ("xn--a\u{a0}b.ü", "\"a\\u00a0b\""),
            ("xn--a\tb.ü", "\"a\\tb\""),
            ("xn--\u{1f600}.ü", "\"\u{1f600}\""),
            ("xn--éx.ü", "\"éx\""),
        ] {
            assert_eq!(
                to_ascii(input),
                Err(format!("idna: invalid label {label}")),
                "{input:?}"
            );
        }
    }
}
