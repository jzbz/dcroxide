// SPDX-License-Identifier: ISC
//! Faithful ports of the Go standard library behaviors the config
//! pipeline observes: `time.Duration` parsing and formatting,
//! `path/filepath.Clean`/`Join`, `os.Expand`, `net.JoinHostPort` /
//! `net.SplitHostPort`, `strconv` conversions, and `os.MkdirAll` with
//! the `*os.PathError` texts its callers print.

// The ports mirror Go's fixed-width arithmetic with explicit
// overflow checks.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_dcrjson::gojson::GoNumError;

/// Format a nanosecond count like Go's `time.Duration.String`.
pub fn go_duration_string(nanos: i64) -> String {
    let neg = nanos < 0;
    let mut u = nanos.unsigned_abs();
    let mut out = String::new();

    const SECOND: u64 = 1_000_000_000;
    if u < SECOND {
        // Special case: if duration is smaller than a second,
        // use smaller units, like 1.2ms
        if u == 0 {
            return "0s".to_string();
        }
        let (unit, prec) = if u < 1_000 {
            ("ns", 0)
        } else if u < 1_000_000 {
            ("µs", 3)
        } else {
            ("ms", 6)
        };
        let (frac, rest) = fmt_frac(u, prec);
        out.push_str(&rest.to_string());
        out.push_str(&frac);
        out.push_str(unit);
    } else {
        let (frac, secs) = fmt_frac(u, 9);
        // u is now integer seconds.
        u = secs;
        let sec_part = format!("{}{}s", u % 60, frac);
        u /= 60;
        // u is now integer minutes.
        if u > 0 {
            out.push_str(&format!("{}m", u % 60));
            u /= 60;
            // u is now integer hours; stop there because days can
            // be different lengths.
            if u > 0 {
                out = format!("{u}h{out}");
            }
        }
        out.push_str(&sec_part);
    }
    if neg {
        out.insert(0, '-');
    }
    out
}

/// Format the fraction of `v / 10**prec` omitting trailing zeros
/// (Go `fmtFrac`); returns the fraction text (with leading dot when
/// non-empty) and the remaining whole part.
fn fmt_frac(mut v: u64, prec: usize) -> (String, u64) {
    let mut digits: Vec<u8> = Vec::new();
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            digits.push(b'0' + digit as u8);
        }
        v /= 10;
    }
    let mut frac = String::new();
    if print {
        frac.push('.');
        for d in digits.iter().rev() {
            frac.push(*d as char);
        }
    }
    (frac, v)
}

/// Quote a string like Go's `strconv.Quote` (the `%q` verb).  This is
/// dcrjson's exact port, `gojson::go_quote`, with Go's `strconv.IsPrint`
/// tables, so the config, version and `strconv` errors quote caller
/// text exactly as the RPC server's errors do.
pub(crate) fn go_quote(s: &str) -> String {
    dcroxide_dcrjson::gojson::go_quote(s)
}

/// Quote a string like the time package's private `quote`
/// (`time/format.go`), which `ParseDuration`'s errors use rather than
/// `strconv.Quote`: every byte of a non-ASCII rune and every control
/// character becomes `\xHH` (there are no `\t` or `\n` forms), only
/// `"` and `\` are backslash-escaped, and DEL stays raw.
fn time_quote(s: &str) -> String {
    let mut buf = String::with_capacity(s.len() + 2);
    buf.push('"');
    for c in s.chars() {
        if c as u32 >= 0x80 || c < ' ' {
            // Unprintable or non-ASCII characters.  A `&str` holds no
            // invalid byte, so a `RuneError` here is a literal U+FFFD
            // and takes its three bytes, as in Go.
            let mut utf8 = [0u8; 4];
            for b in c.encode_utf8(&mut utf8).bytes() {
                buf.push_str(&format!("\\x{b:02x}"));
            }
        } else {
            if c == '"' || c == '\\' {
                buf.push('\\');
            }
            buf.push(c);
        }
    }
    buf.push('"');
    buf
}

/// Parse a duration like Go's `time.ParseDuration`, returning
/// nanoseconds.
pub fn parse_go_duration(orig: &str) -> Result<i64, String> {
    let invalid = || format!("time: invalid duration {}", time_quote(orig));
    let mut s = orig;
    let mut d: u64 = 0;
    let mut neg = false;

    // Consume [-+]?
    if let Some(first) = s.bytes().next()
        && (first == b'-' || first == b'+')
    {
        neg = first == b'-';
        s = &s[1..];
    }
    // Special case: if all that is left is "0", this is zero.
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(invalid());
    }
    while !s.is_empty() {
        // The next character must be [0-9.]
        let c = s.as_bytes()[0];
        if !(c == b'.' || c.is_ascii_digit()) {
            return Err(invalid());
        }
        // Consume [0-9]*
        let pl = s.len();
        let (v_parsed, rest) = leading_int(s).map_err(|_| invalid())?;
        let mut v = v_parsed;
        s = rest;
        let pre = pl != s.len(); // whether we consumed anything before a period

        // Consume (\.[0-9]*)?
        let mut post = false;
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        if !s.is_empty() && s.as_bytes()[0] == b'.' {
            s = &s[1..];
            let pl = s.len();
            let (frac, sc, rest) = leading_fraction(s);
            f = frac;
            scale = sc;
            s = rest;
            post = pl != s.len();
        }
        if !pre && !post {
            // no digits (e.g. ".s" or "-.s")
            return Err(invalid());
        }

        // Consume unit.
        let mut i = 0;
        for (idx, c) in s.char_indices() {
            if c == '.' || c.is_ascii_digit() {
                break;
            }
            i = idx + c.len_utf8();
        }
        if i == 0 {
            return Err(format!(
                "time: missing unit in duration {}",
                time_quote(orig)
            ));
        }
        let u = &s[..i];
        s = &s[i..];
        let unit: u64 = match u {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => {
                return Err(format!(
                    "time: unknown unit {} in duration {}",
                    time_quote(u),
                    time_quote(orig)
                ));
            }
        };
        if v > (1 << 63) / unit {
            // overflow
            return Err(invalid());
        }
        v *= unit;
        if f > 0 {
            // f64 is needed to be nanosecond accurate for fractions
            // of hours (exactly as Go computes it).
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > 1 << 63 {
                return Err(invalid());
            }
        }
        // Go's `d += v` is uint64 arithmetic: two terms of exactly
        // 2^63 wrap to zero, which passes the check below, and Go
        // accepts the zero duration.
        d = d.wrapping_add(v);
        if d > 1 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok((d as i64).wrapping_neg());
    }
    if d > (1 << 63) - 1 {
        return Err(invalid());
    }
    Ok(d as i64)
}

/// Consume the leading `[0-9]*` from `s` (Go `leadingInt`).
fn leading_int(s: &str) -> Result<(u64, &str), ()> {
    let mut x: u64 = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > (1 << 63) / 10 {
            return Err(()); // overflow
        }
        x = x * 10 + u64::from(c - b'0');
        if x > 1 << 63 {
            return Err(()); // overflow
        }
        i += 1;
    }
    Ok((x, &s[i..]))
}

/// Consume the leading `[0-9]*` as a fraction (Go `leadingFraction`):
/// digits past the point of overflow are consumed but ignored.
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            break;
        }
        if !overflow {
            if x > (1 << 63) / 10 {
                overflow = true;
                i += 1;
                continue;
            }
            let y = x * 10 + u64::from(c - b'0');
            if y > 1 << 63 {
                overflow = true;
                i += 1;
                continue;
            }
            x = y;
            scale *= 10.0;
        }
        i += 1;
    }
    (x, scale, &s[i..])
}

/// Clean a path lexically like Go's `path/filepath.Clean` on Unix.
pub(crate) fn filepath_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let b = path.as_bytes();
    let rooted = b[0] == b'/';
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut r = 0;
    let mut dotdot = 0;
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if b[r] == b'/' {
            // Empty path element.
            r += 1;
        } else if b[r] == b'.' && (r + 1 == n || b[r + 1] == b'/') {
            // . element.
            r += 1;
        } else if b[r] == b'.' && b[r + 1] == b'.' && (r + 2 == n || b[r + 2] == b'/') {
            // .. element: remove to last /.
            r += 2;
            if out.len() > dotdot {
                // Can backtrack.
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                // Cannot backtrack, but not rooted, so append ..
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.push(b'.');
                out.push(b'.');
                dotdot = out.len();
            }
        } else {
            // Real path element; add slash if needed.
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && b[r] != b'/' {
                out.push(b[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_string();
    }
    String::from_utf8(out).expect("path bytes remain valid")
}

/// Join path elements like Go's `path/filepath.Join` on Unix.
pub(crate) fn filepath_join(elems: &[&str]) -> String {
    for (i, e) in elems.iter().enumerate() {
        if !e.is_empty() {
            return filepath_clean(&elems[i..].join("/"));
        }
    }
    String::new()
}

/// Whether `path` is already absolute.  A leading `/` counts on every
/// platform — this module cleans and joins with `/`, and the pinned
/// dcrd differential vectors are `/`-rooted — so keeping that check
/// platform-independent preserves parity.  On Windows a drive-rooted
/// path (`C:\` or `C:/`) or a UNC path (`\\host`) is absolute too, so
/// the daemon's real application data directory (e.g. `%LOCALAPPDATA%\
/// Dcroxide`) is not mistaken for a relative path and prefixed with the
/// working directory.
fn is_absolute_path(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    if cfg!(windows) {
        let b = path.as_bytes();
        // Drive-rooted: `X:\` or `X:/`.
        if b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/')
        {
            return true;
        }
        // UNC: `\\host\share` (a `//`-rooted path is already caught above).
        if b.len() >= 2 && b[0] == b'\\' && b[1] == b'\\' {
            return true;
        }
    }
    false
}

/// Make a path absolute like Go's `path/filepath.Abs` (which also
/// cleans the result).
pub(crate) fn filepath_abs(path: &str) -> String {
    if is_absolute_path(path) {
        return filepath_clean(path);
    }
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    filepath_join(&[&cwd, path])
}

/// Whether the byte names a shell special variable (Go
/// `isShellSpecialVar`).
fn is_shell_special_var(c: u8) -> bool {
    matches!(
        c,
        b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-' | b'0'..=b'9'
    )
}

/// Whether the byte is alphanumeric or underscore (Go
/// `isAlphaNum`).
fn is_alpha_num(c: u8) -> bool {
    c == b'_' || c.is_ascii_digit() || c.is_ascii_lowercase() || c.is_ascii_uppercase()
}

/// The name that begins the string and how many bytes it consumes
/// (Go `getShellName`).
fn get_shell_name(s: &str) -> (&str, usize) {
    let b = s.as_bytes();
    if b[0] == b'{' {
        if b.len() > 2 && is_shell_special_var(b[1]) && b[2] == b'}' {
            return (&s[1..2], 3);
        }
        // Scan to closing brace.
        for i in 1..b.len() {
            if b[i] == b'}' {
                if i == 1 {
                    // Bad syntax; eat "${}"
                    return ("", 2);
                }
                return (&s[1..i], i + 1);
            }
        }
        // Bad syntax; eat "${"
        return ("", 1);
    }
    if is_shell_special_var(b[0]) {
        return (&s[0..1], 1);
    }
    // Scan alphanumerics.
    let mut i = 0;
    while i < b.len() && is_alpha_num(b[i]) {
        i += 1;
    }
    (&s[..i], i)
}

/// Expand `$var` and `${var}` like Go's `os.Expand`, with unset
/// variables mapping to the empty string as `os.ExpandEnv` does.
pub(crate) fn expand_env(s: &str, getenv: &dyn Fn(&str) -> Option<String>) -> String {
    let mut buf = String::new();
    let b = s.as_bytes();
    let mut j = 0;
    while j < b.len() {
        if b[j] == b'$' && j + 1 < b.len() {
            let (name, w) = get_shell_name(&s[j + 1..]);
            if name.is_empty() && w > 0 {
                // Encountered invalid syntax; eat the characters.
            } else if name.is_empty() {
                // Valid syntax, but $ was not followed by a name.
                // Leave the dollar character untouched.
                buf.push('$');
            } else {
                buf.push_str(&getenv(name).unwrap_or_default());
            }
            j += 1 + w;
        } else {
            let ch = s[j..].chars().next().expect("in bounds");
            buf.push(ch);
            j += ch.len_utf8();
        }
    }
    buf
}

/// Combine host and port like Go's `net.JoinHostPort`.
pub(crate) fn join_host_port(host: &str, port: &str) -> String {
    // We assume that host is a literal IPv6 address if host has
    // colons.  (Only a colon: the Go releases dcrd builds with do not
    // bracket a host for a `%` alone.)
    if host.contains(':') {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

/// Split host and port like Go's `net.SplitHostPort` (`net/ipsock.go`),
/// with its exact `*AddrError` texts.
pub(crate) fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    // `AddrError.Error` prefixes the address unless it is empty.
    let addr_err = |why: &str| -> Result<(String, String), String> {
        if hostport.is_empty() {
            Err(why.to_string())
        } else {
            Err(format!("address {hostport}: {why}"))
        }
    };
    let b = hostport.as_bytes();
    let (mut j, mut k) = (0, 0);

    // The port starts after the last colon.
    let Some(i) = hostport.rfind(':') else {
        return addr_err(MISSING_PORT);
    };

    let host;
    if b[0] == b'[' {
        // Expect the first ']' just before the last ':'.
        let Some(end) = hostport.find(']') else {
            return addr_err("missing ']' in address");
        };
        match end + 1 {
            // There can't be a ':' behind the ']' now.
            n if n == b.len() => return addr_err(MISSING_PORT),
            // The expected result.
            n if n == i => {}
            // Either ']' isn't followed by a colon, or it is followed
            // by a colon that is not the last one.
            n if b[n] == b':' => return addr_err(TOO_MANY_COLONS),
            _ => return addr_err(MISSING_PORT),
        }
        host = &hostport[1..end];
        // There can't be a '[' resp. ']' before these positions.
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return addr_err(TOO_MANY_COLONS);
        }
    }
    if hostport[j..].contains('[') {
        return addr_err("unexpected '[' in address");
    }
    if hostport[k..].contains(']') {
        return addr_err("unexpected ']' in address");
    }

    Ok((host.to_string(), hostport[i + 1..].to_string()))
}

/// Whether the string parses as an integer like Go's
/// `strconv.Atoi` succeeding.
pub(crate) fn go_atoi_ok(s: &str) -> bool {
    s.parse::<i64>().is_ok()
}

/// Parse a boolean like Go's `strconv.ParseBool`.
pub(crate) fn go_parse_bool(s: &str) -> Result<bool, ()> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(()),
    }
}

/// The Go `strconv.NumError` text for a failed conversion.
fn num_error(func: &str, num: &str, err: &str) -> String {
    format!("strconv.{func}: parsing {}: {err}", go_quote(num))
}

/// Parse a boolean like Go's `strconv.ParseBool`, with the
/// `NumError` text on failure.
pub(crate) fn go_parse_bool_err(s: &str) -> Result<bool, String> {
    go_parse_bool(s).map_err(|()| num_error("ParseBool", s, "invalid syntax"))
}

/// Go's `strconv.ParseUint(s, 0, bit_size)` (`strconv/atoi.go`): the
/// value, or the error with the value Go returns beside it (`maxVal`
/// for `ErrRange`).  The order is Go's: the digits are checked and
/// accumulated left to right, so the first digit that overflows
/// `bit_size` is a range error even when an invalid byte or a
/// misplaced underscore follows it, and the underscores are validated
/// only after the loop.
fn parse_uint_base0(s: &str, bit_size: u32) -> Result<u64, (u64, GoNumError)> {
    if s.is_empty() {
        return Err((0, GoNumError::Syntax));
    }
    let s0 = s;
    let b = s.as_bytes();
    // Look for octal, hex prefix (`lower(c)` is `c | 0x20`).
    let (base, digits): (u64, &[u8]) = if b[0] == b'0' {
        match b.get(1).map(|c| c | 0x20) {
            Some(b'b') if b.len() >= 3 => (2, &b[2..]),
            Some(b'o') if b.len() >= 3 => (8, &b[2..]),
            Some(b'x') if b.len() >= 3 => (16, &b[2..]),
            _ => (8, &b[1..]),
        }
    } else {
        (10, b)
    };

    // Cutoff is the smallest number such that cutoff*base > maxUint64.
    let cutoff = u64::MAX / base + 1;
    let max_val = if bit_size >= 64 {
        u64::MAX
    } else {
        (1u64 << bit_size) - 1
    };

    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in digits {
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => u64::from(c - b'0'),
            _ if (c | 0x20).is_ascii_lowercase() => u64::from((c | 0x20) - b'a' + 10),
            _ => return Err((0, GoNumError::Syntax)),
        };
        if d >= base {
            return Err((0, GoNumError::Syntax));
        }
        if n >= cutoff {
            // n*base overflows
            return Err((max_val, GoNumError::Range));
        }
        n *= base;
        let n1 = n.wrapping_add(d);
        if n1 < n || n1 > max_val {
            // n+d overflows
            return Err((max_val, GoNumError::Range));
        }
        n = n1;
    }

    if underscores && !dcroxide_dcrjson::gojson::underscore_ok(s0) {
        return Err((0, GoNumError::Syntax));
    }
    Ok(n)
}

/// The text of a `strconv` error (`strconv.ErrSyntax`, `ErrRange`).
fn num_error_text(e: GoNumError) -> &'static str {
    match e {
        GoNumError::Syntax => "invalid syntax",
        GoNumError::Range => "value out of range",
    }
}

/// Parse a signed integer like Go's `strconv.ParseInt(s, 0, bits)`,
/// with the `NumError` texts.
pub fn go_parse_int(s: &str, bits: u32) -> Result<i64, String> {
    let fail = |e| num_error("ParseInt", s, num_error_text(e));
    if s.is_empty() {
        return Err(fail(GoNumError::Syntax));
    }

    // Pick off leading sign.
    let (neg, rest) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };

    // Convert unsigned and check range.
    let un = match parse_uint_base0(rest, bits) {
        Ok(un) => un,
        Err((max_val, GoNumError::Range)) => max_val,
        Err((_, e)) => return Err(fail(e)),
    };
    let cutoff = 1u64 << (bits.clamp(1, 64) - 1);
    if !neg && un >= cutoff {
        return Err(fail(GoNumError::Range));
    }
    if neg && un > cutoff {
        return Err(fail(GoNumError::Range));
    }
    let n = un as i64;
    Ok(if neg { n.wrapping_neg() } else { n })
}

/// Parse an unsigned integer like Go's `strconv.ParseUint(s, 0,
/// bits)`, with the `NumError` texts.
pub(crate) fn go_parse_uint(s: &str, bits: u32) -> Result<u64, String> {
    parse_uint_base0(s, bits).map_err(|(_, e)| num_error("ParseUint", s, num_error_text(e)))
}

/// Parse a float like Go's `strconv.ParseFloat(s, 64)`, with the
/// `NumError` text: dcrjson's port, which takes Go's underscores, hex
/// floats and special names (no sign before `NaN`) and refuses an
/// overflowing literal with `ErrRange` where Rust's parser returns
/// infinity.
pub(crate) fn go_parse_float(s: &str) -> Result<f64, String> {
    dcroxide_dcrjson::gojson::go_parse_float_checked(s)
        .map_err(|e| num_error("ParseFloat", s, num_error_text(e)))
}

/// Go's `unhex` (`strconv/quote.go`): only `0-9`, `a-f` and `A-F` are
/// hex digits (no sign, unlike `from_str_radix`).
fn unhex(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some(u32::from(b - b'0')),
        b'a'..=b'f' => Some(u32::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(b - b'A' + 10)),
        _ => None,
    }
}

/// Unquote a Go double-quoted string like `strconv.Unquote` (the only
/// quote form go-flags hands it: a value starting with `"`), with
/// `UnquoteChar`'s escapes -- `\x`, `\u`, `\U` and octal -- and Go's
/// `ErrSyntax` text.  A `\x` or octal escape is a raw byte, so escapes
/// that spell UTF-8 (`\xc3\xa9`) build the character as in Go; a result
/// that is not UTF-8 at all is a Go string a `String` cannot hold, and
/// is refused rather than altered.
pub(crate) fn go_unquote(s: &str) -> Result<String, String> {
    let syntax = || "invalid syntax".to_string();
    if s.len() < 2 || !s.starts_with('"') {
        return Err(syntax());
    }
    let mut buf: Vec<u8> = Vec::with_capacity(s.len());
    let mut rest = &s[1..];
    loop {
        let Some(c) = rest.chars().next() else {
            // No terminating quote.
            return Err(syntax());
        };
        if c == '"' {
            break;
        }
        // Process the next character, rejecting any unescaped newline
        // characters which are invalid.
        if c == '\n' {
            return Err(syntax());
        }
        rest = &rest[c.len_utf8()..];
        if c != '\\' {
            let mut utf8 = [0u8; 4];
            buf.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            continue;
        }

        // Hard case: c is backslash.  The escape is one byte; a
        // non-ASCII one names no escape.
        let Some(&esc) = rest.as_bytes().first() else {
            return Err(syntax());
        };
        if !esc.is_ascii() {
            return Err(syntax());
        }
        rest = &rest[1..];
        match esc {
            b'a' => buf.push(0x07),
            b'b' => buf.push(0x08),
            b'f' => buf.push(0x0c),
            b'n' => buf.push(b'\n'),
            b'r' => buf.push(b'\r'),
            b't' => buf.push(b'\t'),
            b'v' => buf.push(0x0b),
            b'x' | b'u' | b'U' => {
                let n = match esc {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let digits = rest.as_bytes();
                if digits.len() < n {
                    return Err(syntax());
                }
                let mut v: u32 = 0;
                for &d in &digits[..n] {
                    v = v << 4 | unhex(d).ok_or_else(syntax)?;
                }
                rest = &rest[n..];
                if esc == b'x' {
                    // Single-byte string, possibly not UTF-8.
                    buf.push(v as u8);
                    continue;
                }
                // `utf8.ValidRune`: no surrogate, nothing past U+10FFFF.
                let r = char::from_u32(v).ok_or_else(syntax)?;
                let mut utf8 = [0u8; 4];
                buf.extend_from_slice(r.encode_utf8(&mut utf8).as_bytes());
            }
            b'0'..=b'7' => {
                let mut v = u32::from(esc - b'0');
                let digits = rest.as_bytes();
                if digits.len() < 2 {
                    return Err(syntax());
                }
                // One digit already; two more.
                for &d in &digits[..2] {
                    if !(b'0'..=b'7').contains(&d) {
                        return Err(syntax());
                    }
                    v = (v << 3) | u32::from(d - b'0');
                }
                rest = &rest[2..];
                if v > 255 {
                    return Err(syntax());
                }
                buf.push(v as u8);
            }
            b'\\' => buf.push(b'\\'),
            // Only the double quote may be escaped in a double-quoted
            // string.
            b'"' => buf.push(b'"'),
            _ => return Err(syntax()),
        }
    }
    // The terminating quote must end the input.
    if rest.len() != 1 {
        return Err(syntax());
    }
    String::from_utf8(buf).map_err(|_| "the unquoted value is not valid UTF-8".to_string())
}

/// An OS error as Go's `syscall.Errno` renders it.  On Unix that is
/// the C library's text with a lowercase first letter, and on Windows
/// the system message as `FormatMessage` gives it; neither carries
/// Rust's " (os error N)" suffix.  An error with no OS code keeps
/// Rust's rendering.
pub(crate) fn go_errno_string(e: &std::io::Error) -> String {
    let Some(code) = e.raw_os_error() else {
        return e.to_string();
    };
    let text = std::io::Error::from_raw_os_error(code).to_string();
    let text = text.split(" (os error ").next().unwrap_or_default();
    if cfg!(windows) {
        return text.to_string();
    }
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => format!("errno {code}"),
    }
}

/// A Go `*os.PathError`: the operation, the path it failed on, and
/// the OS error.
#[derive(Debug)]
pub(crate) struct GoPathError {
    /// The operation, as Go names it (`open`, `read`, `mkdir`).
    pub op: &'static str,
    /// The path the operation failed on.
    pub path: String,
    /// The underlying OS error.
    pub err: std::io::Error,
}

impl std::fmt::Display for GoPathError {
    /// Go's `PathError.Error`: `e.Op + " " + e.Path + ": " +
    /// e.Err.Error()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.op,
            self.path,
            go_errno_string(&self.err)
        )
    }
}

/// Go's `os.MkdirAll(path, 0700)` (`os/path.go`), with its error: the
/// `*PathError` names the component that failed, the fast path's
/// `ENOTDIR` when the path exists as a file, and the empty path fails
/// with `mkdir : no such file or directory` where Rust's
/// `create_dir_all` returns success.  Directories it creates are
/// owner-only; existing ones keep their mode.
#[cfg(unix)]
pub(crate) fn go_mkdir_all_owner_only(path: &str) -> Result<(), GoPathError> {
    use std::os::unix::fs::DirBuilderExt;

    // Fast path: if we can tell whether path is a directory or file,
    // stop with success or error.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.is_dir() {
            return Ok(());
        }
        return Err(GoPathError {
            op: "mkdir",
            path: path.to_string(),
            err: std::io::Error::from_raw_os_error(libc::ENOTDIR),
        });
    }

    // Slow path: make sure parent exists and then call Mkdir for path.
    // Extract the parent folder by first removing any trailing path
    // separator and then scanning backward until finding a path
    // separator or reaching the beginning of the string.
    let b = path.as_bytes();
    let mut i = b.len();
    while i > 0 && b[i - 1] == b'/' {
        i -= 1;
    }
    while i > 0 && b[i - 1] != b'/' {
        i -= 1;
    }
    // Go's index stops on the separator itself, so the parent leaves it
    // out; the volume name is empty on Unix.
    let parent = &path[..i.saturating_sub(1)];
    if !parent.is_empty() {
        go_mkdir_all_owner_only(parent)?;
    }

    // Parent now exists; invoke Mkdir and use its result.
    if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(path) {
        // Handle arguments like "foo/." by double-checking that the
        // directory doesn't exist.
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            return Ok(());
        }
        return Err(GoPathError {
            op: "mkdir",
            path: path.to_string(),
            err,
        });
    }
    Ok(())
}

/// Off Unix the volume-name rules of Go's `MkdirAll` are not ported:
/// the standard library creates the tree and a failure is reported
/// against the whole path.  The empty path still fails, as Go's
/// `Mkdir("")` does, rather than succeeding as `create_dir_all("")`
/// would.
#[cfg(not(unix))]
pub(crate) fn go_mkdir_all_owner_only(path: &str) -> Result<(), GoPathError> {
    let result = if path.is_empty() {
        std::fs::create_dir(path)
    } else {
        std::fs::create_dir_all(path)
    };
    result.map_err(|err| GoPathError {
        op: "mkdir",
        path: path.to_string(),
        err,
    })
}

#[cfg(test)]
mod tests {
    use super::go_quote;

    /// Go `strconv.Quote` outputs for the escape classes the config
    /// error paths can carry, including the format, private-use and
    /// unassigned runes only Go's `IsPrint` tables reject.
    #[test]
    fn go_quote_matches_strconv_quote() {
        let cases = [
            ("plain", "\"plain\""),
            ("a\"b", "\"a\\\"b\""),
            ("C:\\foo", "\"C:\\\\foo\""),
            ("tab\there", "\"tab\\there\""),
            ("\u{01}", "\"\\x01\""),
            ("\u{7f}", "\"\\x7f\""),
            ("bell\u{07}", "\"bell\\a\""),
            ("h\u{e9}llo", "\"h\u{e9}llo\""),
            ("nb\u{a0}sp", "\"nb\\u00a0sp\""),
            ("soft\u{ad}hyphen", "\"soft\\u00adhyphen\""),
            ("zero\u{200b}width", "\"zero\\u200bwidth\""),
            ("\u{378}", "\"\\u0378\""),
            ("\u{e000}", "\"\\ue000\""),
            ("\u{f0000}", "\"\\U000f0000\""),
            ("", "\"\""),
        ];
        for (input, want) in cases {
            assert_eq!(go_quote(input), want, "{input:?}");
        }
    }

    use super::*;

    /// `split_host_port` matches Go's `net.SplitHostPort`, reporting a
    /// missing port (never panicking) when a bracketed host is followed
    /// by a trailing character — including a multibyte one.
    #[test]
    fn split_host_port_matches_go() {
        assert_eq!(
            split_host_port("[::1]:80").unwrap(),
            ("::1".to_string(), "80".to_string())
        );
        for missing in ["[::1]", "[::1]x", "[::1]\u{20ac}"] {
            assert_eq!(
                split_host_port(missing).unwrap_err(),
                format!("address {missing}: missing port in address"),
                "{missing}"
            );
        }
        assert_eq!(
            split_host_port("[::1]::80").unwrap_err(),
            "address [::1]::80: too many colons in address"
        );
    }

    #[test]
    fn duration_round_trips() {
        // Values mirror Go's time package documentation examples.
        for (nanos, s) in [
            (0i64, "0s"),
            (1, "1ns"),
            (1_100, "1.1µs"),
            (2_200_000, "2.2ms"),
            (3_300_000_000, "3.3s"),
            (245_000_000_000, "4m5s"),
            (245_001_000_000, "4m5.001s"),
            (18_000_000_000_000 + 360_000_000_000, "5h6m0s"),
            (30_000_000_000, "30s"),
            (86_400_000_000_000, "24h0m0s"),
            (120_000_000_000, "2m0s"),
            (-3_600_000_000_000, "-1h0m0s"),
            (500_000_000, "500ms"),
        ] {
            assert_eq!(go_duration_string(nanos), s, "{nanos}");
        }
        for (s, nanos) in [
            ("30s", 30_000_000_000i64),
            ("24h", 86_400_000_000_000),
            ("1h30m", 5_400_000_000_000),
            ("500ms", 500_000_000),
            ("1.5h", 5_400_000_000_000),
            ("-2m", -120_000_000_000),
            ("0", 0),
        ] {
            assert_eq!(parse_go_duration(s).unwrap(), nanos, "{s}");
        }
        assert_eq!(
            parse_go_duration("5").unwrap_err(),
            "time: missing unit in duration \"5\""
        );
        assert_eq!(
            parse_go_duration("5x").unwrap_err(),
            "time: unknown unit \"x\" in duration \"5x\""
        );
        assert_eq!(
            parse_go_duration("").unwrap_err(),
            "time: invalid duration \"\""
        );
    }

    #[test]
    fn clean_matches_go() {
        for (input, want) in [
            ("", "."),
            ("abc", "abc"),
            ("abc/def", "abc/def"),
            ("a/b/c/..", "a/b"),
            ("/../abc", "/abc"),
            ("abc//def//ghi", "abc/def/ghi"),
            ("./abc", "abc"),
            ("abc/./def", "abc/def"),
            ("/", "/"),
            ("../../abc", "../../abc"),
            ("abc/../..", ".."),
        ] {
            assert_eq!(filepath_clean(input), want, "{input}");
        }
    }

    #[test]
    fn expand_matches_go() {
        let getenv = |name: &str| match name {
            "FOO" => Some("bar".to_string()),
            _ => None,
        };
        for (input, want) in [
            ("$FOO/x", "bar/x"),
            ("${FOO}baz", "barbaz"),
            ("$UNSET/x", "/x"),
            ("a$", "a$"),
            ("${}", ""),
            ("$1", ""),
        ] {
            assert_eq!(expand_env(input, &getenv), want, "{input}");
        }
    }

    /// `ParseDuration` quotes its errors with the time package's own
    /// `quote`, not `strconv.Quote`, and wraps its uint64 sum as Go does
    /// (outputs from a Go 1.27 run).
    #[test]
    fn duration_errors_and_wrap_match_go() {
        for (input, want) in [
            (
                "1\u{b5}",
                r#"time: unknown unit "\xc2\xb5" in duration "1\xc2\xb5""#,
            ),
            ("5\tm", r#"time: unknown unit "\x09m" in duration "5\x09m""#),
            (
                "5x\u{7f}",
                "time: unknown unit \"x\u{7f}\" in duration \"5x\u{7f}\"",
            ),
            (
                "5\"q\\",
                r#"time: unknown unit "\"q\\" in duration "5\"q\\""#,
            ),
            (
                "1\u{fffd}s",
                r#"time: unknown unit "\xef\xbf\xbds" in duration "1\xef\xbf\xbds""#,
            ),
            ("\u{1}", r#"time: invalid duration "\x01""#),
        ] {
            assert_eq!(parse_go_duration(input).unwrap_err(), want, "{input:?}");
        }
        assert_eq!(
            parse_go_duration("9223372036854775808ns9223372036854775808ns"),
            Ok(0)
        );
    }

    /// `net.JoinHostPort` brackets for a colon only, and
    /// `net.SplitHostPort` scans the whole address for stray brackets
    /// after its bracket switch, with Go's text for each (outputs from a
    /// Go 1.27 run).
    #[test]
    fn host_port_edges_match_go() {
        assert_eq!(join_host_port("host%zone", "9108"), "host%zone:9108");
        assert_eq!(join_host_port("::1%eth0", "1"), "[::1%eth0]:1");

        for (input, want) in [
            ("[a[b]:80", "address [a[b]:80: unexpected '[' in address"),
            ("[::1]:80]", "address [::1]:80]: unexpected ']' in address"),
            ("[abc", "address [abc: missing port in address"),
            ("[x", "address [x: missing port in address"),
            ("a]:80", "address a]:80: unexpected ']' in address"),
            ("a[b:80", "address a[b:80: unexpected '[' in address"),
            ("[a]b]:80", "address [a]b]:80: missing port in address"),
            ("[::1]]:80", "address [::1]]:80: missing port in address"),
            ("[::1]x:1", "address [::1]x:1: missing port in address"),
            ("[::1]:x:1", "address [::1]:x:1: too many colons in address"),
            ("a:b:c", "address a:b:c: too many colons in address"),
            ("", "missing port in address"),
        ] {
            assert_eq!(split_host_port(input).unwrap_err(), want, "{input}");
        }
        for (input, host, port) in [(":80", "", "80"), ("[]:80", "", "80")] {
            assert_eq!(
                split_host_port(input).unwrap(),
                (host.to_string(), port.to_string()),
                "{input}"
            );
        }
    }

    /// `strconv.ParseInt` and `ParseUint` in Go's order: the first digit
    /// that overflows is a range error even when an invalid byte or a
    /// misplaced underscore follows, and the underscores are checked
    /// last (outputs from a Go 1.27 run).
    #[test]
    fn integer_parsing_matches_go() {
        let int_cases: [(&str, Result<i64, &str>); 18] = [
            ("99999999999999999999x", Err("value out of range")),
            ("9999999999999999999x", Err("invalid syntax")),
            ("-99999999999999999999_", Err("value out of range")),
            ("99999999999999999999_", Err("value out of range")),
            ("0xFFFFFFFFFFFFFFFFF", Err("value out of range")),
            ("0x8000000000000000", Err("value out of range")),
            ("-0x8000000000000000", Ok(i64::MIN)),
            ("1_000", Ok(1000)),
            ("0x_1F", Ok(31)),
            ("0_1", Ok(1)),
            ("0o17", Ok(15)),
            ("0x", Err("invalid syntax")),
            ("0b", Err("invalid syntax")),
            ("08", Err("invalid syntax")),
            ("1__0", Err("invalid syntax")),
            ("_1", Err("invalid syntax")),
            ("+", Err("invalid syntax")),
            ("0b102", Err("invalid syntax")),
        ];
        for (input, want) in int_cases {
            let want =
                want.map_err(|e| format!("strconv.ParseInt: parsing {}: {e}", go_quote(input)));
            assert_eq!(go_parse_int(input, 64), want, "{input}");
        }
        let uint32_cases: [(&str, Result<u64, &str>); 5] = [
            ("4294967296x", Err("value out of range")),
            ("42949672960_", Err("value out of range")),
            ("0x1_0000_0000", Err("value out of range")),
            ("4294967295", Ok(4_294_967_295)),
            ("+1", Err("invalid syntax")),
        ];
        for (input, want) in uint32_cases {
            let want =
                want.map_err(|e| format!("strconv.ParseUint: parsing {}: {e}", go_quote(input)));
            assert_eq!(go_parse_uint(input, 32), want, "{input}");
        }
    }

    /// `strconv.ParseFloat`: underscores, hex floats and `ErrRange` on
    /// overflow, and no sign before `NaN` (outputs from a Go 1.27 run).
    #[test]
    fn float_parsing_matches_go() {
        let cases: [(&str, Result<f64, &str>); 12] = [
            ("0.000_1", Ok(0.0001)),
            ("0x1p-14", Ok(6.103515625e-05)),
            ("0x1.8p1", Ok(3.0)),
            ("0x_1p0", Ok(1.0)),
            ("1e-400", Ok(0.0)),
            ("1e400", Err("value out of range")),
            ("-1e400", Err("value out of range")),
            ("0x1p1024", Err("value out of range")),
            ("-0x1p99999", Err("value out of range")),
            ("+nan", Err("invalid syntax")),
            ("1e_5", Err("invalid syntax")),
            ("1e400x", Err("invalid syntax")),
        ];
        for (input, want) in cases {
            let want =
                want.map_err(|e| format!("strconv.ParseFloat: parsing {}: {e}", go_quote(input)));
            assert_eq!(go_parse_float(input), want, "{input}");
        }
        assert!(go_parse_float("NaN").unwrap().is_nan());
        assert_eq!(go_parse_float("-Inf"), Ok(f64::NEG_INFINITY));
    }

    /// `strconv.Unquote` of a double-quoted value: `\U`, byte escapes
    /// that spell UTF-8, and hex digits that are only hex digits
    /// (outputs from a Go 1.27 run).
    #[test]
    fn unquote_matches_go() {
        for (input, want) in [
            (r#""\U0001F600""#, "\u{1f600}"),
            (r#""\xc3\xa9""#, "\u{e9}"),
            (r#""\303\251""#, "\u{e9}"),
            (r#""\x41B""#, "AB"),
            ("\"\u{e9}x\"", "\u{e9}x"),
            (r#""a\"b""#, "a\"b"),
        ] {
            assert_eq!(go_unquote(input).as_deref(), Ok(want), "{input}");
        }
        for input in [
            r#""\x+1""#,
            r#""\u+12f""#,
            r#""\U00110000""#,
            r#""\ud800""#,
            r#""a\'b""#,
            r#""a"b""#,
            r#""a"#,
            r#""\x4""#,
            r#""\1""#,
            r#""\400""#,
            r#""a"""#,
            "\"a\nb\"",
        ] {
            assert_eq!(
                go_unquote(input),
                Err("invalid syntax".to_string()),
                "{input}"
            );
        }
        // Go takes the raw byte; a `String` cannot hold it.
        assert_eq!(
            go_unquote(r#""\xff""#),
            Err("the unquoted value is not valid UTF-8".to_string())
        );
    }

    /// Go's `os.MkdirAll`: the empty path fails where `create_dir_all`
    /// succeeds, the error names the component that failed as a
    /// `*PathError`, a trailing `.` is double-checked, and what it
    /// creates is owner-only.
    #[cfg(unix)]
    #[test]
    fn mkdir_all_matches_go() {
        use super::go_mkdir_all_owner_only;
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            go_mkdir_all_owner_only("").unwrap_err().to_string(),
            "mkdir : no such file or directory"
        );

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let nested = format!("{root}/a/b/");
        go_mkdir_all_owner_only(&nested).unwrap();
        for created in [format!("{root}/a"), format!("{root}/a/b")] {
            let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{created}");
        }
        go_mkdir_all_owner_only(&nested).unwrap();
        go_mkdir_all_owner_only(&format!("{root}/c/.")).unwrap();

        let file = format!("{root}/file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            go_mkdir_all_owner_only(&file).unwrap_err().to_string(),
            format!("mkdir {file}: not a directory")
        );
        assert_eq!(
            go_mkdir_all_owner_only(&format!("{file}/x/y"))
                .unwrap_err()
                .to_string(),
            format!("mkdir {file}: not a directory")
        );
    }
}
