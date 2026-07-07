// SPDX-License-Identifier: ISC
//! Faithful ports of the Go standard library behaviors the config
//! pipeline observes: `time.Duration` parsing and formatting,
//! `path/filepath.Clean`/`Join`, `os.Expand`, `net.JoinHostPort` /
//! `net.SplitHostPort`, and `strconv` conversions.

// The ports mirror Go's fixed-width arithmetic with explicit
// overflow checks.
#![allow(clippy::arithmetic_side_effects)]

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

/// Quote a string like Go's `strconv.Quote` for the plain ASCII
/// inputs the config errors carry.
pub(crate) fn go_quote(s: &str) -> String {
    format!("\"{s}\"")
}

/// Parse a duration like Go's `time.ParseDuration`, returning
/// nanoseconds.
pub fn parse_go_duration(orig: &str) -> Result<i64, String> {
    let invalid = || format!("time: invalid duration {}", go_quote(orig));
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
            return Err(format!("time: missing unit in duration {}", go_quote(orig)));
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
                    go_quote(u),
                    go_quote(orig)
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
        d += v;
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

/// Make a path absolute like Go's `path/filepath.Abs` (which also
/// cleans the result).
pub(crate) fn filepath_abs(path: &str) -> String {
    if path.starts_with('/') {
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
    // Add brackets when the host contains a colon or a percent sign.
    if host.contains(':') || host.contains('%') {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

/// Split host and port like Go's `net.SplitHostPort`, with Go's
/// exact error texts.
pub(crate) fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let missing_port = || format!("address {hostport}: missing port in address");
    let too_many_colons = || format!("address {hostport}: too many colons in address");
    let bytes = hostport.as_bytes();
    if let Some(stripped) = hostport.strip_prefix('[') {
        // IPv6 literal in brackets.
        let Some(end) = stripped.find(']') else {
            return Err(format!("address {hostport}: missing ']' in address"));
        };
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let Some(port) = rest.strip_prefix(':') else {
            if rest.is_empty() {
                return Err(missing_port());
            }
            return Err(format!(
                "address {hostport}: unexpected '{}' after address",
                &rest[..1]
            ));
        };
        if port.contains(':') {
            return Err(too_many_colons());
        }
        return Ok((host.to_string(), port.to_string()));
    }
    let Some(colon) = hostport.rfind(':') else {
        return Err(missing_port());
    };
    let host = &hostport[..colon];
    let port = &hostport[colon + 1..];
    if host.contains(':') {
        return Err(too_many_colons());
    }
    if bytes.contains(&b'[') || bytes.contains(&b']') {
        return Err(format!("address {hostport}: unexpected '[' in address"));
    }
    Ok((host.to_string(), port.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
