// SPDX-License-Identifier: ISC
//! HTTPS seeding (dcrd addrmgr `seed.go`; relocated verbatim from
//! connmgr in dcrd 2.2, which renames the reflected JSON node type to
//! `addrmgr.node`).

// Bounded scanning arithmetic mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_dcrjson::{GoType, GoValue, StructField, gojson};
use dcroxide_wire::{NetAddress, ServiceFlag};

/// Three days in nanoseconds (dcrd `duration3Days`).
pub const DURATION_3_DAYS: i64 = 24 * 60 * 60 * 3 * 1_000_000_000;

/// Four days in nanoseconds (dcrd `duration4Days`).
pub const DURATION_4_DAYS: i64 = 24 * 60 * 60 * 4 * 1_000_000_000;

const MAX_NODES: usize = 16;
/// The maximum bytes read from an untrusted seeder response (dcrd's
/// `io.LimitReader(resp.Body, maxNodes*maxAddrLen)`).
pub const MAX_RESP_SIZE: usize = MAX_NODES * 256;

/// Filter parameters for a request to an HTTPS seeder (dcrd
/// `HttpsSeederFilters`).
#[derive(Default, Clone, Debug)]
pub struct HttpsSeederFilters {
    ip_version: u16,
    has_ip_version: bool,
    pver: u32,
    has_pver: bool,
    services: u64,
    has_services: bool,
}

impl HttpsSeederFilters {
    /// Filter all results that are not the provided IP version, 4 or 6
    /// (dcrd `SeedFilterIPVersion`).
    pub fn ip_version(mut self, ip_version: u16) -> Self {
        self.ip_version = ip_version;
        self.has_ip_version = true;
        self
    }

    /// Filter all results that are not the provided protocol version
    /// (dcrd `SeedFilterProtocolVersion`).
    pub fn protocol_version(mut self, pver: u32) -> Self {
        self.pver = pver;
        self.has_pver = true;
        self
    }

    /// Filter all results that do not support the provided service
    /// flags (dcrd `SeedFilterServices`).
    pub fn services(mut self, services: u64) -> Self {
        self.services = services;
        self.has_services = true;
        self
    }
}

/// The transport used to contact the HTTPS seeder.  The daemon
/// supplies a TLS-capable HTTP client honoring any proxy
/// configuration; tests supply scripted responses.
pub trait SeederTransport {
    /// Perform a GET for the URL, returning the HTTP status code and
    /// the response body.
    fn get(&mut self, url: &str) -> Result<(u32, Vec<u8>), String>;
}

/// The time source and randomness used to stamp discovered addresses.
pub trait SeedEnv {
    /// The current time in unix nanoseconds.
    fn now_nanos(&mut self) -> i64;
    /// A uniformly random duration in `[0, max)` nanoseconds (dcrd
    /// `rand.Duration`).
    fn rand_duration(&mut self, max_nanos: i64) -> i64;

    /// Report what a seeder round found, at info level.
    ///
    /// dcrd's addrmgr logs through a logger the daemon injects with
    /// `addrmgr.UseLogger(amgrLog)` (`log.go` 84), which is why its
    /// output carries the `AMGR` tag.  This trait is that injection
    /// point: the crate cannot reach the daemon's logging module, and
    /// threading a logger through would duplicate a seam already here.
    /// The default is silent so the vector tests stay quiet.
    fn log_info(&mut self, _msg: &str) {}

    /// Report a malformed entry a seeder returned, at warn level (dcrd
    /// `log.Warnf` in `querySeeder`).
    fn log_warn(&mut self, _msg: &str) {}
}

/// The JSON object shape returned by the https seeders (dcrd `node`).
fn node_type() -> GoType {
    GoType::Named(
        "addrmgr".to_string(),
        "node".to_string(),
        Box::new(GoType::Struct(vec![
            StructField::new("Host", GoType::String).with_json_tag("host"),
            StructField::new("Services", GoType::Uint64).with_json_tag("services"),
            StructField::new("ProtocolVersion", GoType::Uint32).with_json_tag("pver"),
        ])),
    )
}

/// The request URL for a seeder and set of filters, exactly as dcrd
/// builds it (path `/api/addrs` with the filter query parameters
/// encoded in sorted order by Go's `url.Values.Encode`).
pub fn seeder_url(seeder: &str, filters: &HttpsSeederFilters) -> String {
    let mut params: Vec<(&str, String)> = Vec::new();
    if filters.has_ip_version {
        params.push(("ipversion", filters.ip_version.to_string()));
    }
    if filters.has_pver {
        params.push(("pver", filters.pver.to_string()));
    }
    if filters.has_services {
        params.push(("services", filters.services.to_string()));
    }
    // Go's url.Values.Encode emits keys in sorted order; the insertion
    // order above is already sorted.
    let mut url = format!("https://{seeder}/api/addrs");
    if !params.is_empty() {
        url.push('?');
        let encoded: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        url.push_str(&encoded.join("&"));
    }
    url
}

/// Whether Go's JSON scanner treats the byte as whitespace (`isSpace`).
pub(crate) fn is_json_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// Frame the JSON value `rest` begins with, at a byte that is not
/// whitespace, as Go's `Decoder.readValue` frames it over a reader that
/// ends where `rest` does, returning the value's length.  The scanner's
/// first syntax error inside the value is the error, found as the
/// scanner meets it and not only once brackets fail to balance.  A value
/// the input ends partway through is `unexpected EOF`, whatever the
/// scanner was in the middle of.  A value that completes ends where the
/// scanner ends it, and what follows is left for the next read, which
/// Go does not look at before then.  Bytes inside a string need not be
/// UTF-8: the scanner takes anything from 0x20 up there.
///
/// This is the crate's one model of Go's `json.Decoder`: the peers file
/// reads its first value through it and a seeder response its stream of
/// values.
pub(crate) fn read_value(rest: &[u8]) -> Result<usize, String> {
    let err = match gojson::validate_bytes(rest) {
        // One value, then only whitespace.
        Ok(()) => return Ok(rest.len()),
        Err(err) => err.go_message(),
    };
    // The scanner stops at the first byte it rejects, so an error that
    // an appended byte changes is one the end of the input raised (0x01
    // is rejected in every state, and names itself when it is).
    let mut extended = rest.to_vec();
    extended.push(0x01);
    if gojson::validate_bytes(&extended).map_err(|err| err.go_message()) != Err(err.clone()) {
        return Err("unexpected EOF".to_string());
    }
    if !err.ends_with("after top-level value") {
        return Err(err);
    }
    Ok(complete_value_len(rest))
}

/// The length of the complete JSON value that starts `rest` and that
/// something other than whitespace follows.  Go's scanner ends a number
/// or a literal at the first byte that cannot continue it, so `123-4`
/// and `nullx` are the values `123` and `null`.
fn complete_value_len(rest: &[u8]) -> usize {
    match rest[0] {
        b'{' | b'[' | b'"' => bracketed_value_len(rest),
        b't' | b'n' => 4,
        b'f' => 5,
        _ => {
            // -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?, which the
            // scanner has already accepted.
            let digits = |mut i: usize| {
                while rest.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                i
            };
            let mut i = usize::from(rest[0] == b'-');
            i = if rest.get(i) == Some(&b'0') {
                i + 1
            } else {
                digits(i)
            };
            if rest.get(i) == Some(&b'.') {
                i = digits(i + 1);
            }
            if matches!(rest.get(i), Some(b'e' | b'E')) {
                i += 1;
                if matches!(rest.get(i), Some(b'+' | b'-')) {
                    i += 1;
                }
                i = digits(i);
            }
            i
        }
    }
}

/// The length of the object, array or string that starts `rest`.  The
/// scanner has already accepted it, so its brackets balance and its
/// strings close, and counting brackets outside strings finds its end.
fn bracketed_value_len(rest: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &c) in rest.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
                if depth == 0 {
                    return i + 1;
                }
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    rest.len()
}

/// Split host and port like Go's `net.SplitHostPort`, returning the
/// host and port strings.
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
        match end.saturating_add(1) {
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
        (j, k) = (1, end.saturating_add(1));
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

    Ok((
        host.to_string(),
        hostport[i.saturating_add(1)..].to_string(),
    ))
}

/// Parse an IP like Go's `net.ParseIP`, returning the 16-byte form.
fn parse_ip(host: &str) -> Option<[u8; 16]> {
    // Rust's parser matches Go's acceptance for the shapes seeders
    // return: dotted IPv4 without leading zeros and RFC 4291 IPv6.
    // Go rejects zoned addresses in ParseIP, as does Rust.
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&v4.octets());
            Some(ip)
        }
        Ok(std::net::IpAddr::V6(v6)) => Some(v6.octets()),
        Err(_) => None,
    }
}

/// Use HTTPS seeding to return a list of addresses of p2p peers on
/// the network (dcrd `SeedAddrs`).  Addresses the seeder returns with
/// invalid hosts or ports are skipped exactly as dcrd skips them, and
/// each discovered address is stamped with a time randomly selected
/// between 3 and 7 days ago.
pub fn seed_addrs<T: SeederTransport, E: SeedEnv>(
    seeder: &str,
    transport: &mut T,
    env: &mut E,
    filters: &HttpsSeederFilters,
) -> Result<Vec<NetAddress>, String> {
    let url = seeder_url(seeder, filters);
    let (status, body) = transport.get(&url)?;

    if status != 200 {
        return Err(format!(
            "seeder {seeder} returned invalid status code '{status}': {}",
            http_status_text(status),
        ));
    }

    // Parse the JSON response, mirroring dcrd's byte-limited streaming
    // decode capped at maxNodes objects.
    let body = &body[..body.len().min(MAX_RESP_SIZE)];
    let ntype = node_type();
    let mut nodes: Vec<(String, u64, u32)> = Vec::new();
    let mut pos = 0usize;
    // `dec.More()`: skip whitespace; the end of the input or a closing
    // bracket ends the stream, and the nodes decoded so far are kept.
    while let Some(start) = body[pos..]
        .iter()
        .position(|&c| !is_json_space(c))
        .map(|skipped| pos + skipped)
    {
        if matches!(body[start], b']' | b'}') {
            break;
        }
        // `dec.Decode(&node)`: frame the value, then unmarshal it, a
        // byte that is not UTF-8 inside a string becoming U+FFFD.
        let end = start
            + read_value(&body[start..]).map_err(|e| format!("unable to parse response: {e}"))?;
        let value = gojson::unmarshal_input(&body[start..end])
            .and_then(|text| gojson::decode(&ntype, &text))
            .map_err(|e| format!("unable to parse response: {}", e.go_message()))?;
        let fields = match value {
            GoValue::Struct(fields) => fields,
            _ => unreachable!(),
        };
        let host = match &fields[0] {
            GoValue::String(s) => s.clone(),
            _ => String::new(),
        };
        let services = match &fields[1] {
            GoValue::Uint(u) => *u,
            _ => 0,
        };
        let pver = match &fields[2] {
            GoValue::Uint(u) => *u as u32,
            _ => 0,
        };
        nodes.push((host, services, pver));
        pos = end;
        if nodes.len() >= MAX_NODES {
            break;
        }
    }

    // Nothing more to do when no addresses are returned.
    if nodes.is_empty() {
        env.log_info(&format!("0 addresses found from seeder {seeder}"));
        return Ok(Vec::new());
    }

    // Convert the response to net addresses.
    let mut addrs = Vec::with_capacity(nodes.len());
    for (host_port, services, _pver) in &nodes {
        let Ok((host, port_str)) = split_host_port(host_port) else {
            env.log_warn(&format!("seeder returned invalid host \"{host_port}\""));
            continue;
        };
        let Ok(port) = go_parse_port(&port_str) else {
            env.log_warn(&format!("seeder returned invalid port \"{host_port}\""));
            continue;
        };
        let Some(ip) = parse_ip(&host) else {
            env.log_warn(&format!(
                "seeder returned a hostname that is not an IP address \"{host}\""
            ));
            continue;
        };

        // Set the timestamp to a value randomly selected between 3 and
        // 7 days ago.
        let ts_nanos = env.now_nanos() - (DURATION_3_DAYS + env.rand_duration(DURATION_4_DAYS));
        addrs.push(NetAddress {
            timestamp: (ts_nanos / 1_000_000_000) as u32,
            services: ServiceFlag(*services),
            ip,
            port,
        });
    }

    // dcrd reports the yield per seeder, naming it, and says how many
    // entries it had to exclude when any were malformed.
    if addrs.len() < nodes.len() {
        env.log_info(&format!(
            "{} addresses found from seeder {seeder} (excluded {} invalid)",
            addrs.len(),
            nodes.len().saturating_sub(addrs.len())
        ));
    } else {
        env.log_info(&format!(
            "{} addresses found from seeder {seeder}",
            addrs.len()
        ));
    }

    Ok(addrs)
}

/// Parse a port like Go's `strconv.ParseUint(portStr, 10, 16)`, with
/// its `NumError` texts: decimal digits only, no sign, and the digits
/// accumulate left to right, so an overflow is reported before a later
/// non-digit, as in Go.
pub(crate) fn go_parse_port(s: &str) -> Result<u16, String> {
    let error = |reason: &str| {
        format!(
            "strconv.ParseUint: parsing {}: {reason}",
            gojson::go_quote(s)
        )
    };
    if s.is_empty() {
        return Err(error("invalid syntax"));
    }
    let mut n: u16 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(error("invalid syntax"));
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u16::from(c - b'0')))
            .ok_or_else(|| error("value out of range"))?;
    }
    Ok(n)
}

/// The status text Go's `http.StatusText` returns for the codes a
/// seeder can plausibly produce.
fn http_status_text(code: u32) -> &'static str {
    match code {
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
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

    /// The bracket checks run over the whole address, as Go's
    /// `SplitHostPort` does after its bracket switch, and each stray
    /// bracket and the empty address get Go's own text.
    #[test]
    fn split_host_port_rejects_stray_brackets() {
        for (input, want) in [
            ("[a[b]:80", "address [a[b]:80: unexpected '[' in address"),
            ("[::1]:80]", "address [::1]:80]: unexpected ']' in address"),
            ("[abc", "address [abc: missing port in address"),
            ("a]:80", "address a]:80: unexpected ']' in address"),
            ("a[b:80", "address a[b:80: unexpected '[' in address"),
            ("[a]b]:80", "address [a]b]:80: missing port in address"),
            ("", "missing port in address"),
        ] {
            assert_eq!(split_host_port(input).unwrap_err(), want, "{input}");
        }
        assert_eq!(
            split_host_port("[]:80").unwrap(),
            (String::new(), "80".to_string())
        );
    }

    /// `go_parse_port` is Go's `strconv.ParseUint(s, 10, 16)`: the same
    /// accepted set and the same `NumError` texts, the overflow reported
    /// at the digit that overflows, before a later bad byte.
    #[test]
    fn go_parse_port_matches_go() {
        assert_eq!(go_parse_port("9108"), Ok(9108));
        assert_eq!(go_parse_port("65535"), Ok(65535));
        assert_eq!(go_parse_port("009108"), Ok(9108));
        for (input, want) in [
            ("", r#"strconv.ParseUint: parsing "": invalid syntax"#),
            (
                "+9108",
                r#"strconv.ParseUint: parsing "+9108": invalid syntax"#,
            ),
            (
                "0x10",
                r#"strconv.ParseUint: parsing "0x10": invalid syntax"#,
            ),
            (
                "9_108",
                r#"strconv.ParseUint: parsing "9_108": invalid syntax"#,
            ),
            (
                "65536",
                r#"strconv.ParseUint: parsing "65536": value out of range"#,
            ),
            (
                "99999x",
                r#"strconv.ParseUint: parsing "99999x": value out of range"#,
            ),
            (
                "x99999",
                r#"strconv.ParseUint: parsing "x99999": invalid syntax"#,
            ),
        ] {
            assert_eq!(go_parse_port(input), Err(want.to_string()), "{input}");
        }
    }
}
