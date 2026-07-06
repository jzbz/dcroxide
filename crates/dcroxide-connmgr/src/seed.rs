// SPDX-License-Identifier: ISC
//! HTTPS seeding (dcrd connmgr `seed.go`).

// Bounded scanning arithmetic mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_dcrjson::{GoType, GoValue, StructField, gojson};
use dcroxide_wire::{NetAddress, ServiceFlag};

/// Three days in nanoseconds (dcrd `duration3Days`).
pub const DURATION_3_DAYS: i64 = 24 * 60 * 60 * 3 * 1_000_000_000;

/// Four days in nanoseconds (dcrd `duration4Days`).
pub const DURATION_4_DAYS: i64 = 24 * 60 * 60 * 4 * 1_000_000_000;

const MAX_NODES: usize = 16;
const MAX_RESP_SIZE: usize = MAX_NODES * 256;

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
}

/// The JSON object shape returned by the https seeders (dcrd `node`).
fn node_type() -> GoType {
    GoType::Named(
        "connmgr".to_string(),
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

/// Scan one JSON value starting at `pos`, returning the value's start
/// and end offsets, or `None` when only whitespace remains, and `Err`
/// when the value is truncated.  This mirrors the framing behavior of
/// Go's `json.Decoder` over a byte-limited stream.
fn next_value_extent(data: &[u8], pos: usize) -> Result<Option<(usize, usize)>, String> {
    let mut pos = pos;
    while pos < data.len() && matches!(data[pos], b' ' | b'\t' | b'\n' | b'\r') {
        pos += 1;
    }
    if pos >= data.len() {
        return Ok(None);
    }
    let start = pos;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let compound = matches!(data[start], b'{' | b'[');
    while pos < data.len() {
        let c = data[pos];
        pos += 1;
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
                if !compound && depth == 0 {
                    return Ok(Some((start, pos)));
                }
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if compound && depth == 0 {
                    return Ok(Some((start, pos)));
                }
            }
            b',' | b' ' | b'\t' | b'\n' | b'\r' if !compound && depth == 0 => {
                return Ok(Some((start, pos - 1)));
            }
            _ => {}
        }
    }
    if !compound && !in_string {
        // A primitive terminated by the end of input is complete.
        return Ok(Some((start, pos)));
    }
    // A truncated value: Go's decoder reports unexpected EOF.
    Err("unexpected EOF".to_string())
}

/// Split host and port like Go's `net.SplitHostPort`, returning the
/// host and port strings.
fn split_host_port(hostport: &str) -> Result<(String, String), String> {
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
    loop {
        let extent =
            next_value_extent(body, pos).map_err(|e| format!("unable to parse response: {e}"))?;
        let Some((start, end)) = extent else { break };
        let chunk = core::str::from_utf8(&body[start..end])
            .map_err(|_| "unable to parse response: invalid UTF-8".to_string())?;
        let value = gojson::decode(&ntype, chunk)
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
        return Ok(Vec::new());
    }

    // Convert the response to net addresses.
    let mut addrs = Vec::with_capacity(nodes.len());
    for (host_port, services, _pver) in &nodes {
        let Ok((host, port_str)) = split_host_port(host_port) else {
            continue;
        };
        let Ok(port) = go_parse_port(&port_str) else {
            continue;
        };
        let Some(ip) = parse_ip(&host) else {
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

    Ok(addrs)
}

/// Parse a port like Go's `strconv.ParseUint(portStr, 10, 16)`.
fn go_parse_port(s: &str) -> Result<u16, ()> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    s.parse::<u16>().map_err(|_| ())
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
