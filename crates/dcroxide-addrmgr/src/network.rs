// SPDX-License-Identifier: ISC
//! IP address range classification and routability (dcrd addrmgr
//! `network.go`).

// Bounded mask arithmetic over prefix lengths mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

/// The type of an address (dcrd `NetAddressType`).  The values are
/// used in serialization and cannot be changed or re-used.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NetAddressType {
    /// The address type could not be determined.
    Unknown = 0,
    /// An IPv4 address.
    IPv4 = 1,
    /// An IPv6 address.
    IPv6 = 2,
    // TorV2 = 3 is no longer supported.
}

/// A function that returns whether a particular network address type
/// matches a filter (dcrd `NetAddressTypeFilter`).
pub type NetAddressTypeFilter = fn(NetAddressType) -> bool;

/// The 4-byte form of the address when it is IPv4 or an IPv4-mapped
/// IPv6 address (Go `net.IP.To4`).
pub(crate) fn to4(ip: &[u8]) -> Option<[u8; 4]> {
    match ip.len() {
        4 => {
            let mut out = [0u8; 4];
            out.copy_from_slice(ip);
            Some(out)
        }
        16 => {
            // The IPv4-mapped prefix ::ffff:a.b.c.d.
            if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
                let mut out = [0u8; 4];
                out.copy_from_slice(&ip[12..16]);
                Some(out)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The 16-byte form of the address (Go `net.IP.To16`).
pub(crate) fn to16(ip: &[u8]) -> Option<[u8; 16]> {
    match ip.len() {
        4 => {
            let mut out = [0u8; 16];
            out[10] = 0xff;
            out[11] = 0xff;
            out[12..16].copy_from_slice(ip);
            Some(out)
        }
        16 => {
            let mut out = [0u8; 16];
            out.copy_from_slice(ip);
            Some(out)
        }
        _ => None,
    }
}

/// Whether the given address is an IPv4 address (dcrd `isIPv4`).
pub(crate) fn is_ipv4(ip: &[u8]) -> bool {
    to4(ip).is_some()
}

/// Whether an address is contained in a CIDR range over a 4-byte
/// network (Go `net.IPNet.Contains` with a 4-byte mask).
fn contains_v4(net: [u8; 4], ones: u32, ip: &[u8]) -> bool {
    let Some(ip4) = to4(ip) else {
        return false;
    };
    prefix_eq(&net, &ip4, ones)
}

/// Whether an address is contained in a CIDR range over a 16-byte
/// network.
fn contains_v6(net: [u8; 16], ones: u32, ip: &[u8]) -> bool {
    let Some(ip16) = to16(ip) else {
        return false;
    };
    prefix_eq(&net, &ip16, ones)
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u32) -> bool {
    let full = (bits / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    a[full] & mask == b[full] & mask
}

/// Whether the given address is a local address (dcrd `isLocal`):
/// loopback or in 0.0.0.0/8.
pub(crate) fn is_local(ip: &[u8]) -> bool {
    is_loopback(ip) || contains_v4([0, 0, 0, 0], 8, ip)
}

fn is_loopback(ip: &[u8]) -> bool {
    if let Some(ip4) = to4(ip) {
        return ip4[0] == 127;
    }
    ip.len() == 16
        && *ip == {
            let mut lo = [0u8; 16];
            lo[15] = 1;
            lo
        }
}

/// Whether the address is part of the IPv4 private network space
/// (dcrd `isRFC1918`).
fn is_rfc1918(ip: &[u8]) -> bool {
    contains_v4([10, 0, 0, 0], 8, ip)
        || contains_v4([172, 16, 0, 0], 12, ip)
        || contains_v4([192, 168, 0, 0], 16, ip)
}

/// RFC2544 (198.18.0.0/15).
fn is_rfc2544(ip: &[u8]) -> bool {
    contains_v4([198, 18, 0, 0], 15, ip)
}

/// RFC3849 (2001:DB8::/32).
fn is_rfc3849(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x20, 0x01, 0x0d, 0xb8]), 32, ip)
}

/// RFC3927 (169.254.0.0/16).
fn is_rfc3927(ip: &[u8]) -> bool {
    contains_v4([169, 254, 0, 0], 16, ip)
}

/// RFC3964 (2002::/16).
pub(crate) fn is_rfc3964(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x20, 0x02]), 16, ip)
}

/// RFC4193 (FC00::/7).
fn is_rfc4193(ip: &[u8]) -> bool {
    contains_v6(v6(&[0xfc]), 7, ip)
}

/// RFC4380 (2001::/32).
pub(crate) fn is_rfc4380(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x20, 0x01, 0x00, 0x00]), 32, ip)
}

/// RFC4843 (2001:10::/28).
fn is_rfc4843(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x20, 0x01, 0x00, 0x10]), 28, ip)
}

/// RFC4862 (FE80::/64).
fn is_rfc4862(ip: &[u8]) -> bool {
    contains_v6(v6(&[0xfe, 0x80]), 64, ip)
}

/// RFC5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
fn is_rfc5737(ip: &[u8]) -> bool {
    contains_v4([192, 0, 2, 0], 24, ip)
        || contains_v4([198, 51, 100, 0], 24, ip)
        || contains_v4([203, 0, 113, 0], 24, ip)
}

/// RFC6052 (64:FF9B::/96).
pub(crate) fn is_rfc6052(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x00, 0x64, 0xff, 0x9b]), 96, ip)
}

/// RFC6145 (::FFFF:0:0:0/96).
pub(crate) fn is_rfc6145(ip: &[u8]) -> bool {
    let mut net = [0u8; 16];
    net[8] = 0xff;
    net[9] = 0xff;
    contains_v6(net, 96, ip)
}

/// RFC6598 (100.64.0.0/10).
fn is_rfc6598(ip: &[u8]) -> bool {
    contains_v4([100, 64, 0, 0], 10, ip)
}

/// The Hurricane Electric IPv6 block (2001:470::/32).
pub(crate) fn is_he_net(ip: &[u8]) -> bool {
    contains_v6(v6(&[0x20, 0x01, 0x04, 0x70]), 32, ip)
}

fn v6(prefix: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..prefix.len()].copy_from_slice(prefix);
    out
}

/// Whether the passed address is valid (dcrd `isValid`): not
/// unspecified and not the IPv4 broadcast address.
fn is_valid(ip: &[u8]) -> bool {
    if ip.is_empty() {
        return false;
    }
    let unspecified = match ip.len() {
        4 => *ip == [0u8; 4],
        16 => *ip == [0u8; 16],
        _ => false,
    };
    let bcast = to4(ip) == Some([255, 255, 255, 255]);
    !(unspecified || bcast)
}

/// Whether the passed address is routable over the public internet
/// (dcrd `IsRoutable`).
pub fn is_routable(ip: &[u8]) -> bool {
    is_valid(ip)
        && !(is_rfc1918(ip)
            || is_rfc2544(ip)
            || is_rfc3927(ip)
            || is_rfc4862(ip)
            || is_rfc3849(ip)
            || is_rfc4843(ip)
            || is_rfc5737(ip)
            || is_rfc6598(ip)
            || is_local(ip)
            || is_rfc4193(ip))
}

/// Format an IP in Go's `net.IP.String` style: dotted quad for IPv4
/// and IPv4-mapped addresses, RFC5952 for IPv6.
pub(crate) fn ip_to_string(ip: &[u8]) -> String {
    if let Some(ip4) = to4(ip) {
        return std::net::Ipv4Addr::from(ip4).to_string();
    }
    if let Some(ip16) = to16(ip) {
        return std::net::Ipv6Addr::from(ip16).to_string();
    }
    // Unreachable for the supported types; mirror a raw fallback.
    ip.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mask an IP to the given prefix length and return its string form
/// (Go `ip.Mask(net.CIDRMask(bits, len*8)).String()`).
pub(crate) fn masked_string(ip: &[u8], bits: u32) -> String {
    let mut masked = ip.to_vec();
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if full < masked.len() {
        if rem != 0 {
            masked[full] &= 0xffu8 << (8 - rem);
            for b in masked.iter_mut().skip(full + 1) {
                *b = 0;
            }
        } else {
            for b in masked.iter_mut().skip(full) {
                *b = 0;
            }
        }
    }
    ip_to_string(&masked)
}
