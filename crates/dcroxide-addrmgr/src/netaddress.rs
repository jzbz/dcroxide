// SPDX-License-Identifier: ISC
//! Network address information for peers (dcrd addrmgr
//! `netaddress.go`).

use dcroxide_wire::ServiceFlag;

use crate::network::{
    NetAddressType, ip_to_string, is_he_net, is_ipv4, is_local, is_rfc3964, is_rfc4380, is_rfc6052,
    is_rfc6145, is_routable, masked_string, to4,
};
use crate::{AddrError, ErrorKind, make_error};

/// Information about a peer on the network (dcrd `NetAddress`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAddress {
    /// The type of the address.
    pub addr_type: NetAddressType,
    /// The IP address bytes of the peer.
    pub ip: Vec<u8>,
    /// The port of the remote peer.
    pub port: u16,
    /// The last time the address was seen, in Unix nanoseconds.
    pub timestamp: i64,
    /// The service flags supported by this network address.
    pub services: ServiceFlag,
}

impl NetAddress {
    /// Whether the network address is routable (dcrd `IsRoutable`).
    pub fn is_routable(&self) -> bool {
        is_routable(&self.ip)
    }

    /// A string representation of the IP field without the port (dcrd
    /// `ipString`, rendered like Go's `net.IP.String`).
    pub fn ip_string(&self) -> String {
        match self.addr_type {
            NetAddressType::IPv4 | NetAddressType::IPv6 => ip_to_string(&self.ip),
            NetAddressType::Unknown => {
                let hex: String = self.ip.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "unsupported IP type {}, {}, {hex}",
                    self.addr_type as u8,
                    ip_to_string(&self.ip)
                )
            }
        }
    }

    /// A string that uniquely represents the network address including
    /// the port (dcrd `Key`, Go `net.JoinHostPort`).
    pub fn key(&self) -> String {
        let host = self.ip_string();
        if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Add the provided service to the set of supported services
    /// (dcrd `AddService`).
    pub fn add_service(&mut self, service: ServiceFlag) {
        self.services = ServiceFlag(self.services.0 | service.0);
    }

    /// A string representing the network group the address is part of
    /// (dcrd `GroupKey`): the /16 for IPv4, the /32 (/36 for he.net)
    /// for IPv6, "local" for a local address, and "unroutable" for an
    /// unroutable address.
    pub fn group_key(&self) -> String {
        let ip = &self.ip;
        if is_local(ip) {
            return "local".to_string();
        }
        if !is_routable(ip) {
            return "unroutable".to_string();
        }
        if self.addr_type == NetAddressType::IPv4 {
            return masked_string(ip, 16);
        }
        if is_rfc6145(ip) || is_rfc6052(ip) {
            // The last four bytes are the ip address.
            return masked_string(&ip[12..16], 16);
        }
        if is_rfc3964(ip) {
            return masked_string(&ip[2..6], 16);
        }
        if is_rfc4380(ip) {
            // Teredo tunnels have the last 4 bytes as the v4 address
            // XOR 0xff.
            let mut new_ip = [0u8; 4];
            for (i, byte) in ip[12..16].iter().enumerate() {
                new_ip[i] = byte ^ 0xff;
            }
            return masked_string(&new_ip, 16);
        }

        // Otherwise IPv6: /32 for everything except Hurricane
        // Electric's range, which uses /36.
        let bits = if is_he_net(ip) { 36 } else { 32 };
        masked_string(ip, bits)
    }
}

impl core::fmt::Display for NetAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.key())
    }
}

/// Attempt to determine the network address type from raw bytes (dcrd
/// `deriveNetAddressType`).
pub(crate) fn derive_net_address_type(addr_bytes: &[u8]) -> Result<NetAddressType, AddrError> {
    if is_ipv4(addr_bytes) {
        return Ok(NetAddressType::IPv4);
    }
    if addr_bytes.len() == 16 {
        return Ok(NetAddressType::IPv6);
    }
    Err(make_error(
        ErrorKind::UnknownAddressType,
        format!("unable to determine address type from raw network address bytes: {addr_bytes:?}"),
    ))
}

/// Convert the provided address bytes into a standard structure based
/// on the type (dcrd `canonicalizeIP`).
pub(crate) fn canonicalize_ip(addr_type: NetAddressType, addr_bytes: &[u8]) -> Vec<u8> {
    if addr_bytes.len() == 16 && addr_type == NetAddressType::IPv4 {
        if let Some(ip4) = to4(addr_bytes) {
            return ip4.to_vec();
        }
    }
    if addr_type == NetAddressType::IPv6 {
        if let Some(ip16) = crate::network::to16(addr_bytes) {
            return ip16.to_vec();
        }
    }
    addr_bytes.to_vec()
}

/// Return an error if the suggested address type does not match the
/// provided address (dcrd `checkNetAddressType`).
fn check_net_address_type(addr_type: NetAddressType, addr_bytes: &[u8]) -> Result<(), AddrError> {
    let derived = derive_net_address_type(addr_bytes)?;
    if addr_type != derived {
        return Err(make_error(
            ErrorKind::MismatchedAddressType,
            format!(
                "derived address type does not match expected value (got {}, \
                 expected {}, address bytes {addr_bytes:?}).",
                derived as u8, addr_type as u8
            ),
        ));
    }
    Ok(())
}

/// Create a new network address from the given parameters (dcrd
/// `NewNetAddressFromParams`); the timestamp is in Unix nanoseconds.
pub fn new_net_address_from_params(
    addr_type: NetAddressType,
    addr_bytes: &[u8],
    port: u16,
    timestamp: i64,
    services: ServiceFlag,
) -> Result<NetAddress, AddrError> {
    let canonicalized = canonicalize_ip(addr_type, addr_bytes);
    check_net_address_type(addr_type, &canonicalized)?;
    Ok(NetAddress {
        addr_type,
        ip: canonicalized,
        port,
        timestamp,
        services,
    })
}

/// Identify the given host as a supported network address type and
/// convert it to its unique encoding (dcrd `EncodeHost`).  A host
/// that is not recognized returns the unknown type without error.
pub fn encode_host(host: &str) -> (NetAddressType, Vec<u8>) {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => (NetAddressType::IPv4, v4.octets().to_vec()),
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                // Go's ParseIP yields a 16-byte value whose To4 form
                // is used when it is an IPv4 address; EncodeHost's
                // isIPv4 check triggers for mapped forms.
                if is_ipv4(&octets) {
                    (NetAddressType::IPv4, to4(&octets).expect("mapped").to_vec())
                } else {
                    (NetAddressType::IPv6, octets.to_vec())
                }
            }
        };
    }
    (NetAddressType::Unknown, Vec::new())
}

/// Create a new network address given an ip, port, and service flags
/// (dcrd `NewNetAddressFromIPPort`); the ip must be a valid IPv4 or
/// IPv6 address, and the timestamp is in Unix nanoseconds.
pub fn new_net_address_from_ip_port(
    ip: &[u8],
    port: u16,
    services: ServiceFlag,
    timestamp: i64,
) -> NetAddress {
    let addr_type = derive_net_address_type(ip).unwrap_or(NetAddressType::Unknown);
    let canonicalized = canonicalize_ip(addr_type, ip);
    NetAddress {
        addr_type,
        ip: canonicalized,
        port,
        timestamp,
        services,
    }
}
