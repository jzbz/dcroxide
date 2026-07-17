// SPDX-License-Identifier: ISC
//! Peer network addresses as encoded in `addr` and `version` messages
//! (dcrd `netaddress.go`).

use alloc::vec::Vec;

use crate::cursor::Cursor;
use crate::error::WireError;
use crate::protocol::ServiceFlag;

/// The maximum encoded size of a [`NetAddress`]: timestamp 4 + services 8 +
/// IP 16 + port 2 (dcrd `maxNetAddressPayload`).
pub const MAX_NET_ADDRESS_PAYLOAD: u32 = 30;

/// A peer address: services, IPv6-mapped IP bytes, and a port. The
/// timestamp is only on the wire in contexts that include it (`addr`
/// messages, not `version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetAddress {
    /// Last-known-alive time as unix seconds (u32 on the wire).
    pub timestamp: u32,
    /// Advertised services.
    pub services: ServiceFlag,
    /// The IP address as 16 bytes (IPv4 addresses are IPv6-mapped).
    pub ip: [u8; 16],
    /// The port, big-endian on the wire (the sole big-endian field in the
    /// protocol).
    pub port: u16,
}

impl NetAddress {
    /// Decode from the cursor (dcrd `readNetAddress`); `with_timestamp`
    /// selects the `addr`-message form.
    pub(crate) fn decode(
        r: &mut Cursor<'_>,
        with_timestamp: bool,
    ) -> Result<NetAddress, WireError> {
        let timestamp = if with_timestamp { r.read_u32()? } else { 0 };
        let services = ServiceFlag(r.read_u64()?);
        let ip: [u8; 16] = r.take_array()?;
        let port = u16::from_be_bytes(r.take_array()?);
        Ok(NetAddress {
            timestamp,
            services,
            ip,
            port,
        })
    }

    /// Append the encoding (dcrd `writeNetAddress`).
    pub(crate) fn encode(&self, w: &mut Vec<u8>, with_timestamp: bool) {
        if with_timestamp {
            w.extend_from_slice(&self.timestamp.to_le_bytes());
        }
        w.extend_from_slice(&self.services.0.to_le_bytes());
        w.extend_from_slice(&self.ip);
        w.extend_from_slice(&self.port.to_be_bytes());
    }
}

/// The type of a version 2 network address (dcrd `NetAddressType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetAddressType(pub u8);

impl NetAddressType {
    /// An unknown address type (dcrd `UnknownAddressType`).
    pub const UNKNOWN: NetAddressType = NetAddressType(0);
    /// An IPv4 address (dcrd `IPv4Address`).
    pub const IPV4: NetAddressType = NetAddressType(1);
    /// An IPv6 address (dcrd `IPv6Address`).
    pub const IPV6: NetAddressType = NetAddressType(2);
    /// A Tor v3 onion address (dcrd `TorV3Address`).
    pub const TOR_V3: NetAddressType = NetAddressType(3);
}

/// The maximum encoded size of a [`NetAddressV2`]: timestamp 8 +
/// services 8 + type 1 + address up to 32 (a Tor v3 public key) +
/// port 2 (dcrd `maxNetAddressPayloadV2`).
pub const MAX_NET_ADDRESS_PAYLOAD_V2: u32 = 51;

/// The largest unix timestamp a version 2 address may carry: Go
/// rejects values that would overflow its internal time representation
/// (`math.MaxInt64 - unixToInternal` in dcrd's `readElement`).
const MAX_V2_TIMESTAMP: u64 = i64::MAX as u64 - 62_135_596_800;

/// A version 2 peer address as carried by `addrv2` messages (dcrd
/// `NetAddressV2`): a typed, variable-length encoded address with a
/// 64-bit timestamp.  The field order matches the wire encoding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetAddressV2 {
    /// Last-known-alive time as unix seconds (u64 on the wire).
    pub timestamp: u64,
    /// Advertised services.
    pub services: ServiceFlag,
    /// The address type discriminator.
    pub addr_type: NetAddressType,
    /// The encoded address; its length is fixed by the type (4 for
    /// IPv4, 16 for IPv6, 32 for Tor v3).
    pub encoded_addr: Vec<u8>,
    /// The port, or zero when the type has none.  Little-endian on
    /// the wire, unlike the legacy address's big-endian port (dcrd
    /// writes it through `writeElement`).
    pub port: u16,
}

impl NetAddressV2 {
    /// A new version 2 address from the parts, without validation
    /// (dcrd `NewNetAddressV2`).
    pub fn new(
        addr_type: NetAddressType,
        encoded_addr: Vec<u8>,
        port: u16,
        timestamp: u64,
        services: ServiceFlag,
    ) -> NetAddressV2 {
        NetAddressV2 {
            timestamp,
            services,
            addr_type,
            encoded_addr,
            port,
        }
    }

    /// A new IPv4 or IPv6 address from IPv6-mapped IP bytes, choosing
    /// the type from the mapping (dcrd `NewNetAddressV2IPPort`, whose
    /// current-time stamp arrives here as `now_unix`).
    pub fn from_ip_port(
        ip: [u8; 16],
        port: u16,
        services: ServiceFlag,
        now_unix: u64,
    ) -> NetAddressV2 {
        const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        let (addr_type, encoded_addr) = if ip[..12] == V4_MAPPED_PREFIX {
            (NetAddressType::IPV4, ip[12..].to_vec())
        } else {
            (NetAddressType::IPV6, ip.to_vec())
        };
        NetAddressV2 {
            timestamp: now_unix,
            services,
            addr_type,
            encoded_addr,
            port,
        }
    }

    /// Decode from the cursor (dcrd `readNetAddressV2`).
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<NetAddressV2, WireError> {
        let timestamp = r.read_u64()?;
        if timestamp > MAX_V2_TIMESTAMP {
            return Err(WireError::InvalidTimestamp);
        }
        let services = ServiceFlag(r.read_u64()?);
        let addr_type = NetAddressType(r.read_u8()?);
        let encoded_addr: Vec<u8> = match addr_type {
            NetAddressType::IPV4 => r.take_array::<4>()?.to_vec(),
            NetAddressType::IPV6 => r.take_array::<16>()?.to_vec(),
            NetAddressType::TOR_V3 => r.take_array::<32>()?.to_vec(),
            other => {
                return Err(WireError::UnknownNetAddrType { addr_type: other.0 });
            }
        };
        let port = r.read_u16()?;
        Ok(NetAddressV2 {
            timestamp,
            services,
            addr_type,
            encoded_addr,
            port,
        })
    }

    /// Append the encoding (dcrd `writeNetAddressV2`): the timestamp,
    /// services, and type go out BEFORE the address length validation,
    /// exactly like dcrd, so an erroring encode leaves the same
    /// partial prefix behind.
    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        w.extend_from_slice(&self.timestamp.to_le_bytes());
        w.extend_from_slice(&self.services.0.to_le_bytes());
        w.push(self.addr_type.0);
        let want_len = match self.addr_type {
            NetAddressType::IPV4 => 4,
            NetAddressType::IPV6 => 16,
            NetAddressType::TOR_V3 => 32,
            other => {
                return Err(WireError::UnknownNetAddrType { addr_type: other.0 });
            }
        };
        if self.encoded_addr.len() != want_len {
            return Err(WireError::InvalidMsg);
        }
        w.extend_from_slice(&self.encoded_addr);
        w.extend_from_slice(&self.port.to_le_bytes());
        Ok(())
    }
}
