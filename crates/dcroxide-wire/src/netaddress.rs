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
