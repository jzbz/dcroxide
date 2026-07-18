// SPDX-License-Identifier: ISC
//! Protocol versions, service flags, and network magic numbers (dcrd
//! `protocol.go`).

use alloc::string::String;
use core::fmt;

/// The initial protocol version.
pub const INITIAL_PROTOCOL_VERSION: u32 = 1;

/// The latest protocol version this crate implements (dcrd
/// `ProtocolVersion` at the dcrd master 2.2 pre-release parity
/// target): the addrv2 version, negotiated since the strict-verack
/// handshake and the daemon's addrv2 handlers landed.
pub const PROTOCOL_VERSION: u32 = 12;

/// The protocol version which adds the `addrv2` message and retires
/// the legacy `addr` message (dcrd `AddrV2Version`).
pub const ADDR_V2_VERSION: u32 = 12;

/// Version in which the SFNodeBloom service flag was introduced.
pub const NODE_BLOOM_VERSION: u32 = 2;

/// Version in which the sendheaders message was introduced.
pub const SEND_HEADERS_VERSION: u32 = 3;

/// Version in which the maximum block size changed.
pub const MAX_BLOCK_SIZE_VERSION: u32 = 4;

/// Version in which the feefilter message was introduced.
pub const FEE_FILTER_VERSION: u32 = 5;

/// Version in which the version-1 committed filter messages were introduced.
pub const NODE_CF_VERSION: u32 = 6;

/// Version in which the version-2 committed filter messages were introduced
/// (and the version-1 ones deprecated).
pub const CFILTER_V2_VERSION: u32 = 7;

/// Version in which the initial state messages were introduced.
pub const INIT_STATE_VERSION: u32 = 8;

/// Version in which the reject message was removed.
pub const REMOVE_REJECT_VERSION: u32 = 9;

/// Version in which the mixing messages were introduced.
pub const MIX_VERSION: u32 = 10;

/// Version in which the batched committed filters messages were introduced.
pub const BATCHED_CFILTERS_V2_VERSION: u32 = 11;

/// Bit flags describing the services a Decred peer supports (dcrd
/// `ServiceFlag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ServiceFlag(pub u64);

impl ServiceFlag {
    /// The peer is a full node (`SFNodeNetwork`).
    pub const NODE_NETWORK: ServiceFlag = ServiceFlag(1 << 0);
    /// The peer supports bloom filtering (`SFNodeBloom`).
    pub const NODE_BLOOM: ServiceFlag = ServiceFlag(1 << 1);
    /// The peer supports committed filters (`SFNodeCF`).
    pub const NODE_CF: ServiceFlag = ServiceFlag(1 << 2);

    /// Whether all bits in `service` are set.
    pub fn has(self, service: ServiceFlag) -> bool {
        self.0 & service.0 == service.0
    }
}

impl fmt::Display for ServiceFlag {
    /// Matches dcrd's `ServiceFlag.String` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut remaining = self.0;
        if remaining == 0 {
            return f.write_str("0x0");
        }
        let mut s = String::new();
        for (flag, name) in [
            (ServiceFlag::NODE_NETWORK, "SFNodeNetwork"),
            (ServiceFlag::NODE_BLOOM, "SFNodeBloom"),
            (ServiceFlag::NODE_CF, "SFNodeCF"),
        ] {
            if remaining & flag.0 == flag.0 {
                s.push_str(name);
                s.push('|');
                remaining &= !flag.0;
            }
        }
        let mut s = alloc::borrow::ToOwned::to_owned(s.trim_end_matches('|'));
        if remaining != 0 {
            s.push_str(&alloc::format!("|0x{remaining:x}"));
        }
        f.write_str(s.trim_start_matches('|'))
    }
}

/// The network magic value identifying a Decred network (dcrd
/// `CurrencyNet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrencyNet(pub u32);

impl CurrencyNet {
    /// The main network.
    pub const MAIN_NET: CurrencyNet = CurrencyNet(0xd9b400f9);
    /// The regression test network.
    pub const REG_NET: CurrencyNet = CurrencyNet(0xdab500fa);
    /// The test network (version 3).
    pub const TEST_NET3: CurrencyNet = CurrencyNet(0xb194aa75);
    /// The simulation test network.
    pub const SIM_NET: CurrencyNet = CurrencyNet(0x12141c16);
}

impl fmt::Display for CurrencyNet {
    /// Matches dcrd's `CurrencyNet.String` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CurrencyNet::MAIN_NET => f.write_str("MainNet"),
            CurrencyNet::TEST_NET3 => f.write_str("TestNet3"),
            CurrencyNet::REG_NET => f.write_str("RegNet"),
            CurrencyNet::SIM_NET => f.write_str("SimNet"),
            CurrencyNet(other) => write!(f, "Unknown CurrencyNet ({other})"),
        }
    }
}

/// Whether every byte of `s` is within dcrd's strict ASCII range
/// (0x20–0x7e), matching `isStrictAscii`.
pub(crate) fn is_strict_ascii(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..=0x7e).contains(&b))
}
