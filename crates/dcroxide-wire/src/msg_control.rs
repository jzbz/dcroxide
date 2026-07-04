// SPDX-License-Identifier: ISC
//! Connection control messages: version, ping/pong, addr, feefilter, and
//! reject (dcrd `msgversion.go`, `msgping.go`, `msgpong.go`, `msgaddr.go`,
//! `msgfeefilter.go`, `msgreject.go`).

use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::cursor::Cursor;
use crate::error::WireError;
use crate::netaddress::{MAX_NET_ADDRESS_PAYLOAD, NetAddress};
use crate::protocol::{FEE_FILTER_VERSION, REMOVE_REJECT_VERSION, ServiceFlag, is_strict_ascii};
use crate::varint::{read_var_int, read_var_string_bytes, var_int_serialize_size, write_var_int};

/// The maximum user agent length (dcrd `MaxUserAgentLen`).
pub const MAX_USER_AGENT_LEN: usize = 256;

/// The maximum number of addresses in an `addr` message (dcrd
/// `MaxAddrPerMsg`).
pub const MAX_ADDR_PER_MSG: u64 = 1000;

/// Seconds between year 1 and the unix epoch; timestamps above
/// `i64::MAX - this` are rejected exactly like dcrd's `int64Time` handling.
const UNIX_TO_INTERNAL: u64 = 62_135_596_800;

/// The `version` message (dcrd `MsgVersion`).
///
/// Every field after `addr_you` is optional on decode: dcrd stops reading
/// (keeping zero values) once the payload is exhausted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgVersion {
    /// The highest protocol version the peer supports.
    pub protocol_version: i32,
    /// The services the peer advertises.
    pub services: ServiceFlag,
    /// The peer's local time as unix seconds (int64 on the wire).
    pub timestamp: i64,
    /// The address of the remote peer, from the sender's perspective.
    pub addr_you: NetAddress,
    /// The sender's own address.
    pub addr_me: NetAddress,
    /// A nonce for detecting self-connections.
    pub nonce: u64,
    /// The user agent (strict ASCII, at most 256 bytes).
    pub user_agent: String,
    /// The sender's best block height.
    pub last_block: i32,
    /// Whether the peer asks not to be relayed transactions (encoded
    /// inverted as a "relay" flag).
    pub disable_relay_tx: bool,
}

/// Validate a user agent per dcrd `validateUserAgent`.
fn validate_user_agent(user_agent: &str) -> Result<(), WireError> {
    if user_agent.len() > MAX_USER_AGENT_LEN {
        return Err(WireError::UserAgentTooLong {
            len: user_agent.len() as u64,
            max: MAX_USER_AGENT_LEN as u64,
        });
    }
    if !is_strict_ascii(user_agent.as_bytes()) {
        return Err(WireError::MalformedStrictString);
    }
    Ok(())
}

impl MsgVersion {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgVersion, WireError> {
        let protocol_version = r.read_u32()? as i32;
        let services = ServiceFlag(r.read_u64()?);
        let ts = r.read_u64()?;
        // Reject timestamps that would overflow Go's usable time range
        // (dcrd int64Time semantics).
        if ts > i64::MAX as u64 - UNIX_TO_INTERNAL {
            return Err(WireError::InvalidTimestamp);
        }
        let mut msg = MsgVersion {
            protocol_version,
            services,
            timestamp: ts as i64,
            ..MsgVersion::default()
        };
        msg.addr_you = NetAddress::decode(r, false)?;

        // Remaining fields are optional; dcrd stops without error when the
        // payload runs out.
        if r.remaining() > 0 {
            msg.addr_me = NetAddress::decode(r, false)?;
        }
        if r.remaining() > 0 {
            msg.nonce = r.read_u64()?;
        }
        if r.remaining() > 0 {
            let bytes = read_var_string_bytes(r)?;
            if bytes.len() > MAX_USER_AGENT_LEN {
                return Err(WireError::UserAgentTooLong {
                    len: bytes.len() as u64,
                    max: MAX_USER_AGENT_LEN as u64,
                });
            }
            if !is_strict_ascii(&bytes) {
                return Err(WireError::MalformedStrictString);
            }
            msg.user_agent = String::from_utf8(bytes).expect("strict ASCII is UTF-8");
        }
        if r.remaining() > 0 {
            msg.last_block = r.read_u32()? as i32;
        }
        if r.remaining() > 0 {
            let relay_tx = r.read_u8()? != 0;
            msg.disable_relay_tx = !relay_tx;
        }
        Ok(msg)
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        validate_user_agent(&self.user_agent)?;
        w.extend_from_slice(&(self.protocol_version as u32).to_le_bytes());
        w.extend_from_slice(&self.services.0.to_le_bytes());
        if (self.timestamp as u64) > i64::MAX as u64 - UNIX_TO_INTERNAL {
            return Err(WireError::InvalidTimestamp);
        }
        w.extend_from_slice(&(self.timestamp as u64).to_le_bytes());
        self.addr_you.encode(w, false);
        self.addr_me.encode(w, false);
        w.extend_from_slice(&self.nonce.to_le_bytes());
        write_var_int(w, self.user_agent.len() as u64);
        w.extend_from_slice(self.user_agent.as_bytes());
        w.extend_from_slice(&(self.last_block as u32).to_le_bytes());
        w.push(u8::from(!self.disable_relay_tx));
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        33 + (MAX_NET_ADDRESS_PAYLOAD * 2) + 9 + MAX_USER_AGENT_LEN as u32
    }
}

/// The `ping` message (dcrd `MsgPing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgPing {
    /// The nonce echoed back by the corresponding pong.
    pub nonce: u64,
}

/// The `pong` message (dcrd `MsgPong`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgPong {
    /// The nonce of the ping being answered.
    pub nonce: u64,
}

/// The `feefilter` message (dcrd `MsgFeeFilter`); gated at
/// [`FEE_FILTER_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgFeeFilter {
    /// The minimum fee rate in atoms/KB the peer wants relayed.
    pub min_fee: i64,
}

impl MsgFeeFilter {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<MsgFeeFilter, WireError> {
        if pver < FEE_FILTER_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        Ok(MsgFeeFilter {
            min_fee: r.read_u64()? as i64,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < FEE_FILTER_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(&(self.min_fee as u64).to_le_bytes());
        Ok(())
    }
}

/// The `addr` message (dcrd `MsgAddr`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgAddr {
    /// The advertised addresses (at most [`MAX_ADDR_PER_MSG`]).
    pub addr_list: Vec<NetAddress>,
}

impl MsgAddr {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgAddr, WireError> {
        let count = read_var_int(r)?;
        if count > MAX_ADDR_PER_MSG {
            return Err(WireError::TooManyAddrs {
                count,
                max: MAX_ADDR_PER_MSG,
            });
        }
        let mut addr_list = Vec::new();
        for _ in 0..count {
            addr_list.push(NetAddress::decode(r, true)?);
        }
        Ok(MsgAddr { addr_list })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        if self.addr_list.len() as u64 > MAX_ADDR_PER_MSG {
            return Err(WireError::TooManyAddrs {
                count: self.addr_list.len() as u64,
                max: MAX_ADDR_PER_MSG,
            });
        }
        write_var_int(w, self.addr_list.len() as u64);
        for na in &self.addr_list {
            na.encode(w, true);
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_ADDR_PER_MSG) as u32
            + (MAX_ADDR_PER_MSG as u32 * MAX_NET_ADDRESS_PAYLOAD)
    }
}

/// A `reject` message rejection code (dcrd `RejectCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectCode(pub u8);

impl RejectCode {
    /// `REJECT_MALFORMED`.
    pub const MALFORMED: RejectCode = RejectCode(0x01);
    /// `REJECT_INVALID`.
    pub const INVALID: RejectCode = RejectCode(0x10);
    /// `REJECT_OBSOLETE`.
    pub const OBSOLETE: RejectCode = RejectCode(0x11);
    /// `REJECT_DUPLICATE`.
    pub const DUPLICATE: RejectCode = RejectCode(0x12);
    /// `REJECT_NONSTANDARD`.
    pub const NONSTANDARD: RejectCode = RejectCode(0x40);
    /// `REJECT_DUST`.
    pub const DUST: RejectCode = RejectCode(0x41);
    /// `REJECT_INSUFFICIENTFEE`.
    pub const INSUFFICIENT_FEE: RejectCode = RejectCode(0x42);
    /// `REJECT_CHECKPOINT`.
    pub const CHECKPOINT: RejectCode = RejectCode(0x43);
}

/// The `reject` message (dcrd `MsgReject`); removed at
/// [`REMOVE_REJECT_VERSION`] — both encode and decode error at or above it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgReject {
    /// The command of the message being rejected.
    pub cmd: String,
    /// The rejection code.
    pub code: u8,
    /// The human-readable rejection reason.
    pub reason: String,
    /// The hash of the rejected block or transaction (present only when
    /// `cmd` is `block` or `tx`).
    pub hash: Hash,
}

/// Read a strict-ASCII var string for reject fields, mapping non-ASCII to
/// `ErrMalformedStrictString` like dcrd's validate helpers.
fn read_reject_string(r: &mut Cursor<'_>) -> Result<String, WireError> {
    let bytes = read_var_string_bytes(r)?;
    if !is_strict_ascii(&bytes) {
        return Err(WireError::MalformedStrictString);
    }
    Ok(String::from_utf8(bytes).expect("strict ASCII is UTF-8"))
}

impl MsgReject {
    /// Decode a reject payload (dcrd `MsgReject.BtcDecode`).
    ///
    /// Like dcrd, this is exposed on the type but unreachable through
    /// [`crate::read_message`]: reject is write-only at the pinned tag
    /// (quirk QK-0001).
    pub fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<MsgReject, WireError> {
        if pver >= REMOVE_REJECT_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let cmd = read_reject_string(r)?;
        let code = r.read_u8()?;
        let reason = read_reject_string(r)?;
        let mut hash = Hash::ZERO;
        if cmd == "block" || cmd == "tx" {
            hash = Hash(r.take_array()?);
        }
        Ok(MsgReject {
            cmd,
            code,
            reason,
            hash,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver >= REMOVE_REJECT_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if !is_strict_ascii(self.cmd.as_bytes()) || !is_strict_ascii(self.reason.as_bytes()) {
            return Err(WireError::MalformedStrictString);
        }
        write_var_int(w, self.cmd.len() as u64);
        w.extend_from_slice(self.cmd.as_bytes());
        w.push(self.code);
        write_var_int(w, self.reason.len() as u64);
        w.extend_from_slice(self.reason.as_bytes());
        if self.cmd == "block" || self.cmd == "tx" {
            w.extend_from_slice(self.hash.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver >= REMOVE_REJECT_VERSION {
            return 0;
        }
        crate::MAX_MESSAGE_PAYLOAD as u32
    }
}
