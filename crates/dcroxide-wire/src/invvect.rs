// SPDX-License-Identifier: ISC
//! Inventory vectors (dcrd `invvect.go`).

use alloc::vec::Vec;
use core::fmt;

use dcroxide_chainhash::Hash;

use crate::cursor::Cursor;
use crate::error::WireError;
use crate::varint::{read_var_int, write_var_int};

/// The maximum number of inventory vectors per message (dcrd
/// `MaxInvPerMsg`).
pub const MAX_INV_PER_MSG: u64 = 50_000;

/// The encoded size of an inventory vector: type 4 + hash 32.
pub(crate) const INV_VECT_PAYLOAD: u32 = 36;

/// The type of data an inventory vector refers to (dcrd `InvType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvType(pub u32);

impl InvType {
    /// An error (`InvTypeError`).
    pub const ERROR: InvType = InvType(0);
    /// A transaction (`InvTypeTx`).
    pub const TX: InvType = InvType(1);
    /// A block (`InvTypeBlock`).
    pub const BLOCK: InvType = InvType(2);
    /// A filtered block (`InvTypeFilteredBlock`).
    pub const FILTERED_BLOCK: InvType = InvType(3);
    /// A mixing message (`InvTypeMix`).
    pub const MIX: InvType = InvType(4);
}

impl fmt::Display for InvType {
    /// Matches dcrd's `InvType.String` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InvType::ERROR => f.write_str("ERROR"),
            InvType::TX => f.write_str("MSG_TX"),
            InvType::BLOCK => f.write_str("MSG_BLOCK"),
            InvType::FILTERED_BLOCK => f.write_str("MSG_FILTERED_BLOCK"),
            InvType::MIX => f.write_str("MSG_MIX"),
            InvType(other) => write!(f, "Unknown InvType ({other})"),
        }
    }
}

/// An inventory vector advertising or requesting data (dcrd `InvVect`).
/// Unknown type values decode without error, exactly like dcrd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvVect {
    /// The type of data.
    pub inv_type: InvType,
    /// The hash of the data.
    pub hash: Hash,
}

impl InvVect {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<InvVect, WireError> {
        Ok(InvVect {
            inv_type: InvType(r.read_u32()?),
            hash: Hash(r.take_array()?),
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.inv_type.0.to_le_bytes());
        w.extend_from_slice(self.hash.as_bytes());
    }
}

/// Decode a varint-prefixed inventory list bounded by [`MAX_INV_PER_MSG`]
/// (shared by `inv`, `getdata`, and `notfound`).
pub(crate) fn read_inv_list(r: &mut Cursor<'_>) -> Result<Vec<InvVect>, WireError> {
    let count = read_var_int(r)?;
    if count > MAX_INV_PER_MSG {
        return Err(WireError::TooManyVectors {
            count,
            max: MAX_INV_PER_MSG,
        });
    }
    let mut list = Vec::new();
    for _ in 0..count {
        list.push(InvVect::decode(r)?);
    }
    Ok(list)
}

/// Encode a varint-prefixed inventory list, enforcing the limit like dcrd's
/// encoders do.
pub(crate) fn write_inv_list(w: &mut Vec<u8>, list: &[InvVect]) -> Result<(), WireError> {
    if list.len() as u64 > MAX_INV_PER_MSG {
        return Err(WireError::TooManyVectors {
            count: list.len() as u64,
            max: MAX_INV_PER_MSG,
        });
    }
    write_var_int(w, list.len() as u64);
    for iv in list {
        iv.encode(w);
    }
    Ok(())
}
