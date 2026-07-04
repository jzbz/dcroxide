// SPDX-License-Identifier: ISC
//! Committed filter messages: the deprecated version-1 family (still
//! decodable, gated at [`NODE_CF_VERSION`]), the version-2 messages, and
//! the batched form (dcrd `msgcfilter.go`, `msgcfheaders.go`,
//! `msgcftypes.go`, `msggetcfilter.go`, `msggetcfheaders.go`,
//! `msggetcftypes.go`, `msgcfilterv2.go`, `msggetcfilterv2.go`,
//! `msgcfiltersv2.go`, `msggetcfsv2.go`).

use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash};

use crate::cursor::Cursor;
use crate::error::WireError;
use crate::msg_data::MAX_BLOCK_LOCATORS_PER_MSG;
use crate::protocol::{BATCHED_CFILTERS_V2_VERSION, CFILTER_V2_VERSION, NODE_CF_VERSION};
use crate::varint::{
    read_var_bytes, read_var_int, var_int_serialize_size, write_var_bytes, write_var_int,
};

/// The maximum byte size of a committed filter (dcrd `MaxCFilterDataSize`).
pub const MAX_CFILTER_DATA_SIZE: u64 = 256 * 1024;

/// The maximum number of filter types per `cftypes` message (dcrd
/// `MaxFilterTypesPerMsg`).
pub const MAX_FILTER_TYPES_PER_MSG: u64 = 256;

/// The maximum number of committed filter headers per `cfheaders` message
/// (dcrd `MaxCFHeadersPerMsg`).
pub const MAX_CFHEADERS_PER_MSG: u64 = 2000;

/// The maximum number of header-commitment proof hashes (dcrd
/// `MaxHeaderProofHashes`).
pub const MAX_HEADER_PROOF_HASHES: u64 = 32;

/// The maximum number of filters in a batched `cfiltersv2` message (dcrd
/// `MaxCFiltersV2PerBatch`).
pub const MAX_CFILTERS_V2_PER_BATCH: u64 = 100;

/// A committed filter type (dcrd `FilterType`): 0 = regular, 1 = extended.
pub type FilterType = u8;

/// The `getcfilter` message (deprecated version-1 family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgGetCFilter {
    /// The block whose filter is requested.
    pub block_hash: Hash,
    /// The requested filter type.
    pub filter_type: FilterType,
}

/// The `cfilter` message (deprecated version-1 family).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgCFilter {
    /// The block the filter belongs to.
    pub block_hash: Hash,
    /// The filter type.
    pub filter_type: FilterType,
    /// The serialized filter (at most [`MAX_CFILTER_DATA_SIZE`]).
    pub data: Vec<u8>,
}

/// The `getcfheaders` message (deprecated version-1 family).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgGetCFHeaders {
    /// Block locator hashes.
    pub block_locator_hashes: Vec<Hash>,
    /// The hash to stop at.
    pub hash_stop: Hash,
    /// The requested filter type.
    pub filter_type: FilterType,
}

/// The `cfheaders` message (deprecated version-1 family).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgCFHeaders {
    /// The hash the headers stop at.
    pub stop_hash: Hash,
    /// The filter type.
    pub filter_type: FilterType,
    /// The filter header hashes.
    pub header_hashes: Vec<Hash>,
}

/// The `cftypes` message (deprecated version-1 family).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgCFTypes {
    /// The filter types the peer supports.
    pub supported_filters: Vec<FilterType>,
}

/// The `getcfilterv2` message; gated at [`CFILTER_V2_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgGetCFilterV2 {
    /// The block whose version-2 filter is requested.
    pub block_hash: Hash,
}

/// The `cfilterv2` message; gated at [`CFILTER_V2_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgCFilterV2 {
    /// The block the filter belongs to.
    pub block_hash: Hash,
    /// The serialized version-2 filter.
    pub data: Vec<u8>,
    /// The leaf index of the filter in the header commitment.
    pub proof_index: u32,
    /// The commitment inclusion proof hashes.
    pub proof_hashes: Vec<Hash>,
}

/// The `getcfsv2` message; gated at [`BATCHED_CFILTERS_V2_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgGetCFsV2 {
    /// The first block in the requested range.
    pub start_hash: Hash,
    /// The last block in the requested range.
    pub end_hash: Hash,
}

/// The `cfiltersv2` message; gated at [`BATCHED_CFILTERS_V2_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgCFiltersV2 {
    /// The batched filters.
    pub cfilters: Vec<MsgCFilterV2>,
}

impl MsgGetCFilter {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        Ok(MsgGetCFilter {
            block_hash: Hash(r.take_array()?),
            filter_type: r.read_u8()?,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(self.block_hash.as_bytes());
        w.push(self.filter_type);
        Ok(())
    }
}

impl MsgCFilter {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let block_hash = Hash(r.take_array()?);
        let filter_type = r.read_u8()?;
        let data = read_var_bytes(r, MAX_CFILTER_DATA_SIZE)?;
        Ok(MsgCFilter {
            block_hash,
            filter_type,
            data,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.data.len() as u64 > MAX_CFILTER_DATA_SIZE {
            return Err(WireError::FilterTooLarge {
                size: self.data.len() as u64,
                max: MAX_CFILTER_DATA_SIZE,
            });
        }
        w.extend_from_slice(self.block_hash.as_bytes());
        w.push(self.filter_type);
        write_var_bytes(w, &self.data);
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_CFILTER_DATA_SIZE) as u32
            + MAX_CFILTER_DATA_SIZE as u32
            + HASH_SIZE as u32
            + 1
    }
}

impl MsgGetCFHeaders {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let count = read_var_int(r)?;
        if count > MAX_BLOCK_LOCATORS_PER_MSG {
            return Err(WireError::TooManyLocators {
                count,
                max: MAX_BLOCK_LOCATORS_PER_MSG,
            });
        }
        let mut block_locator_hashes = Vec::new();
        for _ in 0..count {
            block_locator_hashes.push(Hash(r.take_array()?));
        }
        let hash_stop = Hash(r.take_array()?);
        let filter_type = r.read_u8()?;
        Ok(MsgGetCFHeaders {
            block_locator_hashes,
            hash_stop,
            filter_type,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.block_locator_hashes.len() as u64 > MAX_BLOCK_LOCATORS_PER_MSG {
            return Err(WireError::TooManyLocators {
                count: self.block_locator_hashes.len() as u64,
                max: MAX_BLOCK_LOCATORS_PER_MSG,
            });
        }
        write_var_int(w, self.block_locator_hashes.len() as u64);
        for hash in &self.block_locator_hashes {
            w.extend_from_slice(hash.as_bytes());
        }
        w.extend_from_slice(self.hash_stop.as_bytes());
        w.push(self.filter_type);
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_BLOCK_LOCATORS_PER_MSG) as u32
            + (MAX_BLOCK_LOCATORS_PER_MSG as u32 * HASH_SIZE as u32)
            + HASH_SIZE as u32
            + 1
    }
}

impl MsgCFHeaders {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let stop_hash = Hash(r.take_array()?);
        let filter_type = r.read_u8()?;
        let count = read_var_int(r)?;
        if count > MAX_CFHEADERS_PER_MSG {
            return Err(WireError::TooManyFilterHeaders {
                count,
                max: MAX_CFHEADERS_PER_MSG,
            });
        }
        let mut header_hashes = Vec::new();
        for _ in 0..count {
            header_hashes.push(Hash(r.take_array()?));
        }
        Ok(MsgCFHeaders {
            stop_hash,
            filter_type,
            header_hashes,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.header_hashes.len() as u64 > MAX_CFHEADERS_PER_MSG {
            return Err(WireError::TooManyFilterHeaders {
                count: self.header_hashes.len() as u64,
                max: MAX_CFHEADERS_PER_MSG,
            });
        }
        w.extend_from_slice(self.stop_hash.as_bytes());
        w.push(self.filter_type);
        write_var_int(w, self.header_hashes.len() as u64);
        for hash in &self.header_hashes {
            w.extend_from_slice(hash.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        HASH_SIZE as u32
            + 1
            + var_int_serialize_size(MAX_CFHEADERS_PER_MSG) as u32
            + (HASH_SIZE as u32 * MAX_CFHEADERS_PER_MSG as u32)
    }
}

impl MsgCFTypes {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let count = read_var_int(r)?;
        if count > MAX_FILTER_TYPES_PER_MSG {
            return Err(WireError::TooManyFilterTypes {
                count,
                max: MAX_FILTER_TYPES_PER_MSG,
            });
        }
        let mut supported_filters = Vec::new();
        for _ in 0..count {
            supported_filters.push(r.read_u8()?);
        }
        Ok(MsgCFTypes { supported_filters })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < NODE_CF_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.supported_filters.len() as u64 > MAX_FILTER_TYPES_PER_MSG {
            return Err(WireError::TooManyFilterTypes {
                count: self.supported_filters.len() as u64,
                max: MAX_FILTER_TYPES_PER_MSG,
            });
        }
        write_var_int(w, self.supported_filters.len() as u64);
        w.extend_from_slice(&self.supported_filters);
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_FILTER_TYPES_PER_MSG) as u32 + MAX_FILTER_TYPES_PER_MSG as u32
    }
}

impl MsgGetCFilterV2 {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < CFILTER_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        Ok(MsgGetCFilterV2 {
            block_hash: Hash(r.take_array()?),
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < CFILTER_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(self.block_hash.as_bytes());
        Ok(())
    }
}

impl MsgCFilterV2 {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < CFILTER_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let block_hash = Hash(r.take_array()?);
        let data = read_var_bytes(r, MAX_CFILTER_DATA_SIZE)?;
        let proof_index = r.read_u32()?;
        let count = read_var_int(r)?;
        if count > MAX_HEADER_PROOF_HASHES {
            return Err(WireError::TooManyProofs {
                count,
                max: MAX_HEADER_PROOF_HASHES,
            });
        }
        let mut proof_hashes = Vec::new();
        for _ in 0..count {
            proof_hashes.push(Hash(r.take_array()?));
        }
        Ok(MsgCFilterV2 {
            block_hash,
            data,
            proof_index,
            proof_hashes,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < CFILTER_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.data.len() as u64 > MAX_CFILTER_DATA_SIZE {
            return Err(WireError::FilterTooLarge {
                size: self.data.len() as u64,
                max: MAX_CFILTER_DATA_SIZE,
            });
        }
        if self.proof_hashes.len() as u64 > MAX_HEADER_PROOF_HASHES {
            return Err(WireError::TooManyProofs {
                count: self.proof_hashes.len() as u64,
                max: MAX_HEADER_PROOF_HASHES,
            });
        }
        w.extend_from_slice(self.block_hash.as_bytes());
        write_var_bytes(w, &self.data);
        w.extend_from_slice(&self.proof_index.to_le_bytes());
        write_var_int(w, self.proof_hashes.len() as u64);
        for hash in &self.proof_hashes {
            w.extend_from_slice(hash.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        HASH_SIZE as u32
            + var_int_serialize_size(MAX_CFILTER_DATA_SIZE) as u32
            + MAX_CFILTER_DATA_SIZE as u32
            + 4
            + var_int_serialize_size(MAX_HEADER_PROOF_HASHES) as u32
            + (MAX_HEADER_PROOF_HASHES as u32 * HASH_SIZE as u32)
    }
}

impl MsgGetCFsV2 {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < BATCHED_CFILTERS_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        Ok(MsgGetCFsV2 {
            start_hash: Hash(r.take_array()?),
            end_hash: Hash(r.take_array()?),
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < BATCHED_CFILTERS_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(self.start_hash.as_bytes());
        w.extend_from_slice(self.end_hash.as_bytes());
        Ok(())
    }
}

impl MsgCFiltersV2 {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        if pver < BATCHED_CFILTERS_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let nb_cfilters = read_var_int(r)?;
        if nb_cfilters > MAX_CFILTERS_V2_PER_BATCH {
            return Err(WireError::TooManyCFilters {
                count: nb_cfilters,
                max: MAX_CFILTERS_V2_PER_BATCH,
            });
        }
        let mut cfilters = Vec::new();
        for _ in 0..nb_cfilters {
            cfilters.push(MsgCFilterV2::decode(r, pver)?);
        }
        Ok(MsgCFiltersV2 { cfilters })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < BATCHED_CFILTERS_V2_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.cfilters.len() as u64 > MAX_CFILTERS_V2_PER_BATCH {
            return Err(WireError::TooManyCFilters {
                count: self.cfilters.len() as u64,
                max: MAX_CFILTERS_V2_PER_BATCH,
            });
        }
        write_var_int(w, self.cfilters.len() as u64);
        for cf in &self.cfilters {
            cf.encode(w, pver)?;
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_CFILTERS_V2_PER_BATCH) as u32
            + (HASH_SIZE as u32
                + var_int_serialize_size(MAX_CFILTER_DATA_SIZE) as u32
                + MAX_CFILTER_DATA_SIZE as u32
                + 4
                + var_int_serialize_size(MAX_HEADER_PROOF_HASHES) as u32
                + (MAX_HEADER_PROOF_HASHES as u32 * HASH_SIZE as u32))
                * MAX_CFILTERS_V2_PER_BATCH as u32
    }
}
