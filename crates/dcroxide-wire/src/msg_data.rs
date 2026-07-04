// SPDX-License-Identifier: ISC
//! Data relay and sync messages: inventory, block/header requests, blocks,
//! and mining/initial state (dcrd `msginv.go`, `msggetdata.go`,
//! `msgnotfound.go`, `msggetblocks.go`, `msggetheaders.go`,
//! `msgheaders.go`, `msgblock.go`, `msgminingstate.go`,
//! `msggetinitstate.go`, `msginitstate.go`).

use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash};

use crate::blockheader::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD};
use crate::cursor::Cursor;
use crate::error::WireError;
use crate::invvect::{INV_VECT_PAYLOAD, InvVect, MAX_INV_PER_MSG, read_inv_list, write_inv_list};
use crate::msgtx::{MIN_TX_PAYLOAD, MsgTx};
use crate::protocol::{INIT_STATE_VERSION, is_strict_ascii};
use crate::varint::{read_ascii_var_string, read_var_int, var_int_serialize_size, write_var_int};

/// The maximum number of block locator hashes per message (dcrd
/// `MaxBlockLocatorsPerMsg`).
pub const MAX_BLOCK_LOCATORS_PER_MSG: u64 = 500;

/// The maximum number of headers in a `headers` message (dcrd
/// `MaxBlockHeadersPerMsg`).
pub const MAX_BLOCK_HEADERS_PER_MSG: u64 = 2000;

/// The maximum block payload before protocol version 4 (dcrd
/// `MaxBlockPayloadV3`; deliberately not 1 MiB).
pub const MAX_BLOCK_PAYLOAD_V3: u32 = 1_000_000;

/// The maximum block payload (dcrd `MaxBlockPayload`, 1.25 MiB).
pub const MAX_BLOCK_PAYLOAD: u32 = 1_310_720;

/// The maximum number of transactions per transaction tree (dcrd
/// `MaxTxPerTxTree`).
pub fn max_tx_per_tx_tree(pver: u32) -> u64 {
    if pver <= 3 {
        (u64::from(MAX_BLOCK_PAYLOAD_V3) / MIN_TX_PAYLOAD) / 2 + 1
    } else {
        (u64::from(MAX_BLOCK_PAYLOAD) / MIN_TX_PAYLOAD) / 2 + 1
    }
}

/// The maximum number of block hashes in a `miningstate` message (dcrd
/// `MaxMSBlocksAtHeadPerMsg`).
pub const MAX_MS_BLOCKS_AT_HEAD_PER_MSG: u64 = 8;

/// The maximum number of vote hashes in a `miningstate` message (dcrd
/// `MaxMSVotesAtHeadPerMsg`).
pub const MAX_MS_VOTES_AT_HEAD_PER_MSG: u64 = 40;

/// The maximum number of block hashes in an `initstate` message (dcrd
/// `MaxISBlocksAtHeadPerMsg`).
pub const MAX_IS_BLOCKS_AT_HEAD_PER_MSG: u64 = 8;

/// The maximum number of vote hashes in an `initstate` message (dcrd
/// `MaxISVotesAtHeadPerMsg`).
pub const MAX_IS_VOTES_AT_HEAD_PER_MSG: u64 = 40;

/// The maximum number of tspend hashes in an `initstate` message (dcrd
/// `MaxISTSpendsAtHeadPerMsg`).
pub const MAX_IS_TSPENDS_AT_HEAD_PER_MSG: u64 = 7;

/// The maximum length of an individual initial state type (dcrd
/// `MaxInitStateTypeLen`).
pub const MAX_INIT_STATE_TYPE_LEN: u64 = 32;

/// The maximum number of initial state types per message (dcrd
/// `MaxInitStateTypes`).
pub const MAX_INIT_STATE_TYPES: u64 = 32;

/// Initial state type for head blocks (dcrd `InitStateHeadBlocks`).
pub const INIT_STATE_HEAD_BLOCKS: &str = "headblocks";

/// Initial state type for head block votes (dcrd `InitStateHeadBlockVotes`).
pub const INIT_STATE_HEAD_BLOCK_VOTES: &str = "headblockvotes";

/// Initial state type for treasury spends (dcrd `InitStateTSpends`).
pub const INIT_STATE_TSPENDS: &str = "tspends";

/// The `inv` message (dcrd `MsgInv`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgInv {
    /// The advertised inventory.
    pub inv_list: Vec<InvVect>,
}

/// The `getdata` message (dcrd `MsgGetData`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgGetData {
    /// The requested inventory.
    pub inv_list: Vec<InvVect>,
}

/// The `notfound` message (dcrd `MsgNotFound`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgNotFound {
    /// The inventory that could not be served.
    pub inv_list: Vec<InvVect>,
}

/// Shared inv-list codec for `inv`/`getdata`/`notfound`.
pub(crate) fn decode_inv_message(r: &mut Cursor<'_>) -> Result<Vec<InvVect>, WireError> {
    read_inv_list(r)
}

pub(crate) fn encode_inv_message(w: &mut Vec<u8>, list: &[InvVect]) -> Result<(), WireError> {
    write_inv_list(w, list)
}

pub(crate) fn inv_message_max_payload(_pver: u32) -> u32 {
    var_int_serialize_size(MAX_INV_PER_MSG) as u32 + MAX_INV_PER_MSG as u32 * INV_VECT_PAYLOAD
}

/// A block locator plus stop hash, shared by `getblocks` and `getheaders`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockLocator {
    /// The advertised protocol version.
    pub protocol_version: u32,
    /// Block locator hashes, newest first.
    pub block_locator_hashes: Vec<Hash>,
    /// The hash to stop at (zero for as many as possible).
    pub hash_stop: Hash,
}

impl BlockLocator {
    fn decode(r: &mut Cursor<'_>) -> Result<BlockLocator, WireError> {
        let protocol_version = r.read_u32()?;
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
        Ok(BlockLocator {
            protocol_version,
            block_locator_hashes,
            hash_stop,
        })
    }

    fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        if self.block_locator_hashes.len() as u64 > MAX_BLOCK_LOCATORS_PER_MSG {
            return Err(WireError::TooManyLocators {
                count: self.block_locator_hashes.len() as u64,
                max: MAX_BLOCK_LOCATORS_PER_MSG,
            });
        }
        w.extend_from_slice(&self.protocol_version.to_le_bytes());
        write_var_int(w, self.block_locator_hashes.len() as u64);
        for hash in &self.block_locator_hashes {
            w.extend_from_slice(hash.as_bytes());
        }
        w.extend_from_slice(self.hash_stop.as_bytes());
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        4 + var_int_serialize_size(MAX_BLOCK_LOCATORS_PER_MSG) as u32
            + (MAX_BLOCK_LOCATORS_PER_MSG as u32 * HASH_SIZE as u32)
            + HASH_SIZE as u32
    }
}

/// The `getblocks` message (dcrd `MsgGetBlocks`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgGetBlocks(pub BlockLocator);

/// The `getheaders` message (dcrd `MsgGetHeaders`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgGetHeaders(pub BlockLocator);

impl MsgGetBlocks {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgGetBlocks, WireError> {
        Ok(MsgGetBlocks(BlockLocator::decode(r)?))
    }
    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        self.0.encode(w)
    }
}

impl MsgGetHeaders {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgGetHeaders, WireError> {
        Ok(MsgGetHeaders(BlockLocator::decode(r)?))
    }
    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        self.0.encode(w)
    }
}

/// The `headers` message (dcrd `MsgHeaders`). Each header is followed on
/// the wire by a transaction count that must be zero.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgHeaders {
    /// The block headers.
    pub headers: Vec<BlockHeader>,
}

impl MsgHeaders {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgHeaders, WireError> {
        let count = read_var_int(r)?;
        if count > MAX_BLOCK_HEADERS_PER_MSG {
            return Err(WireError::TooManyHeaders {
                count,
                max: MAX_BLOCK_HEADERS_PER_MSG,
            });
        }
        let mut headers = Vec::new();
        for _ in 0..count {
            let header = BlockHeader::decode(r)?;
            let tx_count = read_var_int(r)?;
            if tx_count > 0 {
                return Err(WireError::HeaderContainsTxs { count: tx_count });
            }
            headers.push(header);
        }
        Ok(MsgHeaders { headers })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        if self.headers.len() as u64 > MAX_BLOCK_HEADERS_PER_MSG {
            return Err(WireError::TooManyHeaders {
                count: self.headers.len() as u64,
                max: MAX_BLOCK_HEADERS_PER_MSG,
            });
        }
        write_var_int(w, self.headers.len() as u64);
        for header in &self.headers {
            w.extend_from_slice(&header.serialize());
            write_var_int(w, 0);
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        var_int_serialize_size(MAX_BLOCK_HEADERS_PER_MSG) as u32
            + ((MAX_BLOCK_HEADER_PAYLOAD as u32 + 1) * MAX_BLOCK_HEADERS_PER_MSG as u32)
    }
}

/// The `block` message (dcrd `MsgBlock`): a header plus the regular and
/// stake transaction trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgBlock {
    /// The block header.
    pub header: BlockHeader,
    /// The regular transaction tree.
    pub transactions: Vec<MsgTx>,
    /// The stake transaction tree.
    pub stransactions: Vec<MsgTx>,
}

impl MsgBlock {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<MsgBlock, WireError> {
        let header = BlockHeader::decode(r)?;
        let max_per_tree = max_tx_per_tx_tree(pver);

        let tx_count = read_var_int(r)?;
        if tx_count > max_per_tree {
            return Err(WireError::TooManyTxs {
                count: tx_count,
                max: max_per_tree,
            });
        }
        let mut transactions = Vec::new();
        for _ in 0..tx_count {
            transactions.push(MsgTx::decode(r)?);
        }

        let stake_tx_count = read_var_int(r)?;
        if stake_tx_count > max_per_tree {
            return Err(WireError::TooManyTxs {
                count: stake_tx_count,
                max: max_per_tree,
            });
        }
        let mut stransactions = Vec::new();
        for _ in 0..stake_tx_count {
            stransactions.push(MsgTx::decode(r)?);
        }

        Ok(MsgBlock {
            header,
            transactions,
            stransactions,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.header.serialize());
        write_var_int(w, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.encode_into(w);
        }
        write_var_int(w, self.stransactions.len() as u64);
        for tx in &self.stransactions {
            tx.encode_into(w);
        }
    }

    /// Decode from a byte slice, returning the block and bytes consumed
    /// (dcrd `FromBytes`; trailing bytes are not an error there either).
    pub fn from_bytes(b: &[u8]) -> Result<(MsgBlock, usize), WireError> {
        let mut r = Cursor::new(b);
        let msg = Self::decode(&mut r, 0)?;
        Ok((msg, r.position()))
    }

    /// The serialization (dcrd `Bytes`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::new();
        self.encode(&mut w);
        w
    }

    /// The block hash (dcrd `BlockHash`).
    pub fn block_hash(&self) -> Hash {
        self.header.block_hash()
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver <= 3 {
            MAX_BLOCK_PAYLOAD_V3
        } else {
            MAX_BLOCK_PAYLOAD
        }
    }
}

/// The `miningstate` message (dcrd `MsgMiningState`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgMiningState {
    /// The mining state version.
    pub version: u32,
    /// The height of the described blocks.
    pub height: u32,
    /// Hashes of the blocks at the chain tip (at most 8).
    pub block_hashes: Vec<Hash>,
    /// Hashes of votes for those blocks (at most 40).
    pub vote_hashes: Vec<Hash>,
}

/// Decode a varint-counted hash list with a limit and an error constructor.
fn read_hash_list(
    r: &mut Cursor<'_>,
    max: u64,
    err: fn(u64, u64) -> WireError,
) -> Result<Vec<Hash>, WireError> {
    let count = read_var_int(r)?;
    if count > max {
        return Err(err(count, max));
    }
    let mut list = Vec::new();
    for _ in 0..count {
        list.push(Hash(r.take_array()?));
    }
    Ok(list)
}

fn write_hash_list(
    w: &mut Vec<u8>,
    list: &[Hash],
    max: u64,
    err: fn(u64, u64) -> WireError,
) -> Result<(), WireError> {
    if list.len() as u64 > max {
        return Err(err(list.len() as u64, max));
    }
    write_var_int(w, list.len() as u64);
    for hash in list {
        w.extend_from_slice(hash.as_bytes());
    }
    Ok(())
}

fn too_many_blocks(count: u64, max: u64) -> WireError {
    WireError::TooManyBlocks { count, max }
}
fn too_many_votes(count: u64, max: u64) -> WireError {
    WireError::TooManyVotes { count, max }
}
fn too_many_tspends(count: u64, max: u64) -> WireError {
    WireError::TooManyTSpends { count, max }
}

impl MsgMiningState {
    pub(crate) fn decode(r: &mut Cursor<'_>) -> Result<MsgMiningState, WireError> {
        let version = r.read_u32()?;
        let height = r.read_u32()?;
        // dcrd uses ErrTooManyBlocks for the decode-side block hash limit
        // (the AddBlockHash helper uses ErrTooManyHeaders; decode checks
        // first, so the decode-side kind is what is observable).
        let block_hashes = read_hash_list(r, MAX_MS_BLOCKS_AT_HEAD_PER_MSG, too_many_blocks)?;
        let vote_hashes = read_hash_list(r, MAX_MS_VOTES_AT_HEAD_PER_MSG, too_many_votes)?;
        Ok(MsgMiningState {
            version,
            height,
            block_hashes,
            vote_hashes,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>) -> Result<(), WireError> {
        w.extend_from_slice(&self.version.to_le_bytes());
        w.extend_from_slice(&self.height.to_le_bytes());
        write_hash_list(
            w,
            &self.block_hashes,
            MAX_MS_BLOCKS_AT_HEAD_PER_MSG,
            too_many_blocks,
        )?;
        write_hash_list(
            w,
            &self.vote_hashes,
            MAX_MS_VOTES_AT_HEAD_PER_MSG,
            too_many_votes,
        )?;
        Ok(())
    }

    pub(crate) fn max_payload_length(_pver: u32) -> u32 {
        4 + 4
            + var_int_serialize_size(MAX_MS_BLOCKS_AT_HEAD_PER_MSG) as u32
            + (MAX_MS_BLOCKS_AT_HEAD_PER_MSG as u32 * HASH_SIZE as u32)
            + var_int_serialize_size(MAX_MS_VOTES_AT_HEAD_PER_MSG) as u32
            + (MAX_MS_VOTES_AT_HEAD_PER_MSG as u32 * HASH_SIZE as u32)
    }
}

/// The `getinitstate` message (dcrd `MsgGetInitState`); gated at
/// [`INIT_STATE_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgGetInitState {
    /// The requested state types (strict-ASCII strings, at most 32 of at
    /// most 32 bytes each).
    pub types: Vec<String>,
}

impl MsgGetInitState {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<MsgGetInitState, WireError> {
        if pver < INIT_STATE_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let nb_types = read_var_int(r)?;
        if nb_types > MAX_INIT_STATE_TYPES {
            return Err(WireError::TooManyInitStateTypes {
                count: nb_types,
                max: MAX_INIT_STATE_TYPES,
            });
        }
        let mut types = Vec::new();
        for _ in 0..nb_types {
            types.push(read_ascii_var_string(r, MAX_INIT_STATE_TYPE_LEN)?);
        }
        Ok(MsgGetInitState { types })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < INIT_STATE_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.types.len() as u64 > MAX_INIT_STATE_TYPES {
            return Err(WireError::TooManyInitStateTypes {
                count: self.types.len() as u64,
                max: MAX_INIT_STATE_TYPES,
            });
        }
        write_var_int(w, self.types.len() as u64);
        for typ in &self.types {
            if typ.len() as u64 > MAX_INIT_STATE_TYPE_LEN {
                return Err(WireError::InitStateTypeTooLong {
                    len: typ.len() as u64,
                    max: MAX_INIT_STATE_TYPE_LEN,
                });
            }
            if !is_strict_ascii(typ.as_bytes()) {
                return Err(WireError::MalformedStrictString);
            }
            write_var_int(w, typ.len() as u64);
            w.extend_from_slice(typ.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < INIT_STATE_VERSION {
            return 0;
        }
        let max_len_type =
            var_int_serialize_size(MAX_INIT_STATE_TYPE_LEN) as u64 + MAX_INIT_STATE_TYPE_LEN;
        (var_int_serialize_size(MAX_INIT_STATE_TYPES) as u64 + MAX_INIT_STATE_TYPES * max_len_type)
            as u32
    }
}

/// The `initstate` message (dcrd `MsgInitState`); gated at
/// [`INIT_STATE_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgInitState {
    /// Hashes of blocks at the chain tip (at most 8).
    pub block_hashes: Vec<Hash>,
    /// Hashes of votes for those blocks (at most 40).
    pub vote_hashes: Vec<Hash>,
    /// Hashes of mempool treasury spends (at most 7).
    pub tspend_hashes: Vec<Hash>,
}

impl MsgInitState {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<MsgInitState, WireError> {
        if pver < INIT_STATE_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let block_hashes = read_hash_list(r, MAX_IS_BLOCKS_AT_HEAD_PER_MSG, too_many_blocks)?;
        let vote_hashes = read_hash_list(r, MAX_IS_VOTES_AT_HEAD_PER_MSG, too_many_votes)?;
        let tspend_hashes = read_hash_list(r, MAX_IS_TSPENDS_AT_HEAD_PER_MSG, too_many_tspends)?;
        Ok(MsgInitState {
            block_hashes,
            vote_hashes,
            tspend_hashes,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < INIT_STATE_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        write_hash_list(
            w,
            &self.block_hashes,
            MAX_IS_BLOCKS_AT_HEAD_PER_MSG,
            too_many_blocks,
        )?;
        write_hash_list(
            w,
            &self.vote_hashes,
            MAX_IS_VOTES_AT_HEAD_PER_MSG,
            too_many_votes,
        )?;
        write_hash_list(
            w,
            &self.tspend_hashes,
            MAX_IS_TSPENDS_AT_HEAD_PER_MSG,
            too_many_tspends,
        )?;
        Ok(())
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < INIT_STATE_VERSION {
            return 0;
        }
        var_int_serialize_size(MAX_IS_BLOCKS_AT_HEAD_PER_MSG) as u32
            + (MAX_IS_BLOCKS_AT_HEAD_PER_MSG as u32 * HASH_SIZE as u32)
            + var_int_serialize_size(MAX_IS_VOTES_AT_HEAD_PER_MSG) as u32
            + (MAX_IS_VOTES_AT_HEAD_PER_MSG as u32 * HASH_SIZE as u32)
            + var_int_serialize_size(MAX_IS_TSPENDS_AT_HEAD_PER_MSG) as u32
            + (MAX_IS_TSPENDS_AT_HEAD_PER_MSG as u32 * HASH_SIZE as u32)
    }
}
