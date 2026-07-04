// SPDX-License-Identifier: ISC
//! The eight peer-to-peer StakeShuffle mixing messages (dcrd
//! `msgmixpairreq.go` … `msgmixsecrets.go`, `mixvect.go`), all gated at
//! [`MIX_VERSION`].
//!
//! Only the wire codecs live here; the mixpool identity hashes and
//! signed-data digests (`WriteHash`/`WriteSignedData`) land with the
//! mixing crate in Phase 12 (tracked in PARITY.md).

use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::cursor::Cursor;
use crate::error::WireError;
use crate::msgtx::{MsgTx, OutPoint, TxOut};
use crate::protocol::{MIX_VERSION, is_strict_ascii};
use crate::varint::{
    read_ascii_var_string, read_var_bytes, read_var_int, write_var_bytes, write_var_int,
};

/// The size in bytes of a padded or unpadded DC-net message (dcrd
/// `MixMsgSize`).
pub const MIX_MSG_SIZE: usize = 20;

/// The maximum number of peers in a mix session (dcrd `MaxMixPeers`).
pub const MAX_MIX_PEERS: u64 = 512;

/// The maximum total number of mixed messages (dcrd `MaxMixMcount`).
pub const MAX_MIX_MCOUNT: u64 = 1024;

/// The maximum length of a DC-net field value (dcrd `MaxMixFieldValLen`).
pub const MAX_MIX_FIELD_VAL_LEN: u64 = 32;

/// The maximum length of a pair request script class (dcrd
/// `MaxMixPairReqScriptClassLen`).
pub const MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN: u64 = 32;

/// The maximum number of UTXOs in a pair request (dcrd
/// `MaxMixPairReqUTXOs`).
pub const MAX_MIX_PAIR_REQ_UTXOS: u64 = 512;

/// The maximum pair request UTXO script length (dcrd
/// `MaxMixPairReqUTXOScriptLen`).
pub const MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN: u64 = 16384;

/// The maximum pair request UTXO public key length (dcrd
/// `MaxMixPairReqUTXOPubKeyLen`).
pub const MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN: u64 = 33;

/// The maximum pair request UTXO signature length (dcrd
/// `MaxMixPairReqUTXOSignatureLen`).
pub const MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN: u64 = 64;

/// A vector of DC-net messages (dcrd `MixVect`).
pub type MixVect = Vec<[u8; MIX_MSG_SIZE]>;

/// A UTXO being proven for a pair request (dcrd `MixPairReqUTXO`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MixPairReqUTXO {
    /// The unspent output.
    pub out_point: OutPoint,
    /// The redeem script (P2SH only).
    pub script: Vec<u8>,
    /// The public key proving ownership.
    pub pub_key: Vec<u8>,
    /// The ownership proof signature.
    pub signature: Vec<u8>,
    /// The opcode describing the output kind.
    pub opcode: u8,
}

/// The `mixpairreq` message (dcrd `MsgMixPairReq`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixPairReq {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity (compressed secp256k1 public key).
    pub identity: [u8; 33],
    /// The block height at which the message expires.
    pub expiry: u32,
    /// The amount being mixed (must be non-negative).
    pub mix_amount: i64,
    /// The script class describing the mixed outputs (strict ASCII).
    pub script_class: String,
    /// The transaction version of the resulting mix.
    pub tx_version: u16,
    /// The lock time of the resulting mix.
    pub lock_time: u32,
    /// The number of mixed messages this peer contributes.
    pub message_count: u32,
    /// The total input value (must be non-negative).
    pub input_value: i64,
    /// The proven UTXOs.
    pub utxos: Vec<MixPairReqUTXO>,
    /// The optional change output.
    pub change: Option<TxOut>,
    /// Behavior flags.
    pub flags: u8,
    /// Pairing-restriction flags.
    pub pairing_flags: u8,
}

/// Shared decode prologue: pver gate then signature/identity.
fn decode_sig_ident(r: &mut Cursor<'_>, pver: u32) -> Result<([u8; 64], [u8; 33]), WireError> {
    if pver < MIX_VERSION {
        return Err(WireError::MsgInvalidForPVer);
    }
    Ok((r.take_array()?, r.take_array()?))
}

/// Decode a varint-counted hash list bounded by [`MAX_MIX_PEERS`] with
/// dcrd's `ErrTooManyPrevMixMsgs`.
fn read_seen_hashes(r: &mut Cursor<'_>) -> Result<Vec<Hash>, WireError> {
    let count = read_var_int(r)?;
    if count > MAX_MIX_PEERS {
        return Err(WireError::TooManyPrevMixMsgs {
            count,
            max: MAX_MIX_PEERS,
        });
    }
    let mut seen = Vec::new();
    for _ in 0..count {
        seen.push(Hash(r.take_array()?));
    }
    Ok(seen)
}

fn write_seen_hashes(w: &mut Vec<u8>, seen: &[Hash]) -> Result<(), WireError> {
    if seen.len() as u64 > MAX_MIX_PEERS {
        return Err(WireError::TooManyPrevMixMsgs {
            count: seen.len() as u64,
            max: MAX_MIX_PEERS,
        });
    }
    write_var_int(w, seen.len() as u64);
    for hash in seen {
        w.extend_from_slice(hash.as_bytes());
    }
    Ok(())
}

impl MsgMixPairReq {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let expiry = r.read_u32()?;
        let mix_amount = r.read_u64()? as i64;
        if mix_amount < 0 {
            return Err(WireError::InvalidMsg);
        }
        let script_class = read_ascii_var_string(r, MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN)?;
        let tx_version = r.read_u16()?;
        let lock_time = r.read_u32()?;
        let message_count = r.read_u32()?;
        let input_value = r.read_u64()? as i64;
        if input_value < 0 {
            return Err(WireError::InvalidMsg);
        }

        let count = read_var_int(r)?;
        if count > MAX_MIX_PAIR_REQ_UTXOS {
            return Err(WireError::TooManyMixPairReqUTXOs {
                count,
                max: MAX_MIX_PAIR_REQ_UTXOS,
            });
        }
        let mut utxos = Vec::new();
        for _ in 0..count {
            let out_point = OutPoint {
                hash: Hash(r.take_array()?),
                index: r.read_u32()?,
                tree: r.read_u8()? as i8,
            };
            let script = read_var_bytes(r, MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN)?;
            let pub_key = read_var_bytes(r, MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN)?;
            let signature = read_var_bytes(r, MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN)?;
            let opcode = r.read_u8()?;
            utxos.push(MixPairReqUTXO {
                out_point,
                script,
                pub_key,
                signature,
                opcode,
            });
        }

        let change = match r.read_u8()? {
            0 => None,
            1 => Some(TxOut {
                value: r.read_u64()? as i64,
                version: r.read_u16()?,
                pk_script: read_var_bytes(r, crate::MAX_MESSAGE_PAYLOAD)?,
            }),
            _ => return Err(WireError::InvalidMsg),
        };

        let flags = r.read_u8()?;
        let pairing_flags = r.read_u8()?;
        Ok(MsgMixPairReq {
            signature,
            identity,
            expiry,
            mix_amount,
            script_class,
            tx_version,
            lock_time,
            message_count,
            input_value,
            utxos,
            change,
            flags,
            pairing_flags,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.script_class.len() as u64 > MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN {
            return Err(WireError::MixPairReqScriptClassTooLong {
                len: self.script_class.len() as u64,
                max: MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN,
            });
        }
        if !is_strict_ascii(self.script_class.as_bytes()) {
            return Err(WireError::MalformedStrictString);
        }
        if self.utxos.len() as u64 > MAX_MIX_PAIR_REQ_UTXOS {
            return Err(WireError::TooManyMixPairReqUTXOs {
                count: self.utxos.len() as u64,
                max: MAX_MIX_PAIR_REQ_UTXOS,
            });
        }

        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.expiry.to_le_bytes());
        w.extend_from_slice(&(self.mix_amount as u64).to_le_bytes());
        write_var_int(w, self.script_class.len() as u64);
        w.extend_from_slice(self.script_class.as_bytes());
        w.extend_from_slice(&self.tx_version.to_le_bytes());
        w.extend_from_slice(&self.lock_time.to_le_bytes());
        w.extend_from_slice(&self.message_count.to_le_bytes());
        w.extend_from_slice(&(self.input_value as u64).to_le_bytes());
        write_var_int(w, self.utxos.len() as u64);
        for utxo in &self.utxos {
            if utxo.script.len() as u64 > MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN {
                return Err(WireError::VarBytesTooLong {
                    count: utxo.script.len() as u64,
                    max: MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN,
                });
            }
            if utxo.pub_key.len() as u64 > MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN {
                return Err(WireError::VarBytesTooLong {
                    count: utxo.pub_key.len() as u64,
                    max: MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN,
                });
            }
            if utxo.signature.len() as u64 > MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN {
                return Err(WireError::VarBytesTooLong {
                    count: utxo.signature.len() as u64,
                    max: MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN,
                });
            }
            w.extend_from_slice(utxo.out_point.hash.as_bytes());
            w.extend_from_slice(&utxo.out_point.index.to_le_bytes());
            w.push(utxo.out_point.tree as u8);
            write_var_bytes(w, &utxo.script);
            write_var_bytes(w, &utxo.pub_key);
            write_var_bytes(w, &utxo.signature);
            w.push(utxo.opcode);
        }
        match &self.change {
            None => w.push(0),
            Some(change) => {
                w.push(1);
                w.extend_from_slice(&(change.value as u64).to_le_bytes());
                w.extend_from_slice(&change.version.to_le_bytes());
                write_var_bytes(w, &change.pk_script);
            }
        }
        w.push(self.flags);
        w.push(self.pairing_flags);
        Ok(())
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 8_476_848 }
    }
}

/// The `mixkeyxchg` message (dcrd `MsgMixKeyExchange`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixKeyExchange {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session the keys belong to.
    pub session_id: [u8; 32],
    /// The epoch of the session.
    pub epoch: u64,
    /// The run number within the session.
    pub run: u32,
    /// This peer's position in the session.
    pub pos: u32,
    /// The secp256k1 ECDH public key.
    pub ecdh: [u8; 33],
    /// The sntrup4591761 public key.
    pub pqpk: [u8; 1218],
    /// The secrets commitment.
    pub commitment: [u8; 32],
    /// Hashes of all pair requests this message references.
    pub seen_prs: Vec<Hash>,
}

impl MsgMixKeyExchange {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let epoch = r.read_u64()?;
        let run = r.read_u32()?;
        let pos = r.read_u32()?;
        let ecdh = r.take_array()?;
        let pqpk = r.take_array()?;
        let commitment = r.take_array()?;
        let seen_prs = read_seen_hashes(r)?;
        Ok(MsgMixKeyExchange {
            signature,
            identity,
            session_id,
            epoch,
            run,
            pos,
            ecdh,
            pqpk,
            commitment,
            seen_prs,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.epoch.to_le_bytes());
        w.extend_from_slice(&self.run.to_le_bytes());
        w.extend_from_slice(&self.pos.to_le_bytes());
        w.extend_from_slice(&self.ecdh);
        w.extend_from_slice(&self.pqpk);
        w.extend_from_slice(&self.commitment);
        write_seen_hashes(w, &self.seen_prs)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 17_815 }
    }
}

/// The `mixcphrtxt` message (dcrd `MsgMixCiphertexts`). The ciphertext and
/// seen-key-exchange lists share one on-wire count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixCiphertexts {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// One sntrup4591761 ciphertext per peer.
    pub ciphertexts: Vec<[u8; 1047]>,
    /// Hashes of the key exchange messages this message references (same
    /// count as `ciphertexts`).
    pub seen_key_exchanges: Vec<Hash>,
}

impl MsgMixCiphertexts {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let count = read_var_int(r)?;
        if count > MAX_MIX_PEERS {
            return Err(WireError::TooManyPrevMixMsgs {
                count,
                max: MAX_MIX_PEERS,
            });
        }
        let mut ciphertexts = Vec::new();
        for _ in 0..count {
            ciphertexts.push(r.take_array()?);
        }
        let mut seen_key_exchanges = Vec::new();
        for _ in 0..count {
            seen_key_exchanges.push(Hash(r.take_array()?));
        }
        Ok(MsgMixCiphertexts {
            signature,
            identity,
            session_id,
            run,
            ciphertexts,
            seen_key_exchanges,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.ciphertexts.len() != self.seen_key_exchanges.len() {
            return Err(WireError::InvalidMsg);
        }
        if self.ciphertexts.len() as u64 > MAX_MIX_PEERS {
            return Err(WireError::TooManyPrevMixMsgs {
                count: self.ciphertexts.len() as u64,
                max: MAX_MIX_PEERS,
            });
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_var_int(w, self.ciphertexts.len() as u64);
        for ct in &self.ciphertexts {
            w.extend_from_slice(ct);
        }
        for hash in &self.seen_key_exchanges {
            w.extend_from_slice(hash.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 552_584 }
    }
}

/// The `mixslotres` message (dcrd `MsgMixSlotReserve`): an
/// mcount-by-kpcount matrix of field values plus references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixSlotReserve {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// The mcount-by-peers matrix of encrypted field values.
    pub dc_mix: Vec<Vec<Vec<u8>>>,
    /// Hashes of the ciphertext messages this message references.
    pub seen_ciphertexts: Vec<Hash>,
}

impl MsgMixSlotReserve {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;

        let mcount = read_var_int(r)?;
        if mcount == 0 || mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        let kpcount = read_var_int(r)?;
        if kpcount == 0 || kpcount > MAX_MIX_PEERS {
            return Err(WireError::InvalidMsg);
        }
        let mut dc_mix = Vec::new();
        for _ in 0..mcount {
            let mut row = Vec::new();
            for _ in 0..kpcount {
                row.push(read_var_bytes(r, MAX_MIX_FIELD_VAL_LEN)?);
            }
            dc_mix.push(row);
        }
        let seen_ciphertexts = read_seen_hashes(r)?;
        Ok(MsgMixSlotReserve {
            signature,
            identity,
            session_id,
            run,
            dc_mix,
            seen_ciphertexts,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let mcount = self.dc_mix.len() as u64;
        if mcount == 0 || mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        let kpcount = self.dc_mix[0].len() as u64;
        if kpcount == 0 || kpcount > MAX_MIX_PEERS {
            return Err(WireError::InvalidMsg);
        }

        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_var_int(w, mcount);
        write_var_int(w, kpcount);
        for row in &self.dc_mix {
            if row.len() as u64 != kpcount {
                return Err(WireError::InvalidMsg);
            }
            for value in row {
                if value.len() as u64 > MAX_MIX_FIELD_VAL_LEN {
                    return Err(WireError::InvalidMsg);
                }
                write_var_bytes(w, value);
            }
        }
        write_seen_hashes(w, &self.seen_ciphertexts)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 17_318_030 }
    }
}

/// The `mixfactpoly` message (dcrd `MsgMixFactoredPoly`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixFactoredPoly {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// The roots of the factored polynomial.
    pub roots: Vec<Vec<u8>>,
    /// Hashes of the slot reservation messages this message references.
    pub seen_slot_reserves: Vec<Hash>,
}

impl MsgMixFactoredPoly {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let count = read_var_int(r)?;
        if count > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        let mut roots = Vec::new();
        for _ in 0..count {
            roots.push(read_var_bytes(r, MAX_MIX_FIELD_VAL_LEN)?);
        }
        let seen_slot_reserves = read_seen_hashes(r)?;
        Ok(MsgMixFactoredPoly {
            signature,
            identity,
            session_id,
            run,
            roots,
            seen_slot_reserves,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.roots.len() as u64 > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        for root in &self.roots {
            if root.len() as u64 > MAX_MIX_FIELD_VAL_LEN {
                return Err(WireError::InvalidMsg);
            }
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_var_int(w, self.roots.len() as u64);
        for root in &self.roots {
            write_var_bytes(w, root);
        }
        write_seen_hashes(w, &self.seen_slot_reserves)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 49_291 }
    }
}

/// Decode the x/y/msize-prefixed DC-net matrix (dcrd `readMixVects`).
fn read_mix_vects(r: &mut Cursor<'_>) -> Result<Vec<MixVect>, WireError> {
    let x = read_var_int(r)?;
    if x == 0 {
        return Ok(Vec::new());
    }
    let y = read_var_int(r)?;
    let msize = read_var_int(r)?;
    if x > MAX_MIX_MCOUNT || y > MAX_MIX_MCOUNT {
        return Err(WireError::InvalidMsg);
    }
    if msize != MIX_MSG_SIZE as u64 {
        return Err(WireError::InvalidMsg);
    }
    let mut vecs = Vec::new();
    for _ in 0..x {
        let mut vect = MixVect::new();
        for _ in 0..y {
            vect.push(r.take_array()?);
        }
        vecs.push(vect);
    }
    Ok(vecs)
}

/// Encode the DC-net matrix (dcrd `writeMixVects`).
fn write_mix_vects(w: &mut Vec<u8>, vecs: &[MixVect]) {
    write_var_int(w, vecs.len() as u64);
    if vecs.is_empty() {
        return;
    }
    write_var_int(w, vecs[0].len() as u64);
    write_var_int(w, MIX_MSG_SIZE as u64);
    for vect in vecs {
        for msg in vect {
            w.extend_from_slice(msg);
        }
    }
}

/// The `mixdcnet` message (dcrd `MsgMixDCNet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixDCNet {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// The DC-net vector broadcast, one [`MixVect`] per mixed message.
    pub dc_net: Vec<MixVect>,
    /// Hashes of the slot reservation messages this message references.
    pub seen_slot_reserves: Vec<Hash>,
}

impl MsgMixDCNet {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let dc_net = read_mix_vects(r)?;
        let seen_slot_reserves = read_seen_hashes(r)?;
        Ok(MsgMixDCNet {
            signature,
            identity,
            session_id,
            run,
            dc_net,
            seen_slot_reserves,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let mcount = self.dc_net.len() as u64;
        if mcount == 0 || mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_mix_vects(w, &self.dc_net);
        write_seen_hashes(w, &self.seen_slot_reserves)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 20_988_047 }
    }
}

/// The `mixconfirm` message (dcrd `MsgMixConfirm`): a partially signed mix
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixConfirm {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// The mix transaction, signed by this peer.
    pub mix: MsgTx,
    /// Hashes of the DC-net messages this message references.
    pub seen_dc_nets: Vec<Hash>,
}

impl MsgMixConfirm {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let mix = MsgTx::decode(r)?;
        let seen_dc_nets = read_seen_hashes(r)?;
        Ok(MsgMixConfirm {
            signature,
            identity,
            session_id,
            run,
            mix,
            seen_dc_nets,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        self.mix.encode_into(w);
        write_seen_hashes(w, &self.seen_dc_nets)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 1_016_520 }
    }
}

/// The `mixsecrets` message (dcrd `MsgMixSecrets`): reveals a
/// misbehaving-run participant's secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgMixSecrets {
    /// The message signature.
    pub signature: [u8; 64],
    /// The signing identity.
    pub identity: [u8; 33],
    /// The session.
    pub session_id: [u8; 32],
    /// The run number.
    pub run: u32,
    /// The seed used for all random operations.
    pub seed: [u8; 32],
    /// The unmixed slot reservation messages.
    pub slot_reserve_msgs: Vec<Vec<u8>>,
    /// The unmixed DC-net messages.
    pub dc_net_msgs: MixVect,
    /// Hashes of prior secrets messages this message references.
    pub seen_secrets: Vec<Hash>,
}

impl MsgMixSecrets {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let seed = r.take_array()?;

        let num_srs = read_var_int(r)?;
        if num_srs > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        let mut slot_reserve_msgs = Vec::new();
        for _ in 0..num_srs {
            slot_reserve_msgs.push(read_var_bytes(r, MAX_MIX_FIELD_VAL_LEN)?);
        }

        // Single MixVect (dcrd readMixVect): count, then message size when
        // non-empty.
        let n = read_var_int(r)?;
        let mut dc_net_msgs = MixVect::new();
        if n > 0 {
            let msize = read_var_int(r)?;
            if n > MAX_MIX_MCOUNT {
                return Err(WireError::InvalidMsg);
            }
            if msize != MIX_MSG_SIZE as u64 {
                return Err(WireError::InvalidMsg);
            }
            for _ in 0..n {
                dc_net_msgs.push(r.take_array()?);
            }
        }

        let seen_secrets = read_seen_hashes(r)?;
        Ok(MsgMixSecrets {
            signature,
            identity,
            session_id,
            run,
            seed,
            slot_reserve_msgs,
            dc_net_msgs,
            seen_secrets,
        })
    }

    pub(crate) fn encode(&self, w: &mut Vec<u8>, pver: u32) -> Result<(), WireError> {
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        // Note: like dcrd, the slot reserve list is *not* count-checked on
        // encode (an oversized list only fails at the framing layer via the
        // max payload); only the DC-net vector carries an encode-side limit
        // (dcrd `writeMixVect`).
        if self.dc_net_msgs.len() as u64 > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg);
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        w.extend_from_slice(&self.seed);
        write_var_int(w, self.slot_reserve_msgs.len() as u64);
        for sr in &self.slot_reserve_msgs {
            write_var_bytes(w, sr);
        }
        write_var_int(w, self.dc_net_msgs.len() as u64);
        if !self.dc_net_msgs.is_empty() {
            write_var_int(w, MIX_MSG_SIZE as u64);
            for msg in &self.dc_net_msgs {
                w.extend_from_slice(msg);
            }
        }
        write_seen_hashes(w, &self.seen_secrets)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 70_831 }
    }
}
