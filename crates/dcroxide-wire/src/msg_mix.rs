// SPDX-License-Identifier: ISC
//! The eight peer-to-peer StakeShuffle mixing messages (dcrd
//! `msgmixpairreq.go` … `msgmixsecrets.go`, `mixvect.go`), all gated at
//! [`MIX_VERSION`].
//!
//! Besides the wire codecs, the mixpool identity hashes and
//! signed-data preimages (dcrd `WriteHash`/`WriteSignedData`) live
//! here as `mix_hash`/`signed_data` on each message.

use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::cursor::Cursor;
use crate::error::{MessageText, WireError};
use crate::msgtx::{MsgTx, OutPoint, TxOut, read_script};
use crate::protocol::{MIX_VERSION, is_strict_ascii};
use crate::varint::{
    read_ascii_var_string, read_var_bytes, read_var_int, var_int_serialize_size, write_var_bytes,
    write_var_int,
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

/// dcrd's `ErrTooManyPrevMixMsgs` for `count` referenced messages, as
/// the function `op` words it.
fn too_many_prev_mix_msgs(op: &'static str, count: u64) -> WireError {
    WireError::TooManyPrevMixMsgs(
        MessageText::new(
            op,
            "too many previous referenced messages [count %v, max %v]",
        )
        .with_args(count, MAX_MIX_PEERS),
    )
}

/// Decode a varint-counted hash list bounded by [`MAX_MIX_PEERS`] with
/// dcrd's `ErrTooManyPrevMixMsgs`, raised by the decoder `op`.
fn read_seen_hashes(r: &mut Cursor<'_>, op: &'static str) -> Result<Vec<Hash>, WireError> {
    let count = read_var_int(r)?;
    if count > MAX_MIX_PEERS {
        return Err(too_many_prev_mix_msgs(op, count));
    }
    let mut seen = Vec::new();
    for _ in 0..count {
        seen.push(Hash(r.take_array()?));
    }
    Ok(seen)
}

/// The seen-hash list without its count check, for the hashing mode
/// (dcrd's `!hashing && srcount > MaxMixPeers`).
fn write_seen_hashes_unchecked(w: &mut Vec<u8>, seen: &[Hash]) {
    write_var_int(w, seen.len() as u64);
    for hash in seen {
        w.extend_from_slice(hash.as_bytes());
    }
}

/// The seen-hash list with dcrd's count check, raised by the encoder
/// `op`.
fn write_seen_hashes(w: &mut Vec<u8>, seen: &[Hash], op: &'static str) -> Result<(), WireError> {
    if seen.len() as u64 > MAX_MIX_PEERS {
        return Err(too_many_prev_mix_msgs(op, seen.len() as u64));
    }
    write_var_int(w, seen.len() as u64);
    for hash in seen {
        w.extend_from_slice(hash.as_bytes());
    }
    Ok(())
}

impl MsgMixPairReq {
    pub(crate) fn decode(r: &mut Cursor<'_>, pver: u32) -> Result<Self, WireError> {
        const OP: &str = "MsgMixPairReq.BtcDecode";
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let expiry = r.read_u32()?;
        let mix_amount = r.read_u64()? as i64;
        if mix_amount < 0 {
            return Err(WireError::InvalidMsg(MessageText::new(
                OP,
                "mixing pair request contains negative mixed amount",
            )));
        }
        let script_class = read_ascii_var_string(r, MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN)?;
        let tx_version = r.read_u16()?;
        let lock_time = r.read_u32()?;
        let message_count = r.read_u32()?;
        let input_value = r.read_u64()? as i64;
        if input_value < 0 {
            return Err(WireError::InvalidMsg(MessageText::new(
                OP,
                "mixing pair request contains negative input value",
            )));
        }

        let count = read_var_int(r)?;
        if count > MAX_MIX_PAIR_REQ_UTXOS {
            return Err(WireError::TooManyMixPairReqUTXOs(
                MessageText::new(OP, "too many UTXOs in message [count %v, max %v]")
                    .with_args(count, MAX_MIX_PAIR_REQ_UTXOS),
            ));
        }
        let mut utxos = Vec::new();
        for _ in 0..count {
            let out_point = OutPoint {
                hash: Hash(r.take_array()?),
                index: r.read_u32()?,
                tree: r.read_u8()? as i8,
            };
            let script =
                read_var_bytes(r, MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN, "MixPairReqUTXO.Script")?;
            let pub_key = read_var_bytes(
                r,
                MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN,
                "MixPairReqUTXO.PubKey",
            )?;
            let signature = read_var_bytes(
                r,
                MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN,
                "MixPairReqUTXO.Signature",
            )?;
            let opcode = r.read_u8()?;
            utxos.push(MixPairReqUTXO {
                out_point,
                script,
                pub_key,
                signature,
                opcode,
            });
        }

        // The change output is read by dcrd `readTxOut`.
        let change = match r.read_u8()? {
            0 => None,
            1 => Some(TxOut {
                value: r.read_u64()? as i64,
                version: r.read_u16()?,
                pk_script: read_script(r, "transaction output public key script")?,
            }),
            _ => {
                return Err(WireError::InvalidMsg(MessageText::new(
                    OP,
                    "invalid change TxOut encoding",
                )));
            }
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
        const OP: &str = "MsgMixPairReq.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.script_class.len() as u64 > MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN {
            return Err(WireError::MixPairReqScriptClassTooLong(
                MessageText::new(OP, "script class length is too long [len %d, max %d]").with_args(
                    self.script_class.len() as u64,
                    MAX_MIX_PAIR_REQ_SCRIPT_CLASS_LEN,
                ),
            ));
        }
        if !is_strict_ascii(self.script_class.as_bytes()) {
            return Err(WireError::MalformedStrictString(MessageText::new(
                OP,
                "script class string is not strict ASCII",
            )));
        }
        if self.utxos.len() as u64 > MAX_MIX_PAIR_REQ_UTXOS {
            return Err(WireError::TooManyMixPairReqUTXOs(
                MessageText::new(OP, "too many UTXOs in message [%v]")
                    .with_arg(self.utxos.len() as u64),
            ));
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
                return Err(WireError::VarBytesTooLong(
                    MessageText::new(OP, "UTXO script is too long [len %v, max %v]")
                        .with_args(utxo.script.len() as u64, MAX_MIX_PAIR_REQ_UTXO_SCRIPT_LEN),
                ));
            }
            if utxo.pub_key.len() as u64 > MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN {
                return Err(WireError::VarBytesTooLong(
                    MessageText::new(OP, "UTXO public key is too long [len %v, max %v]")
                        .with_args(utxo.pub_key.len() as u64, MAX_MIX_PAIR_REQ_UTXO_PUB_KEY_LEN),
                ));
            }
            if utxo.signature.len() as u64 > MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN {
                return Err(WireError::VarBytesTooLong(
                    MessageText::new(OP, "UTXO signature is too long [len %v, max %v]").with_args(
                        utxo.signature.len() as u64,
                        MAX_MIX_PAIR_REQ_UTXO_SIGNATURE_LEN,
                    ),
                ));
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

    /// A description of the type of transaction being mixed:
    /// the mix amount, script class, transaction version, lock time,
    /// and pairing flags (dcrd `Pairing`).  Only pair requests with
    /// identical pairing descriptions may be mixed together.
    pub fn pairing(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(
            8usize
                .saturating_add(var_int_serialize_size(self.script_class.len() as u64))
                .saturating_add(self.script_class.len())
                .saturating_add(7),
        );
        w.extend_from_slice(&(self.mix_amount as u64).to_le_bytes());
        write_var_int(&mut w, self.script_class.len() as u64);
        w.extend_from_slice(self.script_class.as_bytes());
        w.extend_from_slice(&self.tx_version.to_le_bytes());
        w.extend_from_slice(&self.lock_time.to_le_bytes());
        w.push(self.pairing_flags);
        w
    }

    /// The block height at which the message expires (dcrd
    /// `Expires`).
    pub fn expires(&self) -> u32 {
        self.expiry
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
        let seen_prs = read_seen_hashes(r, "MsgMixKeyExchange.BtcDecode")?;
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
        write_seen_hashes(w, &self.seen_prs, "MsgMixKeyExchange.BtcEncode")
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
            return Err(too_many_prev_mix_msgs("MsgMixCiphertexts.BtcDecode", count));
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
        const OP: &str = "MsgMixCiphertexts.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.ciphertexts.len() != self.seen_key_exchanges.len() {
            return Err(WireError::InvalidMsg(
                MessageText::new(
                    OP,
                    "differing counts of ciphertexts (%d) and seen key exchange messages (%d)",
                )
                .with_args(
                    self.ciphertexts.len() as u64,
                    self.seen_key_exchanges.len() as u64,
                ),
            ));
        }
        if self.ciphertexts.len() as u64 > MAX_MIX_PEERS {
            return Err(too_many_prev_mix_msgs(OP, self.ciphertexts.len() as u64));
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
        const OP: &str = "MsgMixSlotReserve.BtcDecode";
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;

        let mcount = read_var_int(r)?;
        if mcount == 0 {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too few mixed messages [%v]").with_arg(mcount),
            ));
        }
        if mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many total mixed messages [%v]").with_arg(mcount),
            ));
        }
        let kpcount = read_var_int(r)?;
        if kpcount == 0 {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too few mixing peers [%v]").with_arg(kpcount),
            ));
        }
        if kpcount > MAX_MIX_PEERS {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many mixing peers [count %v, max %v]")
                    .with_args(kpcount, MAX_MIX_PEERS),
            ));
        }
        let mut dc_mix = Vec::new();
        for _ in 0..mcount {
            let mut row = Vec::new();
            for _ in 0..kpcount {
                row.push(read_var_bytes(
                    r,
                    MAX_MIX_FIELD_VAL_LEN,
                    "slot reservation field value",
                )?);
            }
            dc_mix.push(row);
        }
        let seen_ciphertexts = read_seen_hashes(r, OP)?;
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
        const OP: &str = "MsgMixSlotReserve.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let mcount = self.dc_mix.len() as u64;
        if mcount == 0 {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too few mixed messages [%v]").with_arg(mcount),
            ));
        }
        if mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many total mixed messages [%v]").with_arg(mcount),
            ));
        }
        let kpcount = self.dc_mix[0].len() as u64;
        if kpcount == 0 {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too few mixing peers [%v]").with_arg(kpcount),
            ));
        }
        if kpcount > MAX_MIX_PEERS {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many mixing peers [%v]").with_arg(kpcount),
            ));
        }

        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_var_int(w, mcount);
        write_var_int(w, kpcount);
        for row in &self.dc_mix {
            if row.len() as u64 != kpcount {
                return Err(WireError::InvalidMsg(MessageText::new(
                    OP,
                    "invalid matrix dimensions",
                )));
            }
            for value in row {
                if value.len() as u64 > MAX_MIX_FIELD_VAL_LEN {
                    return Err(WireError::InvalidMsg(MessageText::new(
                        OP,
                        "value exceeds bytes necessary to represent number in field",
                    )));
                }
                write_var_bytes(w, value);
            }
        }
        write_seen_hashes(w, &self.seen_ciphertexts, OP)
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
        const OP: &str = "MsgMixFactoredPoly.BtcDecode";
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let count = read_var_int(r)?;
        if count > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many roots in message [count %v, max %v]")
                    .with_args(count, MAX_MIX_MCOUNT),
            ));
        }
        let mut roots = Vec::new();
        for _ in 0..count {
            roots.push(read_var_bytes(
                r,
                MAX_MIX_FIELD_VAL_LEN,
                "MixFactoredPoly.Roots",
            )?);
        }
        let seen_slot_reserves = read_seen_hashes(r, OP)?;
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
        const OP: &str = "MsgMixFactoredPoly.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        if self.roots.len() as u64 > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(
                    OP,
                    "too many solutions to factored polynomial [count %v, max %v]",
                )
                .with_args(self.roots.len() as u64, MAX_MIX_MCOUNT),
            ));
        }
        for root in &self.roots {
            if root.len() as u64 > MAX_MIX_FIELD_VAL_LEN {
                return Err(WireError::InvalidMsg(MessageText::new(
                    OP,
                    "root exceeds bytes necessary to represent number in field",
                )));
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
        write_seen_hashes(w, &self.seen_slot_reserves, OP)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 49_291 }
    }
}

/// dcrd's `ErrInvalidMsg` for a DC-net vector dimension over
/// [`MAX_MIX_MCOUNT`] (`readMixVects`, `readMixVect`, `writeMixVect`).
fn mix_vect_too_large(op: &'static str) -> WireError {
    WireError::InvalidMsg(MessageText::new(
        op,
        "DC-net mix vector dimensions are too large for maximum message count",
    ))
}

/// dcrd's `ErrInvalidMsg` for a DC-net message size other than
/// [`MIX_MSG_SIZE`] (`readMixVects`, `readMixVect`).
fn mix_msg_size_mismatch(op: &'static str, msize: u64) -> WireError {
    WireError::InvalidMsg(
        MessageText::new(op, "mixed message length must be %d [got: %d]")
            .with_args(MIX_MSG_SIZE as u64, msize),
    )
}

/// Decode the x/y/msize-prefixed DC-net matrix (dcrd `readMixVects`),
/// for the decoder `op`.
fn read_mix_vects(r: &mut Cursor<'_>, op: &'static str) -> Result<Vec<MixVect>, WireError> {
    let x = read_var_int(r)?;
    if x == 0 {
        return Ok(Vec::new());
    }
    let y = read_var_int(r)?;
    let msize = read_var_int(r)?;
    if x > MAX_MIX_MCOUNT || y > MAX_MIX_MCOUNT {
        return Err(mix_vect_too_large(op));
    }
    if msize != MIX_MSG_SIZE as u64 {
        return Err(mix_msg_size_mismatch(op, msize));
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
        const OP: &str = "MsgMixDCNet.BtcDecode";
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let dc_net = read_mix_vects(r, OP)?;
        let seen_slot_reserves = read_seen_hashes(r, OP)?;
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
        self.write_no_signature(w, pver, false)
    }

    /// dcrd `writeMessageNoSignature`, whose structural checks are
    /// skipped when the destination is a hasher rather than a wire
    /// buffer (`msgmixdcnet.go:130-145`, each guarded by `!hashing`).
    ///
    /// That mode is not a convenience: a `mixdcnet` with a zero outer
    /// dimension decodes but does not re-encode (QK-0010), and dcrd
    /// still hashes and signs it, so it reaches `AcceptMessage` with a
    /// real identity hash, gets its signature verified, and is pooled or
    /// orphaned. Hashing it through the validating encoder instead made
    /// the hash fail, which dropped the message at intake as an untyped
    /// error -- unbannable, where a bad signature on it is bannable at
    /// any service level.
    pub(crate) fn write_no_signature(
        &self,
        w: &mut Vec<u8>,
        pver: u32,
        hashing: bool,
    ) -> Result<(), WireError> {
        const OP: &str = "MsgMixDCNet.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        let mcount = self.dc_net.len() as u64;
        if !hashing && mcount == 0 {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too few mixed messages [%v]").with_arg(mcount),
            ));
        }
        if !hashing && mcount > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many total mixed messages [%v]").with_arg(mcount),
            ));
        }
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.identity);
        w.extend_from_slice(&self.session_id);
        w.extend_from_slice(&self.run.to_le_bytes());
        write_mix_vects(w, &self.dc_net);
        if hashing {
            write_seen_hashes_unchecked(w, &self.seen_slot_reserves);
            return Ok(());
        }
        write_seen_hashes(w, &self.seen_slot_reserves, OP)
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
        let seen_dc_nets = read_seen_hashes(r, "MsgMixConfirm.BtcDecode")?;
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
        write_seen_hashes(w, &self.seen_dc_nets, "MsgMixConfirm.BtcEncode")
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
        const OP: &str = "MsgMixSecrets.BtcDecode";
        let (signature, identity) = decode_sig_ident(r, pver)?;
        let session_id = r.take_array()?;
        let run = r.read_u32()?;
        let seed = r.take_array()?;

        let num_srs = read_var_int(r)?;
        if num_srs > MAX_MIX_MCOUNT {
            return Err(WireError::InvalidMsg(
                MessageText::new(OP, "too many total mixed messages [count %v, max %v]")
                    .with_args(num_srs, MAX_MIX_MCOUNT),
            ));
        }
        let mut slot_reserve_msgs = Vec::new();
        for _ in 0..num_srs {
            slot_reserve_msgs.push(read_var_bytes(
                r,
                MAX_MIX_FIELD_VAL_LEN,
                "slot reservation mixed message",
            )?);
        }

        // Single MixVect (dcrd readMixVect): count, then message size when
        // non-empty.
        let n = read_var_int(r)?;
        let mut dc_net_msgs = MixVect::new();
        if n > 0 {
            let msize = read_var_int(r)?;
            if n > MAX_MIX_MCOUNT {
                return Err(mix_vect_too_large(OP));
            }
            if msize != MIX_MSG_SIZE as u64 {
                return Err(mix_msg_size_mismatch(OP, msize));
            }
            for _ in 0..n {
                dc_net_msgs.push(r.take_array()?);
            }
        }

        let seen_secrets = read_seen_hashes(r, OP)?;
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
        const OP: &str = "MsgMixSecrets.BtcEncode";
        if pver < MIX_VERSION {
            return Err(WireError::MsgInvalidForPVer);
        }
        // dcrd checks the seen count before writing anything, so it
        // wins over the DC-net vector's limit.
        if self.seen_secrets.len() as u64 > MAX_MIX_PEERS {
            return Err(too_many_prev_mix_msgs(OP, self.seen_secrets.len() as u64));
        }
        // Note: like dcrd, the slot reserve list is *not* count-checked on
        // encode (an oversized list only fails at the framing layer via the
        // max payload); only the DC-net vector carries an encode-side limit
        // (dcrd `writeMixVect`).
        if self.dc_net_msgs.len() as u64 > MAX_MIX_MCOUNT {
            return Err(mix_vect_too_large(OP));
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
        write_seen_hashes(w, &self.seen_secrets, OP)
    }

    pub(crate) fn max_payload_length(pver: u32) -> u32 {
        if pver < MIX_VERSION { 0 } else { 70_831 }
    }
}

/// Generate the mixing identity hash and signed-data preimage methods
/// (dcrd `WriteHash`/`Hash` and `WriteSignedData`) for a mix message.
///
/// The identity hash is the BLAKE-256 digest of the full message
/// serialization at [`MIX_VERSION`], and the signed data is the
/// command string with "-sig" appended as a var string followed by
/// the serialization without the leading signature.  dcrd feeds a
/// hasher and silently drops encoding errors, hashing whatever
/// partial preimage was written; such messages cannot arrive through
/// decoding, and this port surfaces the error instead.
macro_rules! mix_message_hashes {
    ($msg:ty, $cmd:expr) => {
        impl $msg {
            /// The mixing message identity hash (dcrd
            /// `WriteHash`/`Hash`).
            ///
            /// dcrd's is total: `WriteHash` discards
            /// `writeMessageNoSignature`'s error, so an invalid message
            /// is hashed over whatever prefix was written before the
            /// check fired.  This one surfaces the error instead.
            ///
            /// The difference is unreachable from the wire for these
            /// types: every check that can fire here is one dcrd also
            /// enforces at decode, so a message that arrived over the
            /// network has already passed it.  `MsgMixDCNet` is the
            /// exception -- it has a check dcrd skips while hashing and
            /// a shape the decoder accepts -- and carries its own pair
            /// below.
            pub fn mix_hash(&self) -> Result<Hash, WireError> {
                let mut buf = Vec::new();
                self.encode(&mut buf, MIX_VERSION)?;
                Ok(Hash(dcroxide_crypto::blake256::sum256(&buf)))
            }

            /// The preimage of the data committed to by the message
            /// signature (dcrd `WriteSignedData`).
            pub fn signed_data(&self) -> Result<Vec<u8>, WireError> {
                let mut msg_buf = Vec::new();
                self.encode(&mut msg_buf, MIX_VERSION)?;
                let cmd = concat!($cmd, "-sig");
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "msg_buf.len() >= 64: a successful encode writes the 64-byte signature first"
                )]
                let mut buf = Vec::with_capacity(1 + cmd.len() + msg_buf.len() - 64);
                write_var_int(&mut buf, cmd.len() as u64);
                buf.extend_from_slice(cmd.as_bytes());
                buf.extend_from_slice(&msg_buf[64..]);
                Ok(buf)
            }
        }
    };
}

mix_message_hashes!(MsgMixPairReq, "mixpairreq");
mix_message_hashes!(MsgMixKeyExchange, "mixkeyxchg");
mix_message_hashes!(MsgMixCiphertexts, "mixcphrtxt");
mix_message_hashes!(MsgMixSlotReserve, "mixslotres");
mix_message_hashes!(MsgMixFactoredPoly, "mixfactpoly");
mix_message_hashes!(MsgMixConfirm, "mixconfirm");
mix_message_hashes!(MsgMixSecrets, "mixsecrets");

impl MsgMixDCNet {
    /// The mixing message identity hash (dcrd `WriteHash`/`Hash`).
    ///
    /// Total, because dcrd's is: `WriteHash` discards
    /// `writeMessageNoSignature`'s error entirely
    /// (`msgmixdcnet.go:113-117`), and in hashing mode it has none to
    /// give.  The `Result` stays for the shape the other seven share.
    pub fn mix_hash(&self) -> Result<Hash, WireError> {
        let mut buf = Vec::new();
        self.write_no_signature(&mut buf, MIX_VERSION, true)?;
        Ok(Hash(dcroxide_crypto::blake256::sum256(&buf)))
    }

    /// The preimage of the data committed to by the message signature
    /// (dcrd `WriteSignedData`), in the same hashing mode.
    pub fn signed_data(&self) -> Result<Vec<u8>, WireError> {
        let mut msg_buf = Vec::new();
        self.write_no_signature(&mut msg_buf, MIX_VERSION, true)?;
        let cmd = "mixdcnet-sig";
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "msg_buf.len() >= 64: a successful write_no_signature writes the 64-byte signature first"
        )]
        let mut buf = Vec::with_capacity(1 + cmd.len() + msg_buf.len() - 64);
        write_var_int(&mut buf, cmd.len() as u64);
        buf.extend_from_slice(cmd.as_bytes());
        buf.extend_from_slice(&msg_buf[64..]);
        Ok(buf)
    }
}
