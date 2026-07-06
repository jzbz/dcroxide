// SPDX-License-Identifier: ISC
//! Mixing message identities and signatures (dcrd mixing
//! `message.go` and `signatures.go`).

// Bounded message and vector arithmetic mirrors Go; genuinely
// wrapping math uses explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_crypto::blake256;
use dcroxide_dcrec::secp256k1::schnorr;
use dcroxide_dcrec::secp256k1::{PUB_KEY_BYTES_LEN_COMPRESSED, PrivateKey, PublicKey};
use dcroxide_wire::{
    MsgMixCiphertexts, MsgMixConfirm, MsgMixDCNet, MsgMixFactoredPoly, MsgMixKeyExchange,
    MsgMixPairReq, MsgMixSecrets, MsgMixSlotReserve, WireError,
};

use crate::MixError;

const TAG: &[u8] = b"decred-mix-signature";

/// A mixing message (dcrd `Message`/`Signed`): in addition to wire
/// encoding, these messages are signed by an ephemeral mixing
/// participant identity, declare the previous messages that have been
/// observed by a peer in a mixing session, and include expiry
/// information.  The pair request returns `None`/empty for the fields
/// that do not apply as the first message in the protocol.
pub trait MixMessage {
    /// The message sender's public key identity (dcrd `Pub`).
    fn pub_key(&self) -> &[u8];
    /// The message signature (dcrd `Sig`).
    fn sig(&self) -> [u8; 64];
    /// Replace the message signature (dcrd writes through the `Sig`
    /// slice).
    fn set_sig(&mut self, sig: [u8; 64]);
    /// The mixing message identity hash (dcrd `Hash`).
    fn mix_hash(&self) -> Result<Hash, WireError>;
    /// The signed-data preimage (dcrd `WriteSignedData`).
    fn signed_data(&self) -> Result<Vec<u8>, WireError>;
    /// Hashes of all previous messages referenced (dcrd `PrevMsgs`;
    /// the pair request and factored polynomial return none).
    fn prev_msgs(&self) -> Vec<Hash>;
    /// The session ID (dcrd `Sid`; the pair request returns `None`).
    fn sid(&self) -> Option<[u8; 32]>;
    /// The run number (dcrd `GetRun`; the pair request returns 0).
    fn run(&self) -> u32;
    /// The protocol command string (dcrd `Command`).
    fn command(&self) -> &'static str;
}

macro_rules! impl_mix_message {
    ($msg:ty, $cmd:expr, sid: $sid:expr, run: $run:expr, prev: $prev:expr) => {
        impl MixMessage for $msg {
            fn pub_key(&self) -> &[u8] {
                &self.identity
            }
            fn sig(&self) -> [u8; 64] {
                self.signature
            }
            fn set_sig(&mut self, sig: [u8; 64]) {
                self.signature = sig;
            }
            fn mix_hash(&self) -> Result<Hash, WireError> {
                <$msg>::mix_hash(self)
            }
            fn signed_data(&self) -> Result<Vec<u8>, WireError> {
                <$msg>::signed_data(self)
            }
            #[allow(clippy::redundant_closure_call)]
            fn prev_msgs(&self) -> Vec<Hash> {
                $prev(self)
            }
            #[allow(clippy::redundant_closure_call)]
            fn sid(&self) -> Option<[u8; 32]> {
                $sid(self)
            }
            #[allow(clippy::redundant_closure_call)]
            fn run(&self) -> u32 {
                $run(self)
            }
            fn command(&self) -> &'static str {
                $cmd
            }
        }
    };
}

impl_mix_message!(MsgMixPairReq, "mixpairreq",
    sid: |_m: &MsgMixPairReq| None,
    run: |_m: &MsgMixPairReq| 0,
    prev: |_m: &MsgMixPairReq| Vec::new());
impl_mix_message!(MsgMixKeyExchange, "mixkeyxchg",
    sid: |m: &MsgMixKeyExchange| Some(m.session_id),
    run: |m: &MsgMixKeyExchange| m.run,
    prev: |m: &MsgMixKeyExchange| m.seen_prs.clone());
impl_mix_message!(MsgMixCiphertexts, "mixcphrtxt",
    sid: |m: &MsgMixCiphertexts| Some(m.session_id),
    run: |m: &MsgMixCiphertexts| m.run,
    prev: |m: &MsgMixCiphertexts| m.seen_key_exchanges.clone());
impl_mix_message!(MsgMixSlotReserve, "mixslotres",
    sid: |m: &MsgMixSlotReserve| Some(m.session_id),
    run: |m: &MsgMixSlotReserve| m.run,
    prev: |m: &MsgMixSlotReserve| m.seen_ciphertexts.clone());
impl_mix_message!(MsgMixFactoredPoly, "mixfactpoly",
    sid: |m: &MsgMixFactoredPoly| Some(m.session_id),
    run: |m: &MsgMixFactoredPoly| m.run,
    prev: |m: &MsgMixFactoredPoly| m.seen_slot_reserves.clone());
impl_mix_message!(MsgMixDCNet, "mixdcnet",
    sid: |m: &MsgMixDCNet| Some(m.session_id),
    run: |m: &MsgMixDCNet| m.run,
    prev: |m: &MsgMixDCNet| m.seen_slot_reserves.clone());
impl_mix_message!(MsgMixConfirm, "mixconfirm",
    sid: |m: &MsgMixConfirm| Some(m.session_id),
    run: |m: &MsgMixConfirm| m.run,
    prev: |m: &MsgMixConfirm| m.seen_dc_nets.clone());
impl_mix_message!(MsgMixSecrets, "mixsecrets",
    sid: |m: &MsgMixSecrets| Some(m.session_id),
    run: |m: &MsgMixSecrets| m.run,
    prev: |m: &MsgMixSecrets| m.seen_secrets.clone());

/// The hash that is Schnorr-signed: the signature tag, command,
/// session, run, and signed-data digest joined by commas (dcrd
/// `schnorrHash`).
fn schnorr_hash(command: &str, sid: &[u8], run: u32, sig_hash: &[u8]) -> [u8; 32] {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    let mut preimage = Vec::new();
    preimage.extend_from_slice(TAG);
    preimage.push(b',');
    preimage.extend_from_slice(command.as_bytes());
    preimage.push(b',');
    preimage.extend_from_slice(hex(sid).as_bytes());
    preimage.push(b',');
    preimage.extend_from_slice(run.to_string().as_bytes());
    preimage.push(b',');
    preimage.extend_from_slice(hex(sig_hash).as_bytes());
    blake256::sum256(&preimage)
}

const ZERO_SID: [u8; 32] = [0u8; 32];

/// Create a signature for the message and write the signature into
/// the message (dcrd `SignMessage`).
pub fn sign_message(m: &mut dyn MixMessage, priv_key: &PrivateKey) -> Result<(), MixError> {
    let signed_data = m.signed_data().map_err(|_| MixError::Signing)?;
    let sig_hash = blake256::sum256(&signed_data);

    let (sid, run) = match m.sid() {
        Some(sid) => (sid, m.run()),
        None => (ZERO_SID, 0),
    };

    let hash = schnorr_hash(m.command(), &sid, run, &sig_hash);
    let sig = schnorr::sign(priv_key, &hash).map_err(|_| MixError::Signing)?;
    m.set_sig(sig.serialize());
    Ok(())
}

/// Verify that a signed message carries a valid signature for the
/// represented identity (dcrd `VerifySignedMessage`).
pub fn verify_signed_message(m: &dyn MixMessage) -> bool {
    let Ok(signed_data) = m.signed_data() else {
        return false;
    };
    let sig_hash = blake256::sum256(&signed_data);

    let (sid, run) = match m.sid() {
        Some(sid) => (sid, m.run()),
        None => (ZERO_SID, 0),
    };

    verify(m.pub_key(), &m.sig(), &sig_hash, m.command(), &sid, run)
}

/// Verify a message signature from its signature hash and information
/// describing the message type and its place in the protocol (dcrd
/// `VerifySignature`).  Multiple messages of the same command, sid,
/// and run should not be signed by the same public key, and
/// demonstrating this can be used to prove malicious behavior.
pub fn verify_signature(
    pub_key: &[u8],
    sig: &[u8],
    sig_hash: &[u8],
    command: &str,
    sid: &[u8],
    run: u32,
) -> bool {
    verify(pub_key, sig, sig_hash, command, sid, run)
}

/// The shared verification path (dcrd `verify`).
fn verify(pk: &[u8], sig: &[u8], sig_hash: &[u8], command: &str, sid: &[u8], run: u32) -> bool {
    if pk.len() != PUB_KEY_BYTES_LEN_COMPRESSED {
        return false;
    }
    let Ok(pk_parsed) = PublicKey::parse(pk) else {
        return false;
    };
    let Ok(sig_parsed) = schnorr::parse_signature(sig) else {
        return false;
    };

    let hash = schnorr_hash(command, sid, run, sig_hash);
    sig_parsed.verify(&hash, &pk_parsed)
}
