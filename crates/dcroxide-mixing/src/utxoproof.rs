// SPDX-License-Identifier: ISC
//! UTXO ownership proofs for pair request messages (dcrd mixing
//! `utxoproof`).

// Bounded message and vector arithmetic mirrors Go; genuinely
// wrapping math uses explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_dcrec::secp256k1::schnorr;
use dcroxide_dcrec::secp256k1::{PrivateKey, PublicKey};

use crate::MixError;

// The signature hash is created from the serialization of:
//   tag , scheme , expiry pubkey
// No separator is written after expiry; it is fixed length.
const PREAMBLE: &[u8] = b"mixpr-utxoproof,P2PKH(EC-Schnorr-DCRv0),";

/// The serialized public key and parsed private key of a secp256k1
/// key pair (dcrd `Secp256k1KeyPair`).
pub struct Secp256k1KeyPair {
    /// The serialized public key.
    pub pub_key: Vec<u8>,
    /// The private key.
    pub priv_key: PrivateKey,
}

impl Secp256k1KeyPair {
    /// The UTXO proof of ownership over an output controlled by the
    /// keypair (dcrd `SignUtxoProof`).  The proof is only valid for
    /// the provided expiry height to prevent its inclusion in other
    /// PR messages signed by an unrelated identity.
    pub fn sign_utxo_proof(&self, expires: u32) -> Result<Vec<u8>, MixError> {
        let mut preimage = Vec::with_capacity(PREAMBLE.len() + 4 + self.pub_key.len());
        preimage.extend_from_slice(PREAMBLE);
        preimage.extend_from_slice(&expires.to_be_bytes());
        preimage.extend_from_slice(&self.pub_key);
        let hash = blake256::sum256(&preimage);

        let sig = schnorr::sign(&self.priv_key, &hash).map_err(|_| MixError::Signing)?;
        Ok(sig.serialize().to_vec())
    }
}

/// Validate the UTXO proof of an output controlled by a secp256k1
/// keypair for the given expiry height (dcrd
/// `ValidateSecp256k1P2PKH`).  Returns true only if the proof is
/// valid.
pub fn validate_secp256k1_p2pkh(pubkey: &[u8], proof: &[u8], expires: u32) -> bool {
    let Ok(pubkey_parsed) = PublicKey::parse(pubkey) else {
        return false;
    };
    let Ok(proof_parsed) = schnorr::parse_signature(proof) else {
        return false;
    };

    let mut preimage = Vec::with_capacity(PREAMBLE.len() + 4 + pubkey.len());
    preimage.extend_from_slice(PREAMBLE);
    preimage.extend_from_slice(&expires.to_be_bytes());
    preimage.extend_from_slice(pubkey);
    let hash = blake256::sum256(&preimage);

    proof_parsed.verify(&hash, &pubkey_parsed)
}
