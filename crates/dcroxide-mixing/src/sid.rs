// SPDX-License-Identifier: ISC
//! Mix session ID derivation and validation (dcrd mixing `sid.go`).

// Bounded message and vector arithmetic mirrors Go; genuinely
// wrapping math uses explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_crypto::blake256;
use dcroxide_wire::{MsgMixKeyExchange, MsgMixPairReq};

use crate::MixError;

/// Create the mix session identifier from an initial sorted slice of
/// PR message hashes (dcrd `deriveSessionID`).
fn derive_session_id(seen_prs: &[Hash], epoch: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(18 + 8 + seen_prs.len() * 32);
    preimage.extend_from_slice(b"decred-mix-session");
    preimage.extend_from_slice(&epoch.to_be_bytes());
    for pr in seen_prs {
        preimage.extend_from_slice(&pr.0);
    }
    blake256::sum256(&preimage)
}

fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// Perform an in-place sort of prs, moving each pair request to its
/// original unmixed position in the protocol, and return the session
/// ID (dcrd `SortPRsForSession`).
pub fn sort_prs_for_session(prs: &mut [MsgMixPairReq], epoch: u64) -> [u8; 32] {
    // Lexicographical sort PRs to derive the sid.  Every message here
    // is well formed, so the identity hashes are available.
    prs.sort_by(|a, b| {
        let a = a.mix_hash().expect("pair request hash");
        let b = b.mix_hash().expect("pair request hash");
        a.0.cmp(&b.0)
    });

    let mut hashes: Vec<Hash> = prs
        .iter()
        .map(|pr| pr.mix_hash().expect("pair request hash"))
        .collect();
    let sid = derive_session_id(&hashes, epoch);

    // XOR the sid into each PR hash and sort the PRs by the result.
    for h in &mut hashes {
        xor(&mut h.0, &sid);
    }
    let mut order: Vec<usize> = (0..prs.len()).collect();
    order.sort_by(|&i, &j| hashes[i].0.cmp(&hashes[j].0));

    let sorted: Vec<MsgMixPairReq> = order.iter().map(|&i| prs[i].clone()).collect();
    for (dst, src) in prs.iter_mut().zip(sorted) {
        *dst = src;
    }

    sid
}

/// Check whether the original unmixed peer order of a key exchange's
/// pair request hashes is validly sorted for the session ID, and for
/// a run-0 KE, also check that the session hash is derived from the
/// specified pair requests and epoch (dcrd `ValidateSession`).
pub fn validate_session(ke: &MsgMixKeyExchange) -> Result<(), MixError> {
    let mut h: Vec<Hash> = ke.seen_prs.clone();

    // XOR the sid into each hash.  The result should be sorted in all
    // runs.
    for hash in &mut h {
        xor(&mut hash.0, &ke.session_id);
    }
    let sorted = h.windows(2).all(|w| w[0].0 <= w[1].0);
    if !sorted {
        return Err(MixError::InvalidPROrder);
    }

    // If this is a run-0 KE, validate the session hash.
    if ke.run == 0 {
        let mut h = ke.seen_prs.clone();
        h.sort_by_key(|hash| hash.0);
        let derived_sid = derive_session_id(&h, ke.epoch);
        if derived_sid != ke.session_id {
            return Err(MixError::InvalidSessionID);
        }
    }

    Ok(())
}
