// SPDX-License-Identifier: ISC
//! Public key parse errors print dcrd's `Error()` text, dynamic parts and
//! all, checked live against dcrd's `secp256k1.ParsePubKey` and
//! `schnorr.ParsePubKey`.  The text reaches clients: stdaddr's P2PK
//! constructors wrap it as `failed to parse public key: %v`, which RPC
//! address decoding returns.  The port used to print the Rust variant name.

// Test-harness index arithmetic over fixed key lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_dcrec::secp256k1::schnorr::parse_pub_key;
use dcroxide_dcrec::secp256k1::{PrivateKey, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};

fn random_priv_key(rng: &mut SplitMix64) -> PrivateKey {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if let Some(key) = PrivateKey::from_bytes(&bytes) {
            return key;
        }
    }
}

/// The oracle's error text for `cmd`, or `None` when dcrd parses it.
fn oracle_error(oracle: &mut Oracle, cmd: &str, bytes: &[u8]) -> Option<String> {
    let resp = oracle.call(cmd, bytes);
    resp.get("error")
        .and_then(|e| e.as_str())
        .map(ToString::to_string)
}

/// Candidates that reach every `ParsePubKey` failure: bad lengths, bad
/// format bytes for each length, coordinates at or past the field prime,
/// mismatched hybrid oddness, and off-curve points in both the compressed
/// and the uncompressed wording.
fn candidates(rng: &mut SplitMix64) -> Vec<Vec<u8>> {
    let pk = random_priv_key(rng).public_key();
    let compressed = pk.serialize_compressed().to_vec();
    let uncompressed = pk.serialize_uncompressed().to_vec();
    let mut out = vec![compressed.clone(), uncompressed.clone()];

    // Every format byte on both lengths.
    let mut format = compressed.clone();
    format[0] = rng.next_u64() as u8;
    out.push(format);
    let mut format = uncompressed.clone();
    format[0] = rng.next_u64() as u8;
    out.push(format);

    // Both hybrid formats; one has the wrong oddness.
    for prefix in [0x06, 0x07] {
        let mut hybrid = uncompressed.clone();
        hybrid[0] = prefix;
        out.push(hybrid);
    }

    // Off-curve points: a tampered x (compressed, often with no y) and a
    // tampered y (uncompressed).
    let mut off = compressed.clone();
    off[1 + rng.below(32) as usize] ^= 1 << rng.below(8);
    out.push(off);
    let mut off = uncompressed.clone();
    off[33 + rng.below(32) as usize] ^= 1 << rng.below(8);
    out.push(off);

    // Coordinates at or past the field prime.
    let mut big = compressed.clone();
    big[1..33].fill(0xff);
    out.push(big);
    let mut big = uncompressed.clone();
    big[33..65].fill(0xff);
    out.push(big);

    // Wrong lengths.
    let cut = rng.below(uncompressed.len() as u64) as usize;
    out.push(uncompressed[..cut].to_vec());
    out
}

#[test]
fn pubkey_parse_error_text_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("pubkey parse error text");
    for i in 0..300 {
        for bytes in candidates(&mut rng) {
            let ours = PublicKey::parse(&bytes).err().map(|e| e.to_string());
            let theirs = oracle_error(&mut oracle, "pubkey_parse", &bytes);
            assert_eq!(ours, theirs, "case {i}: pubkey_parse {}", hex(&bytes));

            let ours = parse_pub_key(&bytes).err().map(|e| e.to_string());
            let theirs = oracle_error(&mut oracle, "schnorr_pubkey_parse", &bytes);
            assert_eq!(
                ours,
                theirs,
                "case {i}: schnorr_pubkey_parse {}",
                hex(&bytes)
            );
        }
    }
}
