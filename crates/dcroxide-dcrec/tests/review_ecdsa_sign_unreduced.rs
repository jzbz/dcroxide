// SPDX-License-Identifier: ISC
//! `ecdsa::sign` over a hash at or above the group order N matches dcrd's
//! `ecdsa.Sign` byte for byte.  libsecp256k1 reduces the hash mod N before
//! deriving its RFC6979 nonce and dcrd's `NonceRFC6979` does not, so for
//! those hashes the two picked different nonces and returned different
//! (both valid) signatures.  A random digest lands there with odds of
//! about 2^-128, which is why the random-hash differential never saw it.

use dcroxide_dcrec::secp256k1::ecdsa::sign;
use dcroxide_dcrec::secp256k1::{GROUP_ORDER_BYTES, PrivateKey};
use dcroxide_testutil::{SplitMix64, hex, oracle_or_skip, unhex};

fn key(hex_key: &str) -> PrivateKey {
    let bytes: [u8; 32] = unhex(hex_key).try_into().expect("32 bytes");
    PrivateKey::from_bytes(&bytes).expect("valid key")
}

/// dcrd's `ecdsa.Sign` for key 1 over the all-ones hash (dcrec/secp256k1
/// at the parity pin), which libsecp256k1's own nonce does not produce.
#[test]
fn a_hash_above_the_order_signs_as_dcrd_does() {
    const DCRD: &str = "304402203f8fe493cf305a7f02b2d2c060ba66a8f7bd13a7a64d5200c0655ad069bd85b5\
                        02201cf94236c3857e33a1023a5216cbc81b1dc3adcc1c71f4212df1997ffdfb140a";
    let priv_key = key("0000000000000000000000000000000000000000000000000000000000000001");
    let hash = [0xffu8; 32];
    let sig = sign(&priv_key, &hash);
    assert_eq!(hex(&sig.serialize()), DCRD);
    assert!(sig.verify(&hash, &priv_key.public_key()));

    // libsecp256k1 signing the same hash reduces it first.
    let secret = libsecp256k1::SecretKey::from_secret_bytes(
        unhex("0000000000000000000000000000000000000000000000000000000000000001")
            .try_into()
            .expect("32 bytes"),
    )
    .expect("valid key");
    let theirs = libsecp256k1::ecdsa::sign(libsecp256k1::Message::from_digest(hash), &secret);
    assert_ne!(hex(&theirs.serialize_der()), DCRD);
}

#[test]
fn hashes_at_or_above_the_order_sign_as_dcrd_does() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ecdsa sign unreduced hash");

    // The order itself, the all-ones hash, and random hashes in [N, 2^256).
    let mut hashes = vec![GROUP_ORDER_BYTES, [0xff; 32]];
    for _ in 0..200 {
        let mut hash = [0xffu8; 32];
        rng.fill(&mut hash[16..]);
        if hash >= GROUP_ORDER_BYTES {
            hashes.push(hash);
        }
    }
    for (i, hash) in hashes.iter().enumerate() {
        let (key_bytes, priv_key) = loop {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            if let Some(key) = PrivateKey::from_bytes(&bytes) {
                break (bytes, key);
            }
        };
        let ours = sign(&priv_key, hash);
        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(&key_bytes);
        req.extend_from_slice(hash);
        assert_eq!(
            hex(&ours.serialize()),
            oracle.call_ok("ecdsa_sign", &req),
            "case {i}: key {} hash {}",
            hex(&key_bytes),
            hex(hash)
        );
        assert!(ours.verify(hash, &priv_key.public_key()), "case {i}");
    }
}
