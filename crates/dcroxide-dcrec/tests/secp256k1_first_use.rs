// SPDX-License-Identifier: ISC
//! Concurrent first use of the static generator tables behind ECDSA
//! verification, compact recovery and Schnorr verification.  This file
//! holds one test, so the tables are first used in it (each integration
//! test file is its own process): sixteen threads wait behind a barrier,
//! then each verifies a good and a tampered ECDSA signature and a Schnorr
//! signature and recovers a compact signature.  Thread i starts with call
//! site i % 3 (ECDSA verification, Schnorr verification, recovery) and
//! runs the other two after it, so each call site is some threads' first
//! multiply and all three race to build the tables.  Every verdict and
//! every recovered key must be right.  It shows that concurrent first use
//! gives right answers; it cannot show that a race happened.  The
//! signatures are made before the barrier: signing never touches the
//! tables.

use std::sync::{Arc, Barrier};
use std::thread;

use dcroxide_dcrec::secp256k1::{PrivateKey, ecdsa, schnorr};
use dcroxide_testutil::SplitMix64;

/// Threads racing to the first multiply.
const THREADS: usize = 16;

/// One thread's inputs, all made before the barrier.
struct Case {
    /// The signed hash.
    hash: [u8; 32],
    /// The signer's key, compressed.
    key: [u8; 33],
    /// A good ECDSA signature of `hash`.
    good: ecdsa::Signature,
    /// An ECDSA signature of another hash under the same key.
    tampered: ecdsa::Signature,
    /// A Schnorr signature of `hash`.
    schnorr: schnorr::Signature,
    /// A compact signature of `hash`, flagged compressed.
    compact: [u8; 65],
}

#[test]
fn concurrent_first_use_gives_right_answers() {
    let mut rng = SplitMix64::from_entropy("secp256k1 first use");
    let cases: Vec<Case> = (0..THREADS)
        .map(|_| {
            let priv_key = loop {
                let mut bytes = [0u8; 32];
                rng.fill(&mut bytes);
                if let Some(key) = PrivateKey::from_bytes(&bytes) {
                    break key;
                }
            };
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            let mut other = hash;
            other[0] ^= 1;
            Case {
                hash,
                key: priv_key.public_key().serialize_compressed(),
                good: ecdsa::sign(&priv_key, &hash),
                tampered: ecdsa::sign(&priv_key, &other),
                schnorr: schnorr::sign(&priv_key, &hash).expect("schnorr sign"),
                compact: ecdsa::sign_compact(&priv_key, &hash, true),
            }
        })
        .collect();

    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = cases
        .into_iter()
        .enumerate()
        .map(|(i, case)| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let key = dcroxide_dcrec::secp256k1::PublicKey::parse(&case.key).expect("key");
                barrier.wait();
                for step in 0..3 {
                    match (i + step) % 3 {
                        0 => {
                            assert!(case.good.verify(&case.hash, &key), "good ECDSA signature");
                            assert!(
                                !case.tampered.verify(&case.hash, &key),
                                "tampered ECDSA signature"
                            );
                        }
                        1 => assert!(case.schnorr.verify(&case.hash, &key), "Schnorr signature"),
                        _ => {
                            let (recovered, compressed) =
                                ecdsa::recover_compact(&case.compact, &case.hash)
                                    .expect("recovery");
                            assert!(compressed, "compressed flag");
                            assert_eq!(recovered.serialize_compressed(), case.key, "recovered key");
                        }
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }
}
