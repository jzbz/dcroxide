// SPDX-License-Identifier: ISC
//! The signature verification cache (dcrd `txscript/sigcache.go`): a
//! bounded map memoizing SUCCESSFUL signature verifications keyed by
//! the signature hash, so a transaction already verified — typically
//! on mempool acceptance — skips the expensive curve math when its
//! block connects.  Only valid signatures are ever added, which also
//! mitigates the denial-of-service attack dcrd documents (an attacker
//! cannot poison the cache with invalid signatures).
//!
//! Parity notes:
//! - dcrd keys entries by `sigHash` and, on a key hit, compares the
//!   parsed signature and public key (`Signature.IsEqual` /
//!   `PublicKey.IsEqual`).  The port stores and compares the raw
//!   signature and public key bytes instead: byte inequality between
//!   encodings that parse to the same values only produces a cache
//!   miss and a fresh verify, so results are identical.
//! - dcrd consults the cache only in the ECDSA paths
//!   (`opcodeCheckSig`, `opcodeCheckMultiSig`); the port also caches
//!   the Ed25519 and Schnorr suites from `opcodeCheckSigAlt`.  Each
//!   entry records its [`SigCacheSuite`] and a hit requires the suite
//!   to match, so a (vanishingly unlikely) cross-suite collision of
//!   hash, signature bytes, and key bytes cannot produce a false hit.
//!   Caching more successful verifications is result-invariant.
//! - dcrd evicts one random existing entry when at capacity, relying
//!   on Go's randomized map iteration start.  The port removes the
//!   first entry in the `HashMap`'s iteration order: the order is
//!   seeded per map by `RandomState`, so the victim is arbitrary and
//!   an adversary cannot target it without a preimage attack on the
//!   hasher key — the same argument dcrd's comment makes.
//! - dcrd's `EvictEntries` (the proactive SipHash-keyed eviction of
//!   entries for transactions in newly-matured blocks, run from a
//!   server goroutine) is not ported: it needs a SipHash dependency
//!   and the server notification loop, and only affects which entries
//!   random eviction later removes — never results.
//!
//! Without the `std` feature (and outside tests) this crate is
//! `no_std`, and [`SigCache`] compiles as an inert stub whose lookups
//! always miss and whose inserts do nothing, keeping every signature
//! that threads a cache through unchanged across configurations.

/// The signature suite a cached verification belongs to, mirroring
/// the `dcrec.SignatureType` values the script engine dispatches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigCacheSuite {
    /// secp256k1 ECDSA (`dcrec.STEcdsaSecp256k1`).
    EcdsaSecp256k1,
    /// Ed25519 (`dcrec.STEd25519`).
    Ed25519,
    /// secp256k1 EC-Schnorr-DCRv0 (`dcrec.STSchnorrSecp256k1`).
    SchnorrSecp256k1,
}

/// One cached successful verification: the suite plus the raw
/// signature and public key bytes compared on a key hit (dcrd
/// `sigCacheEntry`; the `shortTxHash` field only feeds the unported
/// proactive eviction and is omitted).
#[cfg(any(test, feature = "std"))]
struct SigCacheEntry {
    suite: SigCacheSuite,
    signature: Vec<u8>,
    pub_key: Vec<u8>,
}

/// The signature verification cache (dcrd `SigCache`): a bounded map
/// from signature hash to the signature and public key bytes of a
/// verification that succeeded, with random-entry eviction when full.
/// Safe for concurrent use — readers only block while a writer is
/// adding an entry, matching dcrd's `RWMutex`.
#[cfg(any(test, feature = "std"))]
pub struct SigCache {
    /// The cached successful verifications by signature hash (dcrd
    /// `validSigs`).
    valid_sigs: std::sync::RwLock<std::collections::HashMap<[u8; 32], SigCacheEntry>>,
    /// The maximum number of entries (dcrd `maxEntries`); zero
    /// disables the cache — adds are dropped, exactly like dcrd's
    /// early return in `Add`.
    max_entries: usize,
}

#[cfg(any(test, feature = "std"))]
impl SigCache {
    /// A new cache holding at most `max_entries` verifications (dcrd
    /// `NewSigCache`).  Random entries are evicted to make room once
    /// the maximum is reached.
    pub fn new(max_entries: usize) -> SigCache {
        SigCache {
            valid_sigs: std::sync::RwLock::new(std::collections::HashMap::with_capacity(
                max_entries,
            )),
            max_entries,
        }
    }

    /// Whether a successful verification of `signature` over
    /// `sig_hash` under `pub_key` in the given suite is cached (dcrd
    /// `SigCache.Exists`).
    pub fn exists(
        &self,
        sig_hash: &[u8; 32],
        suite: SigCacheSuite,
        signature: &[u8],
        pub_key: &[u8],
    ) -> bool {
        let valid_sigs = self.valid_sigs.read().expect("sigcache lock poisoned");
        valid_sigs.get(sig_hash).is_some_and(|entry| {
            entry.suite == suite && entry.signature == signature && entry.pub_key == pub_key
        })
    }

    /// Record a SUCCESSFUL verification of `signature` over
    /// `sig_hash` under `pub_key` (dcrd `SigCache.Add`).  Callers
    /// must never add failed verifications.  When the cache is full
    /// an arbitrary existing entry is evicted first (see the module
    /// notes on how the randomized eviction is approximated).
    pub fn add(&self, sig_hash: &[u8; 32], suite: SigCacheSuite, signature: &[u8], pub_key: &[u8]) {
        let mut valid_sigs = self.valid_sigs.write().expect("sigcache lock poisoned");

        if self.max_entries == 0 {
            return;
        }

        // If adding this new entry would put the cache over the
        // maximum number of allowed entries, evict one.  The victim
        // is the first entry in the map's iteration order, which the
        // per-map `RandomState` seed makes arbitrary (dcrd relies on
        // Go's random map iteration start the same way).
        if valid_sigs.len() >= self.max_entries {
            let victim = valid_sigs.keys().next().copied();
            if let Some(victim) = victim {
                valid_sigs.remove(&victim);
            }
        }
        valid_sigs.insert(
            *sig_hash,
            SigCacheEntry {
                suite,
                signature: signature.to_vec(),
                pub_key: pub_key.to_vec(),
            },
        );
    }
}

/// The inert `no_std` stand-in for the signature verification cache:
/// every lookup misses and every insert is dropped, so engines given
/// one behave byte-identically to engines given none.
#[cfg(not(any(test, feature = "std")))]
pub struct SigCache {
    _inert: (),
}

#[cfg(not(any(test, feature = "std")))]
impl SigCache {
    /// A new inert cache; `max_entries` is ignored because nothing is
    /// ever stored without the `std` feature.
    pub fn new(_max_entries: usize) -> SigCache {
        SigCache { _inert: () }
    }

    /// Always a miss: the inert cache stores nothing.
    pub fn exists(
        &self,
        _sig_hash: &[u8; 32],
        _suite: SigCacheSuite,
        _signature: &[u8],
        _pub_key: &[u8],
    ) -> bool {
        false
    }

    /// Dropped: the inert cache stores nothing.
    pub fn add(
        &self,
        _sig_hash: &[u8; 32],
        _suite: SigCacheSuite,
        _signature: &[u8],
        _pub_key: &[u8],
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::{SigCache, SigCacheSuite};
    use crate::sign::SignatureType;
    use crate::{Engine, OP_CHECKSIG, ScriptBuilder, ScriptFlags, SigHashType};
    use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

    fn entry_count(cache: &SigCache) -> usize {
        cache.valid_sigs.read().expect("lock").len()
    }

    #[test]
    fn hit_and_miss() {
        let cache = SigCache::new(10);
        let sig_hash = [0x11u8; 32];
        let sig = [0x22u8; 71];
        let key = [0x33u8; 33];

        // Nothing cached yet.
        assert!(!cache.exists(&sig_hash, SigCacheSuite::EcdsaSecp256k1, &sig, &key));

        cache.add(&sig_hash, SigCacheSuite::EcdsaSecp256k1, &sig, &key);
        assert!(cache.exists(&sig_hash, SigCacheSuite::EcdsaSecp256k1, &sig, &key));

        // A key hit still misses when the signature bytes, public key
        // bytes, or suite differ.
        let mut other_sig = sig;
        other_sig[0] ^= 0x01;
        assert!(!cache.exists(&sig_hash, SigCacheSuite::EcdsaSecp256k1, &other_sig, &key));
        let mut other_key = key;
        other_key[1] ^= 0x01;
        assert!(!cache.exists(&sig_hash, SigCacheSuite::EcdsaSecp256k1, &sig, &other_key));
        assert!(!cache.exists(&sig_hash, SigCacheSuite::SchnorrSecp256k1, &sig, &key));

        // A different sig hash misses outright.
        let other_hash = [0x44u8; 32];
        assert!(!cache.exists(&other_hash, SigCacheSuite::EcdsaSecp256k1, &sig, &key));
    }

    #[test]
    fn eviction_at_capacity() {
        let cache = SigCache::new(2);
        let sig = [0x55u8; 71];
        let key = [0x66u8; 33];
        cache.add(&[1u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key);
        cache.add(&[2u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key);
        assert_eq!(entry_count(&cache), 2);

        // Adding a third entry evicts exactly one existing entry and
        // always keeps the newest.
        cache.add(&[3u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key);
        assert_eq!(entry_count(&cache), 2);
        assert!(cache.exists(&[3u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key));
        let survivors = [
            cache.exists(&[1u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key),
            cache.exists(&[2u8; 32], SigCacheSuite::EcdsaSecp256k1, &sig, &key),
        ];
        assert_eq!(survivors.iter().filter(|s| **s).count(), 1);
    }

    #[test]
    fn zero_capacity_stays_empty() {
        let cache = SigCache::new(0);
        let sig_hash = [0x77u8; 32];
        cache.add(
            &sig_hash,
            SigCacheSuite::EcdsaSecp256k1,
            &[1, 2, 3],
            &[4, 5, 6],
        );
        assert!(!cache.exists(
            &sig_hash,
            SigCacheSuite::EcdsaSecp256k1,
            &[1, 2, 3],
            &[4, 5, 6]
        ));
        assert_eq!(entry_count(&cache), 0);
    }

    /// A minimal signed pay-to-pubkey spend: the coinbase-style
    /// funding transaction's output script and the spending
    /// transaction whose sole input signs it with SigHashAll (the
    /// same fixture shape the sign-module unit tests use).
    fn signed_p2pk_spend() -> (Vec<u8>, MsgTx) {
        let mut priv_key = [0x11u8; 32];
        priv_key[0] = 0x01;
        let pub_key = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&priv_key)
            .expect("valid key")
            .public_key()
            .serialize_compressed();
        let pk_script = ScriptBuilder::new()
            .add_data(&pub_key)
            .add_op(OP_CHECKSIG)
            .script()
            .expect("builds");

        let coinbase = MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: dcroxide_chainhash::Hash::ZERO,
                    index: !0u32,
                    tree: 0,
                },
                sequence: !0u32,
                value_in: 0,
                block_height: 0,
                block_index: !0u32,
                signature_script: vec![0x00, 0x00],
            }],
            tx_out: vec![TxOut {
                value: 0,
                version: 0,
                pk_script: pk_script.clone(),
            }],
            lock_time: 0,
            expiry: 0,
        };
        let mut spend = MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: coinbase.tx_hash(),
                    index: 0,
                    tree: 0,
                },
                sequence: !0u32,
                value_in: 0,
                block_height: 0,
                block_index: !0u32,
                signature_script: Vec::new(),
            }],
            tx_out: vec![TxOut {
                value: 0,
                version: 0,
                pk_script: Vec::new(),
            }],
            lock_time: 0,
            expiry: 0,
        };

        let sig = crate::sign::raw_tx_in_signature(
            &spend,
            0,
            &pk_script,
            SigHashType(0x01),
            &priv_key,
            SignatureType::EcdsaSecp256k1,
        )
        .expect("signs");
        spend.tx_in[0].signature_script = ScriptBuilder::new()
            .add_data(&sig)
            .script()
            .expect("builds");
        (pk_script, spend)
    }

    fn run(
        pk_script: &[u8],
        tx: &MsgTx,
        cache: Option<&SigCache>,
    ) -> Result<(), crate::ScriptError> {
        let mut vm = Engine::new(pk_script, tx, 0, ScriptFlags::default(), 0)?;
        if let Some(cache) = cache {
            vm.set_sig_cache(cache);
        }
        vm.execute()
    }

    /// A cold run populates the cache and a warm run over the same
    /// transaction succeeds identically — and both match the no-cache
    /// engine.
    #[test]
    fn warm_engine_run_equals_cold_run() {
        let (pk_script, tx) = signed_p2pk_spend();
        let cache = SigCache::new(100);

        let cold = run(&pk_script, &tx, Some(&cache));
        assert!(cold.is_ok(), "cold run failed: {cold:?}");
        assert_eq!(entry_count(&cache), 1, "successful verify not cached");

        let warm = run(&pk_script, &tx, Some(&cache));
        assert!(warm.is_ok(), "warm run failed: {warm:?}");
        assert_eq!(entry_count(&cache), 1);

        let uncached = run(&pk_script, &tx, None);
        assert!(uncached.is_ok(), "no-cache run failed: {uncached:?}");
    }

    /// A failed verification is never cached: corrupting the
    /// signature makes the script fail on both a cold and a warm run
    /// and leaves the cache empty.
    #[test]
    fn negative_verify_never_cached() {
        let (pk_script, mut tx) = signed_p2pk_spend();
        // Flip a byte inside the pushed signature data (offset 0 is
        // the push opcode; the DER body starts after it).
        tx.tx_in[0].signature_script[10] ^= 0x01;
        let cache = SigCache::new(100);

        let first = run(&pk_script, &tx, Some(&cache));
        assert!(first.is_err(), "corrupted signature verified");
        assert_eq!(entry_count(&cache), 0, "failed verify was cached");

        let second = run(&pk_script, &tx, Some(&cache));
        assert_eq!(
            first.as_ref().err().map(|e| e.kind),
            second.as_ref().err().map(|e| e.kind),
            "cache changed the failure"
        );
        assert_eq!(entry_count(&cache), 0);
    }
}
