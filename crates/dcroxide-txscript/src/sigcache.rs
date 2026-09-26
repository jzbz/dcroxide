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
//!   on Go's randomized map iteration start.  A Rust `HashMap` has no
//!   such start: its iteration always begins at bucket zero, so taking
//!   its first key evicts the lowest occupied bucket every time, the
//!   front of the table drains, and each new entry, landing there, is
//!   evicted by the very next add.  The port therefore keeps every
//!   key in a vector beside the map and removes one at an index drawn
//!   from a keyed hash of a counter (a per-cache `RandomState`), so
//!   the victim is uniform and, as dcrd's comment requires, cannot be
//!   steered without the secret key.  Go's own draw is not uniform,
//!   since it picks a starting slot rather than an entry; no caller
//!   can observe which entry went beyond a later cache miss.
//! - dcrd passes `maxEntries` to `make` as a size hint, and Go
//!   allocates nothing up front for a hint whose table would overflow
//!   or exceed its allocation limit.  The port reserves the bound only
//!   when the allocator can provide it (`try_reserve`) and otherwise
//!   grows on demand, so an effectively unlimited
//!   `--sigcachemaxsize` starts the node, as it starts dcrd.
//! - dcrd's `EvictEntries` (the proactive SipHash-keyed eviction of
//!   entries for transactions in newly-matured blocks, run from a
//!   server goroutine) is not ported: it needs a SipHash dependency
//!   and the server notification loop, and only affects which entries
//!   random eviction later removes — never results.
//! - dcrd exports `Exists` and `Add`; the port keeps both
//!   crate-private.  dcrd's `Add` takes a parsed signature and key and
//!   its engine parses before it looks up, so nothing in its cache can
//!   fail to parse.  The port's entries are raw bytes and
//!   `opcode_check_sig` and `opcode_check_sig_alt` look up before they
//!   parse, which is sound only while the engine's own parse and
//!   verify is the sole source of entries.  Other crates create and
//!   share a cache but can neither fill nor query it:
//!
//! ```compile_fail
//! let cache = dcroxide_txscript::SigCache::new(1);
//! let suite = dcroxide_txscript::SigCacheSuite::EcdsaSecp256k1;
//! cache.add(&[0; 32], suite, &[0x30], &[0x02]);
//! ```
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
    /// The entry's position in [`ValidSigs::keys`].
    slot: usize,
}

/// The cached verifications (dcrd `validSigs`) and the state random
/// eviction draws on.
#[cfg(any(test, feature = "std"))]
struct ValidSigs {
    /// The cached successful verifications by signature hash.
    entries: std::collections::HashMap<[u8; 32], SigCacheEntry>,
    /// Every key of `entries`, each at its entry's `slot`, so that a
    /// victim can be drawn by index.
    keys: Vec<[u8; 32]>,
    /// The number of victims drawn so far: the counter each draw
    /// hashes.
    draws: u64,
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
    valid_sigs: std::sync::RwLock<ValidSigs>,
    /// The secret key of the eviction draw, standing in for the
    /// runtime randomness Go seeds each map iteration with.
    draw_key: std::hash::RandomState,
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
        // dcrd's `make(map, maxEntries)` is a hint: Go leaves the map
        // to grow on demand when the hinted table cannot be allocated,
        // where `with_capacity` would abort the process.
        let mut entries = std::collections::HashMap::new();
        let mut keys = Vec::new();
        if entries.try_reserve(max_entries).is_err() || keys.try_reserve_exact(max_entries).is_err()
        {
            entries = std::collections::HashMap::new();
            keys = Vec::new();
        }
        SigCache {
            valid_sigs: std::sync::RwLock::new(ValidSigs {
                entries,
                keys,
                draws: 0,
            }),
            draw_key: std::hash::RandomState::new(),
            max_entries,
        }
    }

    /// Whether a successful verification of `signature` over
    /// `sig_hash` under `pub_key` in the given suite is cached (dcrd
    /// `SigCache.Exists`).
    pub(crate) fn exists(
        &self,
        sig_hash: &[u8; 32],
        suite: SigCacheSuite,
        signature: &[u8],
        pub_key: &[u8],
    ) -> bool {
        let valid_sigs = self.valid_sigs.read().expect("sigcache lock poisoned");
        valid_sigs.entries.get(sig_hash).is_some_and(|entry| {
            entry.suite == suite && entry.signature == signature && entry.pub_key == pub_key
        })
    }

    /// Record a SUCCESSFUL verification of `signature` over
    /// `sig_hash` under `pub_key` (dcrd `SigCache.Add`).  Callers
    /// must never add failed verifications.  When the cache is full
    /// a randomly chosen existing entry is evicted first (see the
    /// module notes on how the random choice is made).
    ///
    /// Crate-private where dcrd exports `Add`: the engine consults the
    /// cache before it parses the key and signature, which is sound only
    /// while every entry comes from its own parse and verify
    /// (`Engine::verify_sig_with_cache`), so no other crate may add one.
    pub(crate) fn add(
        &self,
        sig_hash: &[u8; 32],
        suite: SigCacheSuite,
        signature: &[u8],
        pub_key: &[u8],
    ) {
        let mut guard = self.valid_sigs.write().expect("sigcache lock poisoned");
        let valid_sigs = &mut *guard;

        if self.max_entries == 0 {
            return;
        }

        // If adding this new entry would put the cache over the
        // maximum number of allowed entries, evict one, even when the
        // entry replaces one under the same hash, as dcrd does.
        if valid_sigs.entries.len() >= self.max_entries {
            self.evict_random(valid_sigs);
        }

        // dcrd overwrites an entry whose sig hash collides.
        let entry = SigCacheEntry {
            suite,
            signature: signature.to_vec(),
            pub_key: pub_key.to_vec(),
            slot: valid_sigs.keys.len(),
        };
        match valid_sigs.entries.entry(*sig_hash) {
            std::collections::hash_map::Entry::Occupied(mut occupied) => {
                let slot = occupied.get().slot;
                occupied.insert(SigCacheEntry { slot, ..entry });
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                valid_sigs.keys.push(*sig_hash);
                vacant.insert(entry);
            }
        }
    }

    /// Remove one uniformly drawn entry (dcrd's delete of the first
    /// key a `range` over the map yields).
    fn evict_random(&self, valid_sigs: &mut ValidSigs) {
        use std::hash::BuildHasher;

        let len = valid_sigs.keys.len();
        if len == 0 {
            return;
        }
        let draw = self.draw_key.hash_one(valid_sigs.draws);
        valid_sigs.draws = valid_sigs.draws.wrapping_add(1);

        // The modulo bias is below one part in 2^40 for any cache
        // that fits in memory.
        let slot = (draw % len as u64) as usize;
        let victim = valid_sigs.keys.swap_remove(slot);
        valid_sigs.entries.remove(&victim);

        // The last key moved into the vacated slot.
        if let Some(moved) = valid_sigs.keys.get(slot)
            && let Some(entry) = valid_sigs.entries.get_mut(moved)
        {
            entry.slot = slot;
        }
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
    pub(crate) fn exists(
        &self,
        _sig_hash: &[u8; 32],
        _suite: SigCacheSuite,
        _signature: &[u8],
        _pub_key: &[u8],
    ) -> bool {
        false
    }

    /// Dropped: the inert cache stores nothing.
    pub(crate) fn add(
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
    use crate::{
        Engine, ErrorKind, OP_1, OP_2, OP_3, OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGALT,
        ScriptBuilder, ScriptFlags, SigHashType,
    };
    use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

    /// The number of cached entries, after checking that the key
    /// vector the eviction draws from indexes exactly the map.
    fn entry_count(cache: &SigCache) -> usize {
        let valid_sigs = cache.valid_sigs.read().expect("lock");
        assert_eq!(valid_sigs.keys.len(), valid_sigs.entries.len());
        for (slot, key) in valid_sigs.keys.iter().enumerate() {
            assert_eq!(valid_sigs.entries.get(key).map(|e| e.slot), Some(slot));
        }
        valid_sigs.entries.len()
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

    /// A distinct 32-byte key per index, standing in for a sig hash.
    fn key(i: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&i.to_le_bytes());
        key[8..16].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        key
    }

    /// Once the cache is full, each add evicts one entry drawn
    /// uniformly, as dcrd's delete of the first key of a Go map range
    /// does, so a verification stays cached for about as many adds as
    /// the cache holds entries.  Taking the first key in `HashMap`
    /// iteration order instead evicts from the lowest occupied bucket
    /// every time, and after a few multiples of the capacity each new
    /// entry is evicted by the very next add.
    #[test]
    fn eviction_keeps_recent_entries_after_churn() {
        const MAX: u64 = 1_000;
        let cache = SigCache::new(MAX as usize);
        let sig = [0x55u8; 71];
        let pub_key = [0x66u8; 33];
        for i in 0..4 * MAX {
            cache.add(&key(i), SigCacheSuite::EcdsaSecp256k1, &sig, &pub_key);
        }
        assert_eq!(entry_count(&cache), MAX as usize);

        // Key `4 * MAX - 1 - k` has survived `k` random evictions, each
        // sparing it with probability 1 - 1/MAX: about 95 of the last
        // 100 are expected to remain, and fewer than 80 is more than
        // six standard deviations out.
        let recent = (4 * MAX - MAX / 10..4 * MAX)
            .filter(|i| cache.exists(&key(*i), SigCacheSuite::EcdsaSecp256k1, &sig, &pub_key))
            .count();
        assert!(
            recent >= 80,
            "only {recent} of the last {} entries survived",
            MAX / 10
        );
    }

    /// An effectively unlimited bound is a size hint that cannot be
    /// honored, which Go's `make` ignores; reserving it outright
    /// panicked with a capacity overflow (or aborted on the failed
    /// allocation) before the node could start.
    #[test]
    fn an_unallocatable_bound_starts_empty_and_grows() {
        for max in [usize::MAX, usize::MAX / 2, 1 << 62] {
            let cache = SigCache::new(max);
            let sig = [0x55u8; 71];
            let pub_key = [0x66u8; 33];
            for i in 0..100 {
                cache.add(&key(i), SigCacheSuite::EcdsaSecp256k1, &sig, &pub_key);
            }
            assert_eq!(entry_count(&cache), 100);
            assert!(cache.exists(&key(0), SigCacheSuite::EcdsaSecp256k1, &sig, &pub_key));
        }
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

    /// A transaction whose only input spends an output locked by the
    /// script under test, with the signature script still empty.
    fn unsigned_spend() -> MsgTx {
        MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: dcroxide_chainhash::Hash([0x42; 32]),
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
        }
    }

    /// The spend with its signature script set to the given pushes.
    fn signed_with(pushes: &[&[u8]]) -> MsgTx {
        let mut tx = unsigned_spend();
        let mut builder = ScriptBuilder::new();
        for push in pushes {
            builder = builder.add_data(push);
        }
        tx.tx_in[0].signature_script = builder.script().expect("builds");
        tx
    }

    /// A SigHashAll signature over the spend's only input.
    fn sign_spend(pk_script: &[u8], key: &[u8], sig_type: SignatureType) -> Vec<u8> {
        crate::sign::raw_tx_in_signature(
            &unsigned_spend(),
            0,
            pk_script,
            SigHashType(0x01),
            key,
            sig_type,
        )
        .expect("signs")
    }

    /// Run the spend without a cache, then twice against `cache`, and
    /// require the three verdicts (the error kind on failure) to agree.
    /// Returns the verdict and the entries the cache holds after the
    /// first, cold, cached run.
    fn cold_warm_uncached(
        pk_script: &[u8],
        tx: &MsgTx,
        cache: &SigCache,
    ) -> (Result<(), ErrorKind>, usize) {
        let kind = |r: Result<(), crate::ScriptError>| r.map_err(|e| e.kind);
        let uncached = kind(run(pk_script, tx, None));
        let cold = kind(run(pk_script, tx, Some(cache)));
        let entries = entry_count(cache);
        let warm = kind(run(pk_script, tx, Some(cache)));
        assert_eq!(cold, uncached, "a cold cache changed the verdict");
        assert_eq!(warm, uncached, "a warm cache changed the verdict");
        (uncached, entries)
    }

    /// A 32-byte Ed25519 key and the 64-byte `seed || pubkey` form
    /// the signer takes.
    fn ed25519_key() -> ([u8; 32], Vec<u8>) {
        let seed = [0x07u8; 32];
        let pub_key = dcroxide_dcrec::edwards::SecretKey::from_seed(seed)
            .public_key()
            .serialize();
        (pub_key, [seed.as_slice(), pub_key.as_slice()].concat())
    }

    /// A secp256k1 private key and its compressed public key.
    fn secp_key(tag: u8) -> ([u8; 32], Vec<u8>) {
        let mut priv_key = [tag; 32];
        priv_key[0] = 0x01;
        let pub_key = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&priv_key)
            .expect("valid key")
            .public_key()
            .serialize_compressed()
            .to_vec();
        (priv_key, pub_key)
    }

    /// Flip a bit inside a signature's body, leaving its hash type.
    fn tampered(sig: &[u8]) -> Vec<u8> {
        let mut sig = sig.to_vec();
        let at = sig.len() - 10;
        sig[at] ^= 0x01;
        sig
    }

    /// Run a CHECKSIGALT spend of the given suite through
    /// [`cold_warm_uncached`]: tampered, then valid, then tampered again
    /// against the warm cache.
    fn check_alt_suite(
        name: &str,
        sig_type_op: u8,
        pub_key: &[u8],
        key: &[u8],
        sig_type: SignatureType,
    ) {
        let pk_script = ScriptBuilder::new()
            .add_data(pub_key)
            .add_op(sig_type_op)
            .add_op(OP_CHECKSIGALT)
            .script()
            .expect("builds");
        let sig = sign_spend(&pk_script, key, sig_type);

        let cache = SigCache::new(100);
        let bad = signed_with(&[&tampered(&sig)]);
        let (verdict, entries) = cold_warm_uncached(&pk_script, &bad, &cache);
        assert!(verdict.is_err(), "{name}: tampered spend verified");
        assert_eq!(entries, 0, "{name}: failed verify was cached");

        let (verdict, entries) = cold_warm_uncached(&pk_script, &signed_with(&[&sig]), &cache);
        assert_eq!(verdict, Ok(()), "{name}: valid spend");
        assert_eq!(entries, 1, "{name}: successful verify not cached");

        // The valid entry must not answer for the tampered bytes.
        let (verdict, entries) = cold_warm_uncached(&pk_script, &bad, &cache);
        assert!(verdict.is_err(), "{name}: tampered spend verified warm");
        assert_eq!(entries, 1, "{name}: failed verify was cached");
    }

    /// OP_CHECKSIGALT consults the cache for its Ed25519 and Schnorr
    /// suites, which dcrd verifies without one (`opcode.go:2874-2902`):
    /// a valid spend verifies alike cold, warm and uncached and leaves
    /// one entry, and a tampered one over the same signature hash fails
    /// alike, before and after the valid one is cached, and is never
    /// cached itself.
    #[test]
    fn checksigalt_suites_verify_alike_cold_warm_and_uncached() {
        let (ed_pub, ed_key) = ed25519_key();
        check_alt_suite("ed25519", OP_1, &ed_pub, &ed_key, SignatureType::Ed25519);
        let (schnorr_priv, schnorr_pub) = secp_key(0x21);
        check_alt_suite(
            "schnorr",
            OP_2,
            &schnorr_pub,
            &schnorr_priv,
            SignatureType::SchnorrSecp256k1,
        );
    }

    /// The cache keys Ed25519 entries by the raw public key bytes,
    /// while verification hashes the canonical encoding.  The identity
    /// point has a second, non-canonical encoding (y = p + 1), and its
    /// discrete log is zero, so `R = B, S = 1` is a valid signature
    /// under either encoding.  Supplying the key from the signature
    /// script keeps the signature hash the same for both, so the two
    /// encodings collide on one cache key: each must still verify
    /// exactly as it does uncached, whatever the other left behind.
    #[test]
    fn noncanonical_ed25519_key_verifies_alike_through_a_shared_entry() {
        let mut noncanonical = [0xffu8; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        let mut canonical = [0u8; 32];
        canonical[0] = 0x01;
        let parsed = dcroxide_dcrec::edwards::parse_pub_key(&noncanonical).expect("parses");
        assert_eq!(parsed.serialize(), canonical);

        // R is the base point's encoding and S is one; the trailing
        // byte is SigHashAll.
        let mut sig = [0x66u8; 65];
        sig[0] = 0x58;
        sig[32..64].fill(0);
        sig[32] = 0x01;
        sig[64] = 0x01;

        let pk_script = ScriptBuilder::new()
            .add_op(OP_1)
            .add_op(OP_CHECKSIGALT)
            .script()
            .expect("builds");
        let cache = SigCache::new(100);
        for (name, key) in [("non-canonical", noncanonical), ("canonical", canonical)] {
            let tx = signed_with(&[&sig, &key]);
            let (verdict, entries) = cold_warm_uncached(&pk_script, &tx, &cache);
            assert_eq!(verdict, Ok(()), "{name} encoding");
            assert_eq!(entries, 1, "{name}: both encodings share one sig hash");
        }

        // A signature that fails under one encoding fails under the
        // other, with the valid entry for the first still cached.
        let mut bad = sig;
        bad[32] = 0x02;
        let tx = signed_with(&[&bad, &noncanonical]);
        let (verdict, entries) = cold_warm_uncached(&pk_script, &tx, &cache);
        assert!(verdict.is_err(), "S = 2 does not verify");
        assert_eq!(entries, 1);
    }

    /// OP_CHECKMULTISIG verifies every signature over one signature
    /// hash, so its entries overwrite each other under a single cache
    /// key.  A 2-of-3 spend verifies alike cold, warm and uncached,
    /// and one whose second signature is tampered fails alike, whether
    /// or not the valid spend's entry is cached.
    #[test]
    fn checkmultisig_verifies_alike_cold_warm_and_uncached() {
        let keys = [secp_key(0x31), secp_key(0x32), secp_key(0x33)];
        let pk_script = ScriptBuilder::new()
            .add_op(OP_2)
            .add_data(&keys[0].1)
            .add_data(&keys[1].1)
            .add_data(&keys[2].1)
            .add_op(OP_3)
            .add_op(OP_CHECKMULTISIG)
            .script()
            .expect("builds");
        let sig_1 = sign_spend(&pk_script, &keys[0].0, SignatureType::EcdsaSecp256k1);
        let sig_3 = sign_spend(&pk_script, &keys[2].0, SignatureType::EcdsaSecp256k1);

        let cache = SigCache::new(100);
        let bad = signed_with(&[&sig_1, &tampered(&sig_3)]);
        let (verdict, entries) = cold_warm_uncached(&pk_script, &bad, &cache);
        assert!(verdict.is_err(), "a tampered signature verified");
        assert_eq!(entries, 0, "failed verify was cached");

        let (verdict, entries) =
            cold_warm_uncached(&pk_script, &signed_with(&[&sig_1, &sig_3]), &cache);
        assert_eq!(verdict, Ok(()), "2-of-3 spend");
        assert_eq!(entries, 1, "both signatures share one sig hash");

        let (verdict, entries) = cold_warm_uncached(&pk_script, &bad, &cache);
        assert!(verdict.is_err(), "a tampered signature verified warm");
        assert_eq!(entries, 1);
    }
}
