// SPDX-License-Identifier: ISC
//! Mixpool regressions from the 2026-09-23 review: orphan
//! reconsideration (key exchanges stay orphaned as in dcrd, and the
//! one-message-per-type rule holds for un-orphaned messages), Go's
//! wrapping arithmetic on negative mix amounts, Go's time arithmetic for
//! key exchange epochs, orphan age on the monotonic clock, and the
//! pre-hashed intake path keeping dcrd's check order.  From the
//! 2026-09-25 review: the recently-removed cache's presence probe and
//! wall-clock TTL, and signatures verified only where dcrd verifies.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    HashedMessage, MixBlockChain, Pool, PoolError, PoolMessage, RuleKind, SCRIPT_CLASS_P2PKH_V0,
    no_mempool_spent, sign_message, sort_prs_for_session,
};
use dcroxide_wire::{
    MixPairReqUTXO, MsgMixCiphertexts, MsgMixKeyExchange, MsgMixPairReq, MsgMixSlotReserve,
    OutPoint,
};

/// The tip the pool validates pair request expiries against.
const TIP_HEIGHT: i64 = 100;

/// The wall clock the pool starts at, in seconds.
const NOW_SECS: i64 = 1_700_000_000;

const NANOS: i64 = 1_000_000_000;

struct StubChain {
    params: &'static Params,
}

impl MixBlockChain for StubChain {
    fn chain_params(&self) -> &Params {
        self.params
    }
    fn current_tip(&self) -> (Hash, i64) {
        (Hash([0u8; 32]), TIP_HEIGHT)
    }
}

/// The pool's two clocks, settable from the test.
struct Clocks {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
}

impl Clocks {
    fn advance_wall(&self, nanos: i64) {
        self.wall.fetch_add(nanos, Ordering::SeqCst);
    }
    fn advance_mono(&self, nanos: i64) {
        self.mono.fetch_add(nanos, Ordering::SeqCst);
    }
}

/// A pool over simnet with no UTXO fetcher, a wall clock at
/// [`NOW_SECS`] and a monotonic clock at zero, both under the test's
/// control.
fn new_pool() -> (Pool<StubChain>, Clocks) {
    let params: &'static Params = Box::leak(Box::new(simnet_params()));
    let wall = Arc::new(AtomicI64::new(NOW_SECS * NANOS));
    let mono = Arc::new(AtomicI64::new(0));
    let (w, m) = (Arc::clone(&wall), Arc::clone(&mono));
    let pool = Pool::new_with_clocks(
        StubChain { params },
        None,
        Arc::new(move || w.load(Ordering::SeqCst)),
        Arc::new(move || m.load(Ordering::SeqCst)),
    );
    (pool, Clocks { wall, mono })
}

fn identity(seed: u8) -> (PrivateKey, [u8; 33]) {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x11;
    bytes[31] = seed;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let pub_key = priv_key.public_key().serialize_compressed();
    (priv_key, pub_key)
}

/// A pair request that passes every acceptance rule once signed.
fn unsigned_pair_request(id: [u8; 33], outpoint_seed: u8) -> MsgMixPairReq {
    let mut hash = [0u8; 32];
    hash[0] = outpoint_seed;
    MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry: 110,
        mix_amount: 10_000_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point: OutPoint {
                hash: Hash(hash),
                index: u32::from(outpoint_seed),
                tree: 0,
            },
            script: Vec::new(),
            pub_key: id.to_vec(),
            signature: vec![0u8; 64],
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    }
}

fn pair_request(priv_key: &PrivateKey, id: [u8; 33], outpoint_seed: u8) -> MsgMixPairReq {
    let mut pr = unsigned_pair_request(id, outpoint_seed);
    sign_message(&mut pr, priv_key).expect("sign pair request");
    pr
}

/// An unsigned pair request used only for its hash, which a key
/// exchange may reference without the pool knowing it.
fn unknown_pair_request(n: u32) -> MsgMixPairReq {
    let mut pr = unsigned_pair_request([0u8; 33], 0);
    pr.lock_time = n;
    pr
}

/// A signed key exchange for the session the two pair requests form in
/// `epoch`, claiming the unmixed position of `pos_pr`.
fn key_exchange(
    priv_key: &PrivateKey,
    id: [u8; 33],
    prs: [&MsgMixPairReq; 2],
    pos_pr: &MsgMixPairReq,
    epoch: u64,
) -> MsgMixKeyExchange {
    let mut prs: Vec<MsgMixPairReq> = prs.into_iter().cloned().collect();
    let sid = sort_prs_for_session(&mut prs, epoch);
    let seen_prs: Vec<Hash> = prs
        .iter()
        .map(|pr| pr.mix_hash().expect("pair request hash"))
        .collect();
    let pos_hash = pos_pr.mix_hash().expect("pair request hash");
    let pos = seen_prs
        .iter()
        .position(|hash| *hash == pos_hash)
        .expect("position") as u32;
    let mut ke = MsgMixKeyExchange {
        signature: [0u8; 64],
        identity: id,
        session_id: sid,
        epoch,
        run: 0,
        pos,
        ecdh: [0u8; 33],
        pqpk: [0u8; 1218],
        commitment: [0u8; 32],
        seen_prs,
    };
    sign_message(&mut ke, priv_key).expect("sign key exchange");
    ke
}

/// A signed slot reservation in `sid`, distinct per `n`.
fn slot_reserve(priv_key: &PrivateKey, id: [u8; 33], sid: [u8; 32], n: u8) -> MsgMixSlotReserve {
    let mut sr = MsgMixSlotReserve {
        signature: [0u8; 64],
        identity: id,
        session_id: sid,
        run: 0,
        dc_mix: vec![vec![vec![n]]],
        seen_ciphertexts: Vec::new(),
    };
    sign_message(&mut sr, priv_key).expect("sign slot reservation");
    sr
}

/// A signed ciphertexts message in `sid`.
fn ciphertexts(priv_key: &PrivateKey, id: [u8; 33], sid: [u8; 32]) -> MsgMixCiphertexts {
    let mut ct = MsgMixCiphertexts {
        signature: [0u8; 64],
        identity: id,
        session_id: sid,
        run: 0,
        ciphertexts: Vec::new(),
        seen_key_exchanges: Vec::new(),
    };
    sign_message(&mut ct, priv_key).expect("sign ciphertexts");
    ct
}

fn accept(pool: &mut Pool<StubChain>, msg: PoolMessage) -> Result<Vec<PoolMessage>, PoolError> {
    pool.accept_message(&msg, 1, &no_mempool_spent)
}

/// The error a message was refused with; neither message type is Debug.
fn rejected<T>(result: Result<T, PoolError>, what: &str) -> PoolError {
    match result {
        Ok(_) => panic!("{what}: accepted"),
        Err(err) => err,
    }
}

fn orphan_count(pool: &Pool<StubChain>) -> usize {
    pool.state_sizes().2
}

fn hashes(msgs: &[PoolMessage]) -> Vec<Hash> {
    msgs.iter().map(|m| m.mix_hash().expect("hash")).collect()
}

/// X1-c#2: dcrd's second reconsideration loop has no key exchange case,
/// so an orphan key exchange whose own pair request is still missing
/// stays an orphan when another key exchange of the same session is
/// accepted.  The port had pooled and returned it through
/// `accept_entry`, skipping every `accept_ke` check.
#[test]
fn orphan_key_exchange_stays_orphaned_when_its_session_is_accepted() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(1);
    let pr = pair_request(&priv_key, id, 1);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");

    let unknown = unknown_pair_request(7);
    let epoch = NOW_SECS as u64;
    // Same pair requests and epoch, so the same session ID; B claims the
    // unknown request's position and is orphaned for it.
    let ke_b = key_exchange(&priv_key, id, [&pr, &unknown], &unknown, epoch);
    let err = rejected(
        accept(&mut pool, PoolMessage::KE(Box::new(ke_b.clone()))),
        "key exchange B is orphaned",
    );
    assert_eq!(
        err,
        PoolError::MissingOwnPR(unknown.mix_hash().expect("hash"))
    );
    assert_eq!(orphan_count(&pool), 1);

    let ke_a = key_exchange(&priv_key, id, [&pr, &unknown], &pr, epoch);
    assert_eq!(ke_a.session_id, ke_b.session_id);
    let accepted =
        accept(&mut pool, PoolMessage::KE(Box::new(ke_a.clone()))).expect("key exchange A");

    assert_eq!(hashes(&accepted), vec![ke_a.mix_hash().expect("hash")]);
    assert_eq!(pool.identity_key_exchange_count(&id), 1);
    assert_eq!(orphan_count(&pool), 1, "key exchange B is still an orphan");
    assert!(!pool.have_message(&ke_b.mix_hash().expect("hash")));
}

/// X1-c#1: messages a key exchange un-orphans are held to the direct
/// path's one-message-per-type rule, so an identity cannot park an
/// orphan pool's worth of one message type before its key exchange and
/// have them all pooled and relayed.  The earliest-received message of
/// each type is the one kept.
#[test]
fn un_orphaned_messages_keep_one_per_type_and_session() {
    let (mut pool, clocks) = new_pool();
    let (priv_key, id) = identity(2);
    let pr = pair_request(&priv_key, id, 2);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");

    let unknown = unknown_pair_request(9);
    let ke = key_exchange(&priv_key, id, [&pr, &unknown], &pr, NOW_SECS as u64);
    let sid = ke.session_id;

    // Received before the key exchange: five slot reservations, sent in
    // descending hash order so that the earliest received is the one a
    // hash-ordered pick would keep last, and one ciphertexts.
    let mut srs: Vec<MsgMixSlotReserve> = (0..5u8)
        .map(|n| slot_reserve(&priv_key, id, sid, n))
        .collect();
    srs.sort_by_key(|sr| std::cmp::Reverse(sr.mix_hash().expect("hash").0));
    for sr in &srs {
        clocks.advance_mono(1);
        let accepted = accept(&mut pool, PoolMessage::SR(sr.clone())).expect("orphaned");
        assert!(accepted.is_empty());
    }
    let first = srs.remove(0);
    let ct = ciphertexts(&priv_key, id, sid);
    accept(&mut pool, PoolMessage::CT(ct.clone())).expect("orphaned");
    assert_eq!(orphan_count(&pool), 6);

    let accepted = accept(&mut pool, PoolMessage::KE(Box::new(ke.clone()))).expect("key exchange");
    let mut got = hashes(&accepted);
    got.sort_by_key(|h| h.0);
    let mut want = vec![
        ke.mix_hash().expect("hash"),
        first.mix_hash().expect("hash"),
        ct.mix_hash().expect("hash"),
    ];
    want.sort_by_key(|h| h.0);
    assert_eq!(got, want);

    // One key exchange, one slot reservation, one ciphertexts; the
    // conflicting slot reservations are dropped, not left orphaned.
    let (_, pool_len, orphans, _, _, _) = pool.state_sizes();
    assert_eq!(pool_len, 3);
    assert_eq!(orphans, 0);
    for sr in &srs {
        assert!(!pool.have_message(&sr.mix_hash().expect("hash")));
    }

    // The direct path refuses a further slot reservation as before.
    let late = slot_reserve(&priv_key, id, sid, 42);
    let err = rejected(accept(&mut pool, PoolMessage::SR(late)), "conflict");
    assert!(matches!(err, PoolError::Rule(RuleKind::Other(ref m)) if m.contains("conflicts")));
}

/// X1-c#7: a hugely negative mix amount is not dust once Go's product
/// wraps, and the checks after it wrap too.  Plain arithmetic had
/// panicked in debug builds on a request signed by a throwaway key.
#[test]
fn negative_mix_amounts_wrap_like_go() {
    let (mut pool, _clocks) = new_pool();

    let (priv_key, id) = identity(3);
    let mut pr = unsigned_pair_request(id, 3);
    pr.message_count = 16;
    pr.mix_amount = -600_000_000_000_000_000;
    sign_message(&mut pr, &priv_key).expect("sign");
    assert_eq!(
        rejected(accept(&mut pool, PoolMessage::PR(pr)), "rejected"),
        PoolError::Rule(RuleKind::InvalidTotalMixAmount)
    );

    let (priv_key, id) = identity(4);
    let mut pr = unsigned_pair_request(id, 4);
    pr.mix_amount = -9_300_000_000_000_000;
    pr.input_value = i64::MAX;
    sign_message(&mut pr, &priv_key).expect("sign");
    assert_eq!(
        rejected(accept(&mut pool, PoolMessage::PR(pr)), "rejected"),
        PoolError::Rule(RuleKind::LowInput)
    );
}

/// X1-c#6: the early key exchange gate compares Go times, not a
/// wrapped epoch-times-1e9 product.  An epoch past the year 2262 is
/// too early, as in dcrd, and an epoch at or above 2**63 is an int64 in
/// the far past, which dcrd accepts.
#[test]
fn early_key_exchange_gate_compares_seconds_like_go() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(5);
    let pr = pair_request(&priv_key, id, 5);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");
    let unknown = unknown_pair_request(11);

    let far_future = key_exchange(&priv_key, id, [&pr, &unknown], &pr, 10_000_000_000);
    let err = rejected(
        accept(&mut pool, PoolMessage::KE(Box::new(far_future))),
        "too early",
    );
    assert_eq!(
        err,
        PoolError::Rule(RuleKind::Other(
            "KE received too early for stated epoch".into()
        ))
    );

    let far_past = key_exchange(
        &priv_key,
        id,
        [&pr, &unknown],
        &pr,
        (1u64 << 63) + 4_000_000_000,
    );
    let accepted = accept(&mut pool, PoolMessage::KE(Box::new(far_past))).expect("accepted");
    assert_eq!(accepted.len(), 1);
}

/// X1-c#6: the orphan sweep takes `time.Since` of the key exchange
/// epoch the way Go does, saturating, where the port's plain
/// subtraction overflowed (a debug-build panic) for an epoch whose
/// nanosecond product wrapped far negative.
#[test]
fn far_past_orphan_key_exchange_expires_without_overflow() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(6);
    // The identity's own pair request is never sent, so the key
    // exchange is orphaned.
    let pr = pair_request(&priv_key, id, 6);
    let unknown = unknown_pair_request(13);
    let ke = key_exchange(
        &priv_key,
        id,
        [&pr, &unknown],
        &pr,
        (1u64 << 63) + 10_000_000_000,
    );
    let err = rejected(accept(&mut pool, PoolMessage::KE(Box::new(ke))), "orphaned");
    assert!(matches!(err, PoolError::MissingOwnPR(_)));
    assert_eq!(orphan_count(&pool), 1);

    pool.expire_messages(0);
    assert_eq!(orphan_count(&pool), 0, "an epoch in the far past expires");
}

/// PW17#2: dcrd measures orphan age with `time.Since` over two
/// `time.Now()` readings, which Go takes from the monotonic clock, so a
/// wall-clock step moves it in neither direction.
#[test]
fn orphan_age_follows_the_monotonic_clock() {
    let twenty_minutes = 20 * 60 * NANOS;
    let (priv_key, id) = identity(7);
    let sr = slot_reserve(&priv_key, id, [7u8; 32], 1);

    // The wall clock steps back an hour while 21 minutes pass.
    let (mut pool, clocks) = new_pool();
    accept(&mut pool, PoolMessage::SR(sr.clone())).expect("orphaned");
    assert_eq!(orphan_count(&pool), 1);
    clocks.advance_wall(-60 * 60 * NANOS);
    clocks.advance_mono(twenty_minutes + 60 * NANOS);
    pool.expire_messages(0);
    assert_eq!(
        orphan_count(&pool),
        0,
        "21 minutes old, whatever the wall says"
    );

    // The wall clock jumps forward half an hour while a second passes.
    let (mut pool, clocks) = new_pool();
    accept(&mut pool, PoolMessage::SR(sr)).expect("orphaned");
    clocks.advance_wall(30 * 60 * NANOS);
    clocks.advance_mono(NANOS);
    pool.expire_messages(0);
    assert_eq!(
        orphan_count(&pool),
        1,
        "one second old, whatever the wall says"
    );
}

/// X1-c#5: the daemon's intake path hashes a message once, before the
/// sync-manager and mixpool locks, and the signature counts only where
/// dcrd verifies it: a rerun is refused as a rerun (not bannable)
/// whatever its signature, an already-accepted message is a silent
/// duplicate, and only then does a bad signature count.
#[test]
fn hashed_acceptance_keeps_dcrd_check_order() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(8);
    let pr = pair_request(&priv_key, id, 8);
    let pr_hash = pr.mix_hash().expect("hash");

    let msg = HashedMessage::new(PoolMessage::PR(pr.clone()));
    assert_eq!(msg.hash(), Ok(pr_hash));
    let accepted = pool
        .accept_hashed(&msg, 1, &no_mempool_spent)
        .expect("accepted");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].hash(), Ok(pr_hash));
    assert!(
        pool.accept_hashed(&msg, 1, &no_mempool_spent)
            .expect("duplicate")
            .is_empty()
    );

    let mut forged = pr;
    forged.lock_time = 1;
    let forged = HashedMessage::new(PoolMessage::PR(forged));
    assert_eq!(
        pool.accept_hashed(&forged, 1, &no_mempool_spent).err(),
        Some(PoolError::Rule(RuleKind::InvalidSignature))
    );

    let unknown = unknown_pair_request(15);
    let mut rerun = key_exchange(
        &priv_key,
        id,
        [&unknown_pair_request(14), &unknown],
        &unknown,
        NOW_SECS as u64,
    );
    rerun.run = 1;
    let rerun = HashedMessage::new(PoolMessage::KE(Box::new(rerun)));
    let err = rejected(pool.accept_hashed(&rerun, 1, &no_mempool_spent), "rerun");
    assert_eq!(
        err,
        PoolError::Rule(RuleKind::Other("nonzero reruns are unsupported".into()))
    );
    assert!(!err.is_bannable(dcroxide_wire::ServiceFlag::NODE_NETWORK));
}

/// X1-c#5: a message whose hash the node's input loop computed as it
/// read it (dcrd's `readMessage` caching `WriteHash`) is not hashed a
/// second time but still has its signature verified, so it earns the
/// same outcome as one hashed on intake.
#[test]
fn precomputed_hash_still_verifies_the_signature() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(9);
    let pr = pair_request(&priv_key, id, 9);
    let pr_hash = pr.mix_hash().expect("hash");

    let msg = HashedMessage::with_hash(PoolMessage::PR(pr.clone()), pr_hash);
    assert_eq!(msg.hash(), Ok(pr_hash));
    let accepted = pool
        .accept_hashed(&msg, 1, &no_mempool_spent)
        .expect("accepted");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].hash(), Ok(pr_hash));

    let mut forged = pr;
    forged.lock_time = 1;
    let forged_hash = forged.mix_hash().expect("hash");
    let forged = HashedMessage::with_hash(PoolMessage::PR(forged), forged_hash);
    assert_eq!(
        pool.accept_hashed(&forged, 1, &no_mempool_spent).err(),
        Some(PoolError::Rule(RuleKind::InvalidSignature))
    );
}

/// The pool keys a message by the hash it is handed, so debug builds
/// refuse one that does not belong to the message.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "precomputed mix hash does not match the message")]
fn precomputed_hash_must_match_the_message() {
    let (priv_key, id) = identity(10);
    let pr = pair_request(&priv_key, id, 10);
    let _ = HashedMessage::with_hash(PoolMessage::PR(pr), Hash([7u8; 32]));
}

/// X1-p#1: netsync's `needMixMsg` asks only whether dcrd's
/// `RecentMessage` finds a message.  The presence probe answers exactly
/// what `recent_message` finds -- a pooled pair request, a pooled entry,
/// a removed message still in the recently-removed cache -- without
/// copying the message out.
#[test]
fn recent_presence_probe_finds_what_recent_message_finds() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(11);
    let pr = pair_request(&priv_key, id, 11);
    let unknown = unknown_pair_request(16);
    let ke = key_exchange(&priv_key, id, [&pr, &unknown], &pr, NOW_SECS as u64);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");
    accept(&mut pool, PoolMessage::KE(Box::new(ke.clone()))).expect("key exchange is accepted");
    let pr_hash = pr.mix_hash().expect("hash");
    let ke_hash = ke.mix_hash().expect("hash");
    let never = unknown.mix_hash().expect("hash");

    for hash in [pr_hash, ke_hash] {
        assert!(pool.have_message(&hash));
        assert!(pool.have_recent_message(&hash), "pooled");
        assert_eq!(
            pool.recent_message(&hash)
                .map(|m| m.mix_hash().expect("hash")),
            Some(hash)
        );
    }
    assert!(!pool.have_recent_message(&never));
    assert!(pool.recent_message(&never).is_none());

    // The pair request expires, taking the key exchange with it: both
    // leave the pool for the recently-removed cache.
    pool.expire_messages(110);
    for hash in [pr_hash, ke_hash] {
        assert!(!pool.have_message(&hash), "removed from the pool");
        assert!(pool.have_recent_message(&hash), "recently removed");
        assert_eq!(
            pool.recent_message(&hash)
                .map(|m| m.mix_hash().expect("hash")),
            Some(hash)
        );
    }
    assert!(!pool.have_recent_message(&never));
}

/// C2-p#1: dcrd's `container/lru` stores an item's expiry as
/// `now.Add(ttl).UnixNano()` and compares `now.UnixNano()`, so the
/// recently-removed cache's one-minute TTL runs on the wall clock, not
/// the monotonic one the orphan age uses.
#[test]
fn recent_cache_expires_on_the_wall_clock() {
    let (mut pool, clocks) = new_pool();
    let (priv_key, id) = identity(12);
    let pr = pair_request(&priv_key, id, 12);
    let pr_hash = pr.mix_hash().expect("hash");
    accept(&mut pool, PoolMessage::PR(pr)).expect("pair request is accepted");
    pool.expire_messages(110);
    assert!(pool.have_recent_message(&pr_hash));

    // Two monotonic minutes with the wall clock stood still: still
    // recent.
    clocks.advance_mono(2 * 60 * NANOS);
    assert!(
        pool.have_recent_message(&pr_hash),
        "the wall says no time passed"
    );

    // The wall clock steps past the TTL: gone, however little time
    // really passed.
    clocks.advance_wall(61 * NANOS);
    assert!(
        !pool.have_recent_message(&pr_hash),
        "expired on the wall clock"
    );
    assert!(pool.recent_message(&pr_hash).is_none());
}

/// X1-p#2: dcrd verifies a mix message's signature only after the
/// rerun check and the already-accepted check (`AcceptMessage`,
/// `mixpool.go:1172-1198`; netsync's rejected filter runs before that),
/// so a replay of a pooled message, or a rerun, costs no Schnorr verify.
/// Hashing a message no longer verifies it; the pool says when dcrd
/// would, and verifies under its guard only if the caller did not.
#[test]
fn replays_and_reruns_are_never_verified() {
    let (mut pool, _clocks) = new_pool();
    let (priv_key, id) = identity(13);
    let pr = pair_request(&priv_key, id, 13);

    let msg = HashedMessage::new(PoolMessage::PR(pr.clone()));
    assert!(!msg.signature_checked(), "hashing does not verify");
    assert!(pool.needs_signature_check(&msg));
    assert!(msg.verify());
    assert_eq!(
        pool.accept_hashed(&msg, 1, &no_mempool_spent)
            .expect("accepted")
            .len(),
        1
    );

    // A replay of the pooled message is a silent duplicate, unverified.
    let replay = HashedMessage::new(PoolMessage::PR(pr.clone()));
    assert!(!pool.needs_signature_check(&replay));
    assert!(
        pool.accept_hashed(&replay, 1, &no_mempool_spent)
            .expect("duplicate")
            .is_empty()
    );
    assert!(!replay.signature_checked(), "a replay is never verified");

    // A rerun is refused before any verification.
    let unknown = unknown_pair_request(17);
    let mut rerun = key_exchange(&priv_key, id, [&pr, &unknown], &pr, NOW_SECS as u64);
    rerun.run = 1;
    let rerun = HashedMessage::new(PoolMessage::KE(Box::new(rerun)));
    assert!(!pool.needs_signature_check(&rerun));
    rejected(pool.accept_hashed(&rerun, 1, &no_mempool_spent), "rerun");
    assert!(!rerun.signature_checked(), "a rerun is never verified");

    // A new message the caller did not verify is verified under the
    // guard, where dcrd would verify it.
    let mut forged = pr;
    forged.lock_time = 1;
    let forged = HashedMessage::new(PoolMessage::PR(forged));
    assert!(pool.needs_signature_check(&forged));
    assert_eq!(
        pool.accept_hashed(&forged, 1, &no_mempool_spent).err(),
        Some(PoolError::Rule(RuleKind::InvalidSignature))
    );
    assert!(forged.signature_checked());
}
