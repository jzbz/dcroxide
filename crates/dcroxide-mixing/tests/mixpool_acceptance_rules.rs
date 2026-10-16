// SPDX-License-Identifier: ISC
//! The mixpool acceptance rules dcrd changed between `6f6cf21b` and
//! `382ff4dd`:
//!
//! - `6b65e0d1`: a key exchange's seen pair requests are bounded by the
//!   wire's 512, no longer by `MAX_PEERS`.
//! - `ffb42adf`: one key exchange per identity and session, and a plain
//!   error for a session that records a message the pool dropped.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    MAX_PEERS, MixBlockChain, Pool, PoolError, PoolMessage, RuleKind, SCRIPT_CLASS_P2PKH_V0,
    no_mempool_spent, sign_message, sort_prs_for_session,
};
use dcroxide_wire::{
    MAX_MIX_PEERS, MIX_VERSION, Message, MixPairReqUTXO, MsgMixCiphertexts, MsgMixKeyExchange,
    MsgMixPairReq, OutPoint, ServiceFlag, WireError, decode_message_payload,
};

/// The tip the pool validates pair request expiries against.
const TIP_HEIGHT: i64 = 100;

/// The wall clock the pool starts at, in seconds: a whole minute, so a
/// key exchange stating it as its epoch is inside dcrd's window.
const NOW_SECS: i64 = 1_699_999_980;

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

/// A pool over simnet with no UTXO fetcher, its wall clock at
/// [`NOW_SECS`] and its monotonic clock at zero, both under the test's
/// control.
fn new_pool() -> (Pool<StubChain>, Arc<AtomicI64>, Arc<AtomicI64>) {
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
    (pool, wall, mono)
}

fn identity(seed: u8) -> (PrivateKey, [u8; 33]) {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x21;
    bytes[31] = seed;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let pub_key = priv_key.public_key().serialize_compressed();
    (priv_key, pub_key)
}

/// A signed pair request that passes every acceptance rule of a pool
/// without a UTXO fetcher.
fn pair_request(priv_key: &PrivateKey, id: [u8; 33], outpoint_seed: u8) -> MsgMixPairReq {
    let mut hash = [0u8; 32];
    hash[0] = outpoint_seed;
    let mut pr = MsgMixPairReq {
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
    };
    sign_message(&mut pr, priv_key).expect("sign pair request");
    pr
}

/// An unsigned pair request used only for its hash, which a key
/// exchange may reference without the pool knowing it.
fn unknown_pair_request(n: u32) -> MsgMixPairReq {
    MsgMixPairReq {
        signature: [0u8; 64],
        identity: [0u8; 33],
        expiry: 0,
        mix_amount: 0,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: n,
        message_count: 1,
        input_value: 0,
        utxos: Vec::new(),
        change: None,
        flags: 0,
        pairing_flags: 0,
    }
}

/// `own` and `others` unknown pair requests numbered from `first`.
fn with_unknown(own: &MsgMixPairReq, first: u32, others: u32) -> Vec<MsgMixPairReq> {
    let mut prs = vec![own.clone()];
    prs.extend((first..first + others).map(unknown_pair_request));
    prs
}

/// An unsigned key exchange for the session `prs` form in `epoch`,
/// claiming the unmixed position of `own`.
fn unsigned_key_exchange(
    id: [u8; 33],
    prs: &[MsgMixPairReq],
    own: &MsgMixPairReq,
    epoch: u64,
) -> MsgMixKeyExchange {
    let mut prs = prs.to_vec();
    let sid = sort_prs_for_session(&mut prs, epoch);
    let seen_prs: Vec<Hash> = prs
        .iter()
        .map(|pr| pr.mix_hash().expect("pair request hash"))
        .collect();
    let own_hash = own.mix_hash().expect("pair request hash");
    let pos = seen_prs
        .iter()
        .position(|hash| *hash == own_hash)
        .expect("own position") as u32;
    MsgMixKeyExchange {
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
    }
}

fn key_exchange(
    priv_key: &PrivateKey,
    id: [u8; 33],
    prs: &[MsgMixPairReq],
    own: &MsgMixPairReq,
    epoch: u64,
) -> MsgMixKeyExchange {
    let mut ke = unsigned_key_exchange(id, prs, own, epoch);
    sign_message(&mut ke, priv_key).expect("sign key exchange");
    ke
}

/// [`key_exchange`] with a commitment of `commitment` repeated: a
/// distinct key exchange for the same session.
fn key_exchange_committing(
    priv_key: &PrivateKey,
    id: [u8; 33],
    prs: &[MsgMixPairReq],
    own: &MsgMixPairReq,
    epoch: u64,
    commitment: u8,
) -> MsgMixKeyExchange {
    let mut ke = unsigned_key_exchange(id, prs, own, epoch);
    ke.commitment = [commitment; 32];
    sign_message(&mut ke, priv_key).expect("sign key exchange");
    ke
}

/// A signed ciphertexts message in `sid`, with no ciphertexts.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn accept(pool: &mut Pool<StubChain>, msg: PoolMessage) -> Result<Vec<PoolMessage>, PoolError> {
    pool.accept_message(&msg, 1, &no_mempool_spent)
}

fn accept_ke(
    pool: &mut Pool<StubChain>,
    ke: &MsgMixKeyExchange,
) -> Result<Vec<PoolMessage>, PoolError> {
    accept(pool, PoolMessage::KE(Box::new(ke.clone())))
}

fn hash_of(ke: &MsgMixKeyExchange) -> Hash {
    ke.mix_hash().expect("key exchange hash")
}

fn orphan_count(pool: &Pool<StubChain>) -> usize {
    pool.state_sizes().2
}

/// dcrd's conflict text for `ke` refused against `prev`
/// (`mixing/mixpool/mixpool.go:1717-1719`).
fn conflict(ke: &MsgMixKeyExchange, prev: Hash) -> PoolError {
    PoolError::Rule(RuleKind::Other(format!(
        "message {} by identity {} in session {} conflicts with already accepted message {}",
        hash_of(ke),
        hex(&ke.identity),
        hex(&ke.session_id),
        prev
    )))
}

/// dcrd's plain error for a session recording `prev`, which the pool
/// no longer holds (`mixing/mixpool/mixpool.go:1709-1710`).
fn unknown_message(ke: &MsgMixKeyExchange, prev: Hash) -> PoolError {
    PoolError::Other(format!(
        "unknown message {prev} recorded by session {}",
        hex(&ke.session_id)
    ))
}

/// `6b65e0d1`: a key exchange naming more pair requests than
/// `MAX_PEERS` is pooled, up to the wire's 512.  The port had refused it
/// with "65 referenced PRs exceeds max peers 64", as dcrd did before.
#[test]
fn key_exchanges_may_name_more_pair_requests_than_max_peers() {
    let (mut pool, _, _) = new_pool();
    let (priv_key, id) = identity(1);
    let pr = pair_request(&priv_key, id, 1);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");

    let epoch = NOW_SECS as u64;
    let just_past = with_unknown(&pr, 0, MAX_PEERS);
    assert_eq!(just_past.len(), 65);
    let ke = key_exchange(&priv_key, id, &just_past, &pr, epoch);
    let accepted = accept_ke(&mut pool, &ke).expect("65 seen pair requests");
    assert_eq!(accepted.len(), 1);
    assert!(pool.have_message(&hash_of(&ke)));

    let wire_cap = with_unknown(&pr, 1000, MAX_MIX_PEERS as u32 - 1);
    assert_eq!(wire_cap.len(), 512);
    let ke = key_exchange(&priv_key, id, &wire_cap, &pr, epoch);
    let accepted = accept_ke(&mut pool, &ke).expect("512 seen pair requests");
    assert_eq!(accepted.len(), 1);
    assert!(pool.have_message(&hash_of(&ke)));
    assert_eq!(pool.identity_key_exchange_count(&id), 2);
}

/// What bounds a key exchange's seen list now: the wire refuses a 513th
/// hash both ways, with dcrd's `ErrTooManyPrevMixMsgs`, so no such key
/// exchange reaches the pool.
#[test]
fn a_seen_list_past_the_wire_cap_is_refused_by_the_wire() {
    let (priv_key, id) = identity(2);
    let pr = pair_request(&priv_key, id, 2);
    let prs = with_unknown(&pr, 0, MAX_MIX_PEERS as u32 - 1);
    let ke = key_exchange(&priv_key, id, &prs, &pr, NOW_SECS as u64);

    let payload = Message::MixKeyExchange(Box::new(ke.clone()))
        .encode_payload(MIX_VERSION)
        .expect("512 seen pair requests encode");
    match decode_message_payload("mixkeyxchg", &payload, MIX_VERSION) {
        Ok(Message::MixKeyExchange(decoded)) => assert_eq!(*decoded, ke),
        _ => panic!("512 seen pair requests decode"),
    }

    // The count is the last field's prefix: 0xfd 0x0200 for 512.
    let count_at = payload.len() - 512 * 32 - 3;
    assert_eq!(payload[count_at..count_at + 3], [0xfd, 0x00, 0x02]);
    let mut past = payload;
    past[count_at + 1] = 0x01;
    past.extend_from_slice(&[0x55; 32]);
    assert!(matches!(
        decode_message_payload("mixkeyxchg", &past, MIX_VERSION),
        Err(WireError::TooManyPrevMixMsgs(_))
    ));

    let mut over = ke;
    over.seen_prs.push(Hash([0x55; 32]));
    assert!(matches!(
        Message::MixKeyExchange(Box::new(over)).encode_payload(MIX_VERSION),
        Err(WireError::TooManyPrevMixMsgs(_))
    ));
}

/// `ffb42adf`: a second, distinct key exchange by an identity in a
/// session where it already has one is refused with dcrd's conflict
/// text, neither pooled nor bannable, and leaves the identity's latest
/// key exchange as it was.  Another identity's key exchange in the same
/// session is not a conflict.  The check comes before the pair requests
/// the key exchange names are looked up, so one claiming the other
/// identity's position is a conflict too, not an identity mismatch.
/// The port had pooled the second and relayed it.
#[test]
fn a_second_key_exchange_by_an_identity_in_its_session_is_refused() {
    let (mut pool, _, _) = new_pool();
    let (key_a, id_a) = identity(3);
    let (key_b, id_b) = identity(4);
    let pr_a = pair_request(&key_a, id_a, 3);
    let pr_b = pair_request(&key_b, id_b, 4);
    for pr in [&pr_a, &pr_b] {
        accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request is accepted");
    }
    let prs = [pr_a.clone(), pr_b.clone()];
    let epoch = NOW_SECS as u64;

    let ke_a = key_exchange(&key_a, id_a, &prs, &pr_a, epoch);
    let ke_b = key_exchange(&key_b, id_b, &prs, &pr_b, epoch);
    assert_eq!(ke_a.session_id, ke_b.session_id);
    accept_ke(&mut pool, &ke_a).expect("A's key exchange");
    accept_ke(&mut pool, &ke_b).expect("B's key exchange, same session");
    let before = pool.state_sizes();

    let again = key_exchange_committing(&key_a, id_a, &prs, &pr_a, epoch, 7);
    assert_eq!(again.session_id, ke_a.session_id);
    assert_ne!(hash_of(&again), hash_of(&ke_a));
    let err = accept_ke(&mut pool, &again).err().expect("refused");
    assert_eq!(err, conflict(&again, hash_of(&ke_a)));
    assert!(!err.is_bannable(ServiceFlag(u64::MAX)));
    assert!(!pool.have_message(&hash_of(&again)));
    assert_eq!(pool.state_sizes(), before);
    assert_eq!(pool.identity_key_exchange_count(&id_a), 1);

    let misplaced = key_exchange_committing(&key_a, id_a, &prs, &pr_b, epoch, 8);
    assert_eq!(misplaced.session_id, ke_a.session_id);
    assert_eq!(
        accept_ke(&mut pool, &misplaced).err().expect("refused"),
        conflict(&misplaced, hash_of(&ke_a))
    );
    assert_eq!(pool.state_sizes(), before);

    let pairing = pr_a.pairing();
    let mut latest: Vec<Hash> = pool
        .receive_kes_by_pairing(&pairing, epoch)
        .iter()
        .map(hash_of)
        .collect();
    latest.sort_by_key(|h| h.0);
    let mut want = vec![hash_of(&ke_a), hash_of(&ke_b)];
    want.sort_by_key(|h| h.0);
    assert_eq!(latest, want);

    // The same key exchange again is a duplicate, not a conflict.
    assert_eq!(accept_ke(&mut pool, &ke_a).expect("duplicate").len(), 0);
}

/// `ffb42adf`: only a key exchange by the same identity is a conflict;
/// dcrd's walk passes over every other message of the session
/// (`mixing/mixpool/mixpool.go:1712-1715`).  So the refusal names the
/// identity's key exchange even when the session also holds its
/// ciphertexts, which on some of these pools have the hash that comes
/// first in the port's walk.
#[test]
fn a_conflict_names_the_identity_s_key_exchange_alone() {
    let mut ciphertexts_first = false;
    for round in 0..16u8 {
        let (mut pool, _, _) = new_pool();
        let (key, id) = identity(64 + round);
        let pr = pair_request(&key, id, 64 + round);
        accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request");
        let prs = [pr.clone()];
        let epoch = NOW_SECS as u64;
        let ke = key_exchange(&key, id, &prs, &pr, epoch);
        accept_ke(&mut pool, &ke).expect("key exchange");
        let ct = ciphertexts(&key, id, ke.session_id);
        let accepted = accept(&mut pool, PoolMessage::CT(ct.clone())).expect("ciphertexts");
        assert_eq!(accepted.len(), 1);

        let again = key_exchange_committing(&key, id, &prs, &pr, epoch, 7);
        let err = accept_ke(&mut pool, &again).err().expect("refused");
        assert_eq!(err, conflict(&again, hash_of(&ke)));
        ciphertexts_first |= ct.mix_hash().expect("hash").0 < hash_of(&ke).0;
    }
    assert!(ciphertexts_first, "a ciphertexts hash came first");
}

/// `ffb42adf`: two orphaned key exchanges by one identity for one
/// session meet the check when its pair request arrives.  dcrd's
/// `reconsiderOrphans` accepts the first `acceptKE` passes and
/// `continue`s past the other, which stays an orphan; which one is
/// first is Go's map order there and the port's hash map order here.
#[test]
fn an_un_orphaned_conflicting_key_exchange_stays_an_orphan() {
    let (mut pool, _, _) = new_pool();
    let (key, id) = identity(5);
    let pr = pair_request(&key, id, 5);
    let prs = [pr.clone()];
    let epoch = NOW_SECS as u64;
    let first = key_exchange_committing(&key, id, &prs, &pr, epoch, 1);
    let second = key_exchange_committing(&key, id, &prs, &pr, epoch, 2);
    for ke in [&first, &second] {
        let err = accept_ke(&mut pool, ke).err().expect("orphaned");
        assert!(matches!(err, PoolError::MissingOwnPR(_)));
    }
    assert_eq!(orphan_count(&pool), 2);

    let accepted = accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request");
    assert_eq!(accepted.len(), 2, "the pair request and one key exchange");
    let pooled: Vec<bool> = [&first, &second]
        .iter()
        .map(|ke| pool.have_message(&hash_of(ke)))
        .collect();
    assert_eq!(pooled.iter().filter(|p| **p).count(), 1);
    assert_eq!(orphan_count(&pool), 1, "the other stays an orphan");
    assert_eq!(pool.identity_key_exchange_count(&id), 1);
}

/// `ffb42adf`: a key exchange into a session that still records a
/// message `remove_message` took out of the pool gets dcrd's plain
/// error, which is not a rule error and so not bannable.  No peer can
/// cause it: dcrd's node and the port's daemon never call
/// `RemoveMessage`.
#[test]
fn a_session_recording_a_removed_message_answers_a_plain_error() {
    let (mut pool, _, _) = new_pool();
    let (key, id) = identity(6);
    let pr = pair_request(&key, id, 6);
    accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request");
    let prs = [pr.clone()];
    let epoch = NOW_SECS as u64;
    let ke = key_exchange(&key, id, &prs, &pr, epoch);
    accept_ke(&mut pool, &ke).expect("key exchange");
    pool.remove_message(&PoolMessage::KE(Box::new(ke.clone())))
        .expect("remove key exchange");
    assert!(!pool.have_message(&hash_of(&ke)));

    let next = key_exchange_committing(&key, id, &prs, &pr, epoch, 9);
    let err = accept_ke(&mut pool, &next).err().expect("refused");
    assert_eq!(err, unknown_message(&next, hash_of(&ke)));
    assert!(!err.is_bannable(ServiceFlag(u64::MAX)));
    assert!(!pool.have_message(&hash_of(&next)));
}

/// When a session holds both a removed message and the identity's key
/// exchange, dcrd's answer depends on Go's map order.  The port's is
/// the one for the hash that is smaller in internal byte order (the
/// bytes as held, the reverse of the displayed hex), on every pool,
/// however its hash set happens to iterate.
#[test]
fn a_session_holding_both_failures_answers_for_the_smaller_hash() {
    let mut seen_missing = false;
    let mut seen_conflict = false;
    for round in 0..16u8 {
        let (mut pool, _, _) = new_pool();
        let (key_a, id_a) = identity(32 + 2 * round);
        let (key_b, id_b) = identity(33 + 2 * round);
        let pr_a = pair_request(&key_a, id_a, 32 + 2 * round);
        let pr_b = pair_request(&key_b, id_b, 33 + 2 * round);
        for pr in [&pr_a, &pr_b] {
            accept(&mut pool, PoolMessage::PR(pr.clone())).expect("pair request");
        }
        let prs = [pr_a.clone(), pr_b.clone()];
        let epoch = NOW_SECS as u64;
        let ke_a = key_exchange(&key_a, id_a, &prs, &pr_a, epoch);
        let ke_b = key_exchange(&key_b, id_b, &prs, &pr_b, epoch);
        accept_ke(&mut pool, &ke_a).expect("A's key exchange");
        accept_ke(&mut pool, &ke_b).expect("B's key exchange");
        pool.remove_message(&PoolMessage::KE(Box::new(ke_b.clone())))
            .expect("remove B's key exchange");

        let again = key_exchange_committing(&key_a, id_a, &prs, &pr_a, epoch, 7);
        let err = accept_ke(&mut pool, &again).err().expect("refused");
        let (a, b) = (hash_of(&ke_a), hash_of(&ke_b));
        if a.0 < b.0 {
            assert_eq!(err, conflict(&again, a));
            seen_conflict = true;
        } else {
            assert_eq!(err, unknown_message(&again, b));
            seen_missing = true;
        }
    }
    assert!(seen_missing && seen_conflict, "both orders were exercised");
}
