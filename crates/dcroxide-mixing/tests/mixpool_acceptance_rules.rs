// SPDX-License-Identifier: ISC
//! The mixpool acceptance rules dcrd changed between `6f6cf21b` and
//! `382ff4dd`:
//!
//! - `6b65e0d1`: a key exchange's seen pair requests are bounded by the
//!   wire's 512, no longer by `MAX_PEERS`.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    MAX_PEERS, MixBlockChain, Pool, PoolError, PoolMessage, SCRIPT_CLASS_P2PKH_V0,
    no_mempool_spent, sign_message, sort_prs_for_session,
};
use dcroxide_wire::{
    MAX_MIX_PEERS, MIX_VERSION, Message, MixPairReqUTXO, MsgMixKeyExchange, MsgMixPairReq,
    OutPoint, WireError, decode_message_payload,
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
