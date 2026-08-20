// SPDX-License-Identifier: ISC
//! Memory reclamation tests for the mixpool: the scheduled expiry
//! pass really shrinks the pool, the expiry latch tracks the newest
//! height it was armed with, and one identity cannot flood the pool
//! with sessions.
//!
//! These are regression tests for a remote unbounded memory growth
//! bug: mix messages are accepted unauthenticated and unsolicited, a
//! single accepted pair request lets its identity mint an unlimited
//! number of sessions (only the sender's own pair request has to be
//! known, every other referenced hash may be arbitrary), and nothing
//! but the scheduled expiry pass reclaims any of it.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::no_mempool_spent;
use dcroxide_mixing::{
    MAX_KES_PER_IDENTITY, MixBlockChain, Pool, PoolMessage, SCRIPT_CLASS_P2PKH_V0, sign_message,
    sort_prs_for_session,
};
use dcroxide_wire::{MixPairReqUTXO, MsgMixKeyExchange, MsgMixPairReq, OutPoint};

/// The tip the pool validates pair request expiries against.
const TIP_HEIGHT: i64 = 100;

/// A fixed wall clock for the pool, in seconds.
const NOW_SECS: i64 = 1_700_000_000;

/// A chain view pinned at [`TIP_HEIGHT`].
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

/// A pool over simnet at [`TIP_HEIGHT`] with no UTXO fetcher, so pair
/// requests are accepted on their structure alone (dcrd skips the
/// ownership checks when the blockchain does not implement the
/// fetcher).
fn new_pool() -> Pool<StubChain> {
    let params: &'static Params = Box::leak(Box::new(simnet_params()));
    Pool::new_with_clock(
        StubChain { params },
        None,
        Arc::new(|| NOW_SECS * 1_000_000_000),
    )
}

/// A mixing identity derived from a seed byte.
fn identity(seed: u8) -> (PrivateKey, [u8; 33]) {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x11;
    bytes[31] = seed;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let pub_key = priv_key.public_key().serialize_compressed();
    (priv_key, pub_key)
}

/// A signed pair request that passes every acceptance rule: one
/// output, one mixed message, a non-dust mix amount and enough fee.
fn pair_request(
    priv_key: &PrivateKey,
    id: [u8; 33],
    expiry: u32,
    outpoint_seed: u8,
) -> MsgMixPairReq {
    let mut hash = [0u8; 32];
    hash[0] = outpoint_seed;
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry,
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

/// An unsigned pair request used only for its hash: a key exchange
/// may reference pair requests the pool has never seen, and each
/// distinct set of referenced hashes derives a distinct session ID.
fn unknown_pair_request(n: u32) -> MsgMixPairReq {
    let mut pr = pair_request_shell();
    pr.lock_time = n;
    pr
}

fn pair_request_shell() -> MsgMixPairReq {
    MsgMixPairReq {
        signature: [0u8; 64],
        identity: [0u8; 33],
        expiry: 0,
        mix_amount: 0,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 0,
        utxos: Vec::new(),
        change: None,
        flags: 0,
        pairing_flags: 0,
    }
}

/// A signed key exchange in a fresh session formed from the
/// identity's own pair request and one pair request the pool does not
/// know, which is all an attacker needs to mint an unlimited number
/// of distinct sessions.
fn key_exchange(
    priv_key: &PrivateKey,
    id: [u8; 33],
    own_pr: &MsgMixPairReq,
    n: u32,
) -> MsgMixKeyExchange {
    let mut prs = vec![own_pr.clone(), unknown_pair_request(n)];
    let epoch = NOW_SECS as u64;
    let sid = sort_prs_for_session(&mut prs, epoch);
    let seen_prs: Vec<Hash> = prs
        .iter()
        .map(|pr| pr.mix_hash().expect("pair request hash"))
        .collect();
    let own_hash = own_pr.mix_hash().expect("pair request hash");
    let pos = seen_prs
        .iter()
        .position(|hash| *hash == own_hash)
        .expect("own pair request position") as u32;

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

/// Accept a pair request and `kes` key exchanges from one identity,
/// returning the identity's public key.
fn fill(pool: &mut Pool<StubChain>, seed: u8, expiry: u32, kes: u32) -> [u8; 33] {
    let (priv_key, id) = identity(seed);
    let pr = pair_request(&priv_key, id, expiry, seed);
    pool.accept_message(&PoolMessage::PR(pr.clone()), 1, &no_mempool_spent)
        .expect("pair request is accepted");
    for n in 0..kes {
        let ke = key_exchange(&priv_key, id, &pr, n);
        pool.accept_message(&PoolMessage::KE(Box::new(ke)), 1, &no_mempool_spent)
            .expect("key exchange is accepted");
    }
    id
}

/// The scheduled expiry pass reclaims everything an expired pair
/// request pulled into the pool: its sessions, their messages and the
/// by-identity index.  Arming the latch alone must not be mistaken
/// for reclamation -- until the pass runs (the daemon's epoch ticker
/// drives it) the pool only ever grows.
#[test]
fn scheduled_expiry_shrinks_the_pool() {
    let mut pool = new_pool();
    let id_a = fill(&mut pool, 1, 110, 8);
    let id_b = fill(&mut pool, 2, 150, 3);

    // 2 pair requests, 11 key exchanges each in their own session,
    // and 13 message hashes indexed by 2 identities.
    assert_eq!(pool.state_sizes(), (2, 11, 0, 11, 2, 13));

    // A block connect arms the latch; by itself it reclaims nothing.
    pool.expire_messages_in_background(120);
    assert_eq!(
        pool.state_sizes(),
        (2, 11, 0, 11, 2, 13),
        "arming the latch must not be the only thing that happens"
    );

    // The epoch tick runs the pass: identity A's pair request has
    // expired at height 120, so its 8 sessions and their messages go
    // with it, while identity B (expiry 150) is untouched.
    pool.expire_scheduled_messages();
    assert_eq!(
        pool.state_sizes(),
        (1, 3, 0, 3, 1, 4),
        "the expiry pass must reclaim the expired identity"
    );
    assert_eq!(pool.identity_key_exchange_count(&id_a), 0);
    assert_eq!(pool.identity_key_exchange_count(&id_b), 3);

    // The next pass, once B has expired too, empties the pool.
    pool.expire_messages_in_background(150);
    pool.expire_scheduled_messages();
    assert_eq!(
        pool.state_sizes(),
        (0, 0, 0, 0, 0, 0),
        "nothing may be retained past its expiry"
    );
}

/// The latch tracks the newest height it is armed with.  A latch that
/// kept the first height would expire against a stale height whenever
/// the ticker coalesces several block connects into one pass, and
/// would keep pair requests the tip has already expired.
#[test]
fn expiry_latch_tracks_the_newest_height() {
    // Ascending arming: the pass must use the newer height.
    let mut pool = new_pool();
    fill(&mut pool, 1, 110, 4);
    pool.expire_messages_in_background(105);
    pool.expire_messages_in_background(115);
    assert_eq!(pool.scheduled_expire_height(), 115);
    pool.expire_scheduled_messages();
    assert_eq!(
        pool.state_sizes(),
        (0, 0, 0, 0, 0, 0),
        "the pass must expire against the newest armed height"
    );
    assert_eq!(
        pool.scheduled_expire_height(),
        0,
        "the pass drains the latch"
    );

    // Out of order arming (a reorg to a lower tip) keeps the newest.
    let mut pool = new_pool();
    fill(&mut pool, 1, 110, 4);
    pool.expire_messages_in_background(115);
    pool.expire_messages_in_background(105);
    assert_eq!(pool.scheduled_expire_height(), 115);
    pool.expire_scheduled_messages();
    assert_eq!(pool.state_sizes(), (0, 0, 0, 0, 0, 0));

    // Control: a height below the expiry reclaims nothing, so the
    // assertions above are about the height and not about the pass
    // clearing the pool unconditionally.
    let mut pool = new_pool();
    fill(&mut pool, 1, 110, 4);
    pool.expire_messages_in_background(105);
    pool.expire_scheduled_messages();
    assert_eq!(pool.state_sizes(), (1, 4, 0, 4, 1, 5));
}

/// One identity cannot fill the pool with sessions: acceptance stops
/// at the per-identity key exchange cap, and the capacity is released
/// again when the messages are removed.
#[test]
fn key_exchange_flood_stops_at_the_per_identity_cap() {
    let mut pool = new_pool();
    let (priv_key, id) = identity(1);
    let pr = pair_request(&priv_key, id, 110, 1);
    pool.accept_message(&PoolMessage::PR(pr.clone()), 1, &no_mempool_spent)
        .expect("pair request is accepted");

    let flood = MAX_KES_PER_IDENTITY as u32 + 64;
    let mut accepted = 0usize;
    let mut first_rejection = None;
    for n in 0..flood {
        let ke = key_exchange(&priv_key, id, &pr, n);
        match pool.accept_message(&PoolMessage::KE(Box::new(ke)), 1, &no_mempool_spent) {
            Ok(msgs) => {
                assert_eq!(msgs.len(), 1, "an accepted key exchange is relayed");
                accepted += 1;
            }
            Err(err) => {
                first_rejection.get_or_insert((n, err));
            }
        }
    }

    assert_eq!(
        accepted, MAX_KES_PER_IDENTITY,
        "acceptance must stop at the cap"
    );
    let (rejected_at, err) = first_rejection.expect("the flood must be rejected");
    assert_eq!(rejected_at as usize, MAX_KES_PER_IDENTITY);
    assert!(
        !err.is_bannable(dcroxide_wire::ServiceFlag(u64::MAX)),
        "a capacity rejection is not a bannable rule violation: {err}"
    );

    assert_eq!(pool.identity_key_exchange_count(&id), MAX_KES_PER_IDENTITY);
    assert_eq!(
        pool.state_sizes(),
        (
            1,
            MAX_KES_PER_IDENTITY,
            0,
            MAX_KES_PER_IDENTITY,
            1,
            MAX_KES_PER_IDENTITY + 1
        ),
        "the flood is bounded in every index it touches"
    );

    // The cap bounds live state, not a lifetime count: removing an
    // accepted key exchange frees a slot for the next one.
    let removed = key_exchange(&priv_key, id, &pr, 0);
    pool.remove_message(&PoolMessage::KE(Box::new(removed)))
        .expect("remove key exchange");
    assert_eq!(
        pool.identity_key_exchange_count(&id),
        MAX_KES_PER_IDENTITY - 1
    );
    let ke = key_exchange(&priv_key, id, &pr, flood);
    pool.accept_message(&PoolMessage::KE(Box::new(ke)), 1, &no_mempool_spent)
        .expect("a freed slot accepts a key exchange again");
    assert_eq!(pool.identity_key_exchange_count(&id), MAX_KES_PER_IDENTITY);

    // A second identity has its own capacity.
    let id_b = fill(&mut pool, 2, 110, 5);
    assert_eq!(pool.identity_key_exchange_count(&id_b), 5);
}
