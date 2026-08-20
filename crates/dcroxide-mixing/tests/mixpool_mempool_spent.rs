// SPDX-License-Identifier: ISC
//! Pair-request acceptance consults the transaction memory pool
//! (RVW-001).
//!
//! dcrd's `mixpoolChain.FetchUtxoEntry` asks the mempool before the
//! chain (`server.go:3752-3754`) and returns a nil entry when it answers
//! yes; `mixpool.go:1448` folds nil into the same rejection as a spent
//! entry. So a pair request whose claimed output an unmined transaction
//! already spends is refused.
//!
//! The port asked only the chain's utxo set, which reports such an
//! output unspent because nothing has mined the spender yet. The request
//! was pooled and relayed, and its pairing would then fail against peers
//! that do run dcrd.
//!
//! The answer arrives as a predicate rather than a pool handle. dcrd
//! answers it inside the fetcher, which runs under the mixpool's own
//! mutex; doing that here would take the tx-pool lock while holding the
//! mixpool's, against an acceptance gauntlet that already takes them the
//! other way round.

use std::sync::Arc;

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    MixBlockChain, MixUtxoEntry, MixUtxoFetcher, Pool, PoolError, PoolMessage,
    SCRIPT_CLASS_P2PKH_V0, no_mempool_spent, sign_message,
};
use dcroxide_wire::{MixPairReqUTXO, MsgMixPairReq, OutPoint};

const TIP_HEIGHT: i64 = 100;

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

/// An output the chain considers live: unspent, confirmed, version 0.
struct LiveEntry;

impl MixUtxoEntry for LiveEntry {
    fn is_spent(&self) -> bool {
        false
    }
    fn pk_script(&self) -> &[u8] {
        &[]
    }
    fn script_version(&self) -> u16 {
        0
    }
    fn block_height(&self) -> i64 {
        1
    }
    fn amount(&self) -> i64 {
        10_100_000
    }
}

struct LiveFetcher;

impl MixUtxoFetcher for LiveFetcher {
    fn fetch_utxo_entry(&self, _op: &OutPoint) -> Result<Box<dyn MixUtxoEntry>, String> {
        Ok(Box::new(LiveEntry))
    }
}

fn new_pool() -> Pool<StubChain> {
    let params: &'static Params = Box::leak(Box::new(simnet_params()));
    Pool::new(StubChain { params }, Some(Arc::new(LiveFetcher)))
}

fn identity() -> (PrivateKey, [u8; 33]) {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x11;
    bytes[31] = 7;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let pub_key = priv_key.public_key().serialize_compressed();
    (priv_key, pub_key)
}

fn claimed_outpoint() -> OutPoint {
    let mut hash = [0u8; 32];
    hash[0] = 7;
    OutPoint {
        hash: Hash(hash),
        index: 7,
        tree: 0,
    }
}

/// A signed pair request claiming [`claimed_outpoint`].
fn pair_request() -> MsgMixPairReq {
    let (priv_key, id) = identity();
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry: (TIP_HEIGHT + 10) as u32,
        mix_amount: 10_000_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point: claimed_outpoint(),
            script: Vec::new(),
            pub_key: id.to_vec(),
            signature: vec![0u8; 64],
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    sign_message(&mut pr, &priv_key).expect("sign pair request");
    pr
}

fn text(err: &PoolError) -> String {
    format!("{err}")
}

/// The verdict when the memory pool already spends the claimed output.
///
/// dcrd's exact rejection text, and the same one a chain-spent output
/// gets, because dcrd reaches it through the same branch.
#[test]
fn a_pair_request_over_a_mempool_spent_output_is_rejected() {
    let mut pool = new_pool();
    let pr = pair_request();
    let target = claimed_outpoint();

    let err = pool
        .accept_message(&PoolMessage::PR(pr), 1, &|op: &OutPoint| *op == target)
        .err()
        .expect("a mempool-spent output must not back a pair request");
    assert!(
        text(&err).contains("is not unspent"),
        "expected dcrd's not-unspent rejection, got: {err}",
    );
}

/// The same request, with the memory pool answering no, must get past
/// that check -- otherwise the assertion above would hold for reasons
/// having nothing to do with the mempool.
///
/// It still fails, on the ownership proof further down the same loop,
/// which is the point: the *verdict changes* with the predicate, and
/// only the mempool branch produces the not-unspent text. dcrd orders
/// the two the same way, consulting the mempool inside its fetch, ahead
/// of the proof (`mixpool.go:1443-1470`).
#[test]
fn the_same_request_reaches_past_that_check_when_the_mempool_says_no() {
    let mut pool = new_pool();
    let pr = pair_request();

    let err = pool
        .accept_message(&PoolMessage::PR(pr), 1, &no_mempool_spent)
        .err()
        .expect("the fixture's ownership proof is not valid");
    assert!(
        !text(&err).contains("is not unspent"),
        "without a mempool spend the not-unspent branch must not fire, got: {err}",
    );
}

/// And the predicate has to be keyed on the request's own outputs: a
/// mempool spend of some unrelated outpoint must not reject it.
#[test]
fn an_unrelated_mempool_spend_does_not_reject() {
    let mut pool = new_pool();
    let pr = pair_request();
    let unrelated = OutPoint {
        hash: Hash([0xab; 32]),
        index: 3,
        tree: 0,
    };

    let err = pool
        .accept_message(&PoolMessage::PR(pr), 1, &|op: &OutPoint| *op == unrelated)
        .err()
        .expect("the fixture's ownership proof is not valid");
    assert!(
        !text(&err).contains("is not unspent"),
        "an unrelated mempool spend must not reject, got: {err}",
    );
}
