// SPDX-License-Identifier: ISC
//! GAP01#3: dcrd processes each connected block's orphans with its tip
//! at that block (`server.go:3046-3053`), so an orphan a later block of
//! the same batch mines is not in the chain yet there: it is accepted
//! when its inputs are, the orphans redeeming it with it, and the later
//! block removes it alone.  The daemon's drain runs with the later block
//! already connected, where that orphan fails as a duplicate of a chain
//! transaction, or as an orphan of its own spent inputs; it is taken as
//! accepted without being pooled, so its redeemers are processed at the
//! earlier block, as in dcrd.  An orphan dcrd would still find missing
//! an input at the earlier block stays an orphan, and one that is a
//! duplicate for any other reason keeps dcrd's cascade.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{chain_from_init, harness_policy};
use dcroxide_blockchain::validate::AgendaFlags;
use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::TxPool;
use dcroxide_wire::{MsgTx, OutPoint, TX_TREE_REGULAR, TxIn, TxOut};

/// The pay-to-script-hash output over a lone `OP_TRUE`.
fn op_true_p2sh() -> Vec<u8> {
    let mut script = vec![0xa9, 0x14]; // OP_HASH160 OP_DATA_20
    script.extend_from_slice(&dcroxide_txscript::stdaddr::hash160(&[0x51]));
    script.push(0x87); // OP_EQUAL
    script
}

/// An input spending output 0 of `parent`.
fn input(parent: &MsgTx) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: parent.tx_hash(),
            index: 0,
            tree: TX_TREE_REGULAR,
        },
        sequence: u32::MAX,
        value_in: parent.tx_out[0].value,
        block_height: 0,
        block_index: 0,
        signature_script: vec![0x01, 0x51],
    }
}

/// A transaction spending output 0 of each parent to one
/// pay-to-`OP_TRUE` output, less a fee.
fn spend_all(parents: &[&MsgTx]) -> MsgTx {
    MsgTx {
        tx_in: parents.iter().map(|parent| input(parent)).collect(),
        tx_out: vec![TxOut {
            value: parents
                .iter()
                .map(|parent| parent.tx_out[0].value)
                .sum::<i64>()
                - 10_000,
            version: 0,
            pk_script: op_true_p2sh(),
        }],
        ..MsgTx::default()
    }
}

/// A transaction spending output 0 of `parent`.
fn spend(parent: &MsgTx) -> MsgTx {
    spend_all(&[parent])
}

/// A pay-to-`OP_TRUE` transaction to confirm and start from, told
/// apart by `tag`.
fn seed(tag: u32) -> MsgTx {
    MsgTx {
        tx_out: vec![TxOut {
            value: 1_000_000_000,
            version: 0,
            pk_script: op_true_p2sh(),
        }],
        lock_time: tag,
        ..MsgTx::default()
    }
}

/// A pool over the harness chain with `seeds` confirmed, holding
/// `orphans` as orphans.
fn pool_with(seeds: &[&MsgTx], orphans: &[&MsgTx]) -> TxPool<common::FakeChain> {
    let data = include_str!("data/txpool_vectors.txt");
    let init: Vec<&str> = data.lines().next().expect("init row").split(' ').collect();
    let params = mainnet_params();
    let mut policy = harness_policy(params.coinbase_maturity);
    policy.accept_non_std = true;
    let mut chain = chain_from_init(&init);
    let height = chain.best_height;
    for seed in seeds {
        chain.utxos.add_tx_outs(seed, height - 10, 1, false);
    }

    let mut pool = TxPool::new(chain, policy, &params);
    for orphan in orphans {
        let accepted = pool
            .process_transaction(orphan, true, false, 0)
            .expect("the orphan is admitted");
        assert!(accepted.is_empty(), "a parent is unknown");
        assert!(pool.is_orphan_in_pool(&orphan.tx_hash()));
    }
    pool
}

/// Connect a block mining `txs` to the pool's chain without running any
/// maintenance, as each block of a batch of connects is.
fn mine(pool: &mut TxPool<common::FakeChain>, txs: &[&MsgTx]) {
    let height = pool.chain.best_height + 1;
    for tx in txs {
        for tx_in in &tx.tx_in {
            pool.chain.utxos.remove_entry(&tx_in.previous_out_point);
        }
        pool.chain.utxos.add_tx_outs(tx, height, 1, false);
    }
    pool.chain.best_height = height;
}

/// The daemon's maintenance for a connected block mining `txs`, as the
/// drain runs it (`ChainNtfnHandler::handle_connected_block`), with
/// `mined_later` naming what the batch's later blocks mined.  Returns
/// what it accepted, in order.
fn maintain(
    pool: &mut TxPool<common::FakeChain>,
    txs: &[&MsgTx],
    mined_later: &dyn Fn(&Hash) -> bool,
) -> Vec<Hash> {
    let mut accepted = Vec::new();
    for tx in txs {
        let hash = tx.tx_hash();
        pool.remove_transaction(tx, &hash, false);
        let _ = pool.maybe_accept_dependents(tx, &hash, false);
        pool.remove_double_spends(tx, &hash);
        pool.remove_orphan_pub(&hash);
        accepted.extend(
            pool.process_orphans_accepted_in_batch(tx, &hash, AgendaFlags::default(), mined_later)
                .into_iter()
                .map(|(hash, _)| hash),
        );
    }
    accepted
}

/// The predicate naming exactly `txs`.
fn named(txs: &[&MsgTx]) -> impl Fn(&Hash) -> bool {
    let hashes: Vec<Hash> = txs.iter().map(|tx| tx.tx_hash()).collect();
    move |hash: &Hash| hashes.contains(hash)
}

#[test]
fn an_orphan_a_later_block_mined_releases_its_redeemers_at_this_block() {
    // o spends x, d spends o; one block mines x and the next o.
    let seed = seed(7);
    let x = spend(&seed);
    let o = spend(&x);
    let d = spend(&o);
    let mut pool = pool_with(&[&seed], &[&o, &d]);
    mine(&mut pool, &[&x]);
    mine(&mut pool, &[&o]);

    // x's block: o is already in the chain, mined by the later block.
    // dcrd accepts o there, and d with it, and announces both.
    let accepted = maintain(&mut pool, &[&x], &named(&[&o]));
    assert_eq!(accepted, vec![d.tx_hash()], "d is accepted at x's block");
    assert!(
        !pool.is_orphan_in_pool(&o.tx_hash()),
        "o leaves the orphans"
    );
    assert!(!pool.is_transaction_in_pool(&o.tx_hash()), "o is mined");
    assert!(pool.is_transaction_in_pool(&d.tx_hash()));

    // o's block removes o alone, which the pool does not hold.
    assert!(maintain(&mut pool, &[&o], &named(&[])).is_empty());
    assert!(pool.is_transaction_in_pool(&d.tx_hash()));
}

#[test]
fn an_orphan_chain_a_later_block_mined_releases_the_grandchild() {
    // o spends x, d spends o, e spends d; one block mines x and the next
    // o and d.  With d mined, o is fully spent, so it fails as an orphan
    // of its own spent input rather than as a duplicate, and d fails as
    // a duplicate.  dcrd accepts o, d and e at x's block and keeps e.
    let seed = seed(7);
    let x = spend(&seed);
    let o = spend(&x);
    let d = spend(&o);
    let e = spend(&d);
    let mut pool = pool_with(&[&seed], &[&o, &d, &e]);
    mine(&mut pool, &[&x]);
    mine(&mut pool, &[&o, &d]);

    let accepted = maintain(&mut pool, &[&x], &named(&[&o, &d]));
    assert_eq!(accepted, vec![e.tx_hash()], "e is accepted at x's block");
    for mined in [&o, &d] {
        assert!(!pool.is_orphan_in_pool(&mined.tx_hash()));
        assert!(!pool.is_transaction_in_pool(&mined.tx_hash()));
    }

    // The later block's own maintenance keeps e.
    assert!(maintain(&mut pool, &[&o, &d], &named(&[])).is_empty());
    assert!(pool.is_transaction_in_pool(&e.tx_hash()));
}

#[test]
fn an_orphan_missing_an_input_a_later_block_mined_stays_an_orphan() {
    // o spends x and y, d spends o; one block mines x and the next y and
    // o.  At x's block dcrd still misses y, which no pool holds, so o
    // stays an orphan; at the later block o is a duplicate there too,
    // and dcrd discards it with d.
    let (seed_x, seed_y) = (seed(7), seed(8));
    let x = spend(&seed_x);
    let y = spend(&seed_y);
    let o = spend_all(&[&x, &y]);
    let d = spend(&o);
    let mut pool = pool_with(&[&seed_x, &seed_y], &[&o, &d]);
    mine(&mut pool, &[&x]);
    mine(&mut pool, &[&y, &o]);

    assert!(maintain(&mut pool, &[&x], &named(&[&y, &o])).is_empty());
    assert!(pool.is_orphan_in_pool(&o.tx_hash()), "o is still an orphan");
    assert!(pool.is_orphan_in_pool(&d.tx_hash()));

    assert!(maintain(&mut pool, &[&y, &o], &named(&[])).is_empty());
    assert!(!pool.is_orphan_in_pool(&o.tx_hash()));
    assert!(!pool.is_orphan_in_pool(&d.tx_hash()), "d goes with o");
    assert!(!pool.is_transaction_in_pool(&d.tx_hash()));
}

#[test]
fn an_orphan_mined_with_its_parent_takes_its_redeemers_with_it() {
    // x and o in one block, as dcrd sees any pair it processes at the
    // same tip: o is a duplicate of a chain transaction, and dcrd's
    // `removeOrphan(tx, true)` discards its redeemer too.
    let seed = seed(7);
    let x = spend(&seed);
    let o = spend(&x);
    let d = spend(&o);
    let mut pool = pool_with(&[&seed], &[&o, &d]);
    mine(&mut pool, &[&x, &o]);

    assert!(maintain(&mut pool, &[&x, &o], &named(&[])).is_empty());
    assert!(!pool.is_orphan_in_pool(&o.tx_hash()));
    assert!(
        !pool.is_orphan_in_pool(&d.tx_hash()),
        "the redeemer goes too"
    );
    assert!(!pool.is_transaction_in_pool(&d.tx_hash()));
}
