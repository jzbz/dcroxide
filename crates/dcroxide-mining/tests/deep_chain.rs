// SPDX-License-Identifier: ISC
//! The mining view over an unbounded chain of unconfirmed
//! transactions.
//!
//! dcrd walks the dependency graph recursively, which is safe there
//! because Go grows goroutine stacks on demand.  Rust threads have a
//! fixed stack and overflowing it aborts the process on the guard
//! page rather than unwinding, so a relayed chain of linked mempool
//! transactions would kill every node at the same block.  The pool
//! imposes no package, ancestor, or descendant limit, so the walks
//! must run off the heap.
//!
//! These drive the public view surface — `descendants`, `ancestors`,
//! and `reject`, which the background template thread reaches — over
//! a chain far longer than the stack the bodies run under, and pin
//! the traversal order the recursive form produced.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::sync::Arc;

use dcroxide_chainhash::Hash;
use dcroxide_mining::{TxDesc, TxMiningView};
use dcroxide_stake::TxType;
use dcroxide_wire::{MsgTx, OutPoint, TX_TREE_REGULAR, TxIn, TxOut};

/// The stack size the deep bodies run under.  A recursive walk needs
/// a frame per link, so reintroducing the recursion overflows the
/// guard page and aborts the test binary instead of quietly passing.
const WALK_STACK_BYTES: usize = 512 * 1024;

/// The length of the chain the deep tests build, roughly ten times
/// more links than `WALK_STACK_BYTES` holds recursive frames for.
const DEEP_CHAIN_LEN: u32 = 50_000;

/// A hash with the index encoded big-endian in its leading bytes, so
/// the expected traversals can be written as index sequences.
fn hash_of(index: u32) -> Hash {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&index.to_be_bytes());
    Hash(bytes)
}

/// The index [`hash_of`] encoded into the hash.
fn index_of(hash: &Hash) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash.0[0..4]);
    u32::from_be_bytes(bytes)
}

/// The thin transaction source backing the view, mirroring what the
/// mempool provides it.
#[derive(Default)]
struct ThinSource {
    pool: HashMap<[u8; 32], Arc<TxDesc>>,
    outpoints: HashMap<([u8; 32], u32, i8), Arc<TxDesc>>,
}

impl ThinSource {
    fn add(&mut self, view: &mut TxMiningView, desc: Arc<TxDesc>) {
        self.pool.insert(desc.tx_hash.0, desc.clone());
        let pool = &self.pool;
        let outpoints = &self.outpoints;
        view.add_transaction(&desc, &|hash| pool.get(&hash.0).cloned(), &|tx, f| {
            for i in 0..tx.tx.tx_out.len() as u32 {
                if let Some(redeemer) = outpoints.get(&(tx.tx_hash.0, i, tx.tree)) {
                    f(redeemer.clone());
                }
            }
        });
        for tx_in in &desc.tx.tx_in {
            let op = &tx_in.previous_out_point;
            self.outpoints
                .insert((op.hash.0, op.index, op.tree), desc.clone());
        }
    }
}

/// A descriptor for the chain link at `index`, spending the single
/// output of the link before it.
fn link_desc(index: u32) -> Arc<TxDesc> {
    let prev = OutPoint {
        hash: hash_of(index.wrapping_sub(1)),
        index: 0,
        tree: TX_TREE_REGULAR,
    };
    let tx = MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: prev,
            sequence: 0xffff_ffff,
            value_in: 1_000_000,
            block_height: 1,
            block_index: 0,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: 900_000,
            version: 0,
            pk_script: Vec::new(),
        }],
        ..MsgTx::default()
    };
    Arc::new(TxDesc {
        tx,
        tx_hash: hash_of(index),
        tree: TX_TREE_REGULAR,
        tx_type: TxType::Regular,
        added_unix: 0,
        height: 1,
        fee: 100_000,
        total_sig_ops: 1,
        tx_size: 200,
    })
}

/// A view holding the chain `0 -> 1 -> ... -> len - 1`, with the
/// source that produced it.
fn chain_view(len: u32) -> (TxMiningView, ThinSource) {
    let mut view = TxMiningView::new(true);
    let mut source = ThinSource::default();
    for index in 0..len {
        source.add(&mut view, link_desc(index));
    }
    (view, source)
}

/// Run the body on a thread with a stack far too small for one
/// recursive frame per link of a [`DEEP_CHAIN_LEN`] chain.
fn on_a_small_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(WALK_STACK_BYTES)
        .spawn(body)
        .expect("spawn")
        .join()
        .expect("join")
}

#[test]
fn a_long_chain_of_descendants_does_not_consume_the_stack() {
    let visited = on_a_small_stack(|| {
        let (view, _source) = chain_view(DEEP_CHAIN_LEN);
        view.descendants(&hash_of(0))
            .iter()
            .map(index_of)
            .collect::<Vec<_>>()
    });

    // The post-order walk emits the far end of the chain first.
    let expected: Vec<u32> = (1..DEEP_CHAIN_LEN).rev().collect();
    assert_eq!(visited, expected);
}

#[test]
fn a_long_chain_of_ancestors_does_not_consume_the_stack() {
    let visited = on_a_small_stack(|| {
        let (mut view, _source) = chain_view(DEEP_CHAIN_LEN);
        view.ancestors(&hash_of(DEEP_CHAIN_LEN - 1))
            .iter()
            .map(|desc| index_of(&desc.tx_hash))
            .collect::<Vec<_>>()
    });

    // The post-order walk emits the root of the chain first.
    let expected: Vec<u32> = (0..DEEP_CHAIN_LEN - 1).collect();
    assert_eq!(visited, expected);
}

#[test]
fn rejecting_the_root_of_a_long_chain_does_not_consume_the_stack() {
    let (remaining, root_rejected, tail_rejected) = on_a_small_stack(|| {
        let (mut view, _source) = chain_view(DEEP_CHAIN_LEN);
        view.reject(&hash_of(0));
        (
            view.descendants(&hash_of(0)).len(),
            view.is_rejected(&hash_of(0)),
            view.is_rejected(&hash_of(DEEP_CHAIN_LEN - 1)),
        )
    });

    assert_eq!(remaining, 0);
    assert!(root_rejected);
    assert!(tail_rejected);
}

#[test]
fn the_public_walks_keep_their_traversal_order() {
    // A join and a tail, so both walks have a level with two
    // relatives and a node reachable along two paths:
    //
    //     1
    //    / \
    //   2   3
    //    \ /
    //     4
    //     |
    //     5
    let mut view = TxMiningView::new(true);
    let mut source = ThinSource::default();
    let descs: Vec<Arc<TxDesc>> = (1..=5).map(join_desc).collect();
    for desc in &descs {
        source.add(&mut view, desc.clone());
    }

    let descendants: Vec<u32> = view.descendants(&hash_of(1)).iter().map(index_of).collect();
    assert_eq!(descendants, vec![5, 4, 2, 3]);

    let ancestors: Vec<u32> = view
        .ancestors(&hash_of(5))
        .iter()
        .map(|desc| index_of(&desc.tx_hash))
        .collect();
    assert_eq!(ancestors, vec![1, 2, 3, 4]);
}

/// A descriptor for the join fixture: 2 and 3 spend separate outputs
/// of 1, 4 spends one output each of 2 and 3, and 5 spends 4.
fn join_desc(index: u32) -> Arc<TxDesc> {
    // Each entry is the parent transaction and the output of it that
    // is spent, so no two links redeem the same outpoint.
    let parents: &[(u32, u32)] = match index {
        1 => &[],
        2 => &[(1, 0)],
        3 => &[(1, 1)],
        4 => &[(2, 0), (3, 0)],
        _ => &[(4, 0)],
    };
    let tx_in: Vec<TxIn> = parents
        .iter()
        .map(|(parent, output)| TxIn {
            previous_out_point: OutPoint {
                hash: hash_of(*parent),
                index: *output,
                tree: TX_TREE_REGULAR,
            },
            sequence: 0xffff_ffff,
            value_in: 1_000_000,
            block_height: 1,
            block_index: 0,
            signature_script: Vec::new(),
        })
        .collect();
    let tx = MsgTx {
        tx_in,
        tx_out: vec![
            TxOut {
                value: 400_000,
                version: 0,
                pk_script: Vec::new(),
            },
            TxOut {
                value: 400_000,
                version: 0,
                pk_script: Vec::new(),
            },
        ],
        ..MsgTx::default()
    };
    Arc::new(TxDesc {
        tx,
        tx_hash: hash_of(index),
        tree: TX_TREE_REGULAR,
        tx_type: TxType::Regular,
        added_unix: 0,
        height: 1,
        fee: 100_000,
        total_sig_ops: 1,
        tx_size: 200,
    })
}
