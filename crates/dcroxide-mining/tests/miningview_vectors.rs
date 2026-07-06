// SPDX-License-Identifier: ISC
//! Replay of dcrd's mining view, priority queue, and priority
//! calculation behavior generated inside dcrd's internal/mining
//! package (`data/miningview_vectors.txt`): the dependency diamond
//! with out-of-order arrival, removals with and without descendant
//! stat updates, clone isolation, rejection cascades, the ancestor
//! tracking limit over a linear chain with front removals and
//! reversed re-adds, the priority queue pop order with Go heap
//! semantics including ties, and the input-age priority math bit for
//! bit — over a thin transaction source mirroring exactly what the
//! mempool provides the view.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::rc::Rc;

use dcroxide_chainhash::Hash;
use dcroxide_mining::{
    TxDesc, TxMiningView, TxPrioItem, TxPriorityQueue, UNMINED_HEIGHT, calc_input_value_age,
    calc_priority, tx_pq_by_stake_and_fee,
};
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgTx, OutPoint, TX_TREE_REGULAR};

fn tx_type(v: &str) -> TxType {
    match v {
        "0" => TxType::Regular,
        "1" => TxType::SStx,
        "2" => TxType::SSGen,
        "3" => TxType::SSRtx,
        other => panic!("unknown tx type {other}"),
    }
}

/// The thin transaction source backing the view, mirroring the dump's
/// and the mempool's wiring.
#[derive(Default)]
struct ThinSource {
    pool: HashMap<[u8; 32], Rc<TxDesc>>,
    outpoints: HashMap<([u8; 32], u32, i8), Rc<TxDesc>>,
}

impl ThinSource {
    fn add(&mut self, view: &mut TxMiningView, desc: Rc<TxDesc>) {
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

    fn remove(&mut self, view: &mut TxMiningView, tx_hash: &Hash, update_descendant_stats: bool) {
        if let Some(desc) = self.pool.get(&tx_hash.0).cloned() {
            for tx_in in &desc.tx.tx_in {
                let op = &tx_in.previous_out_point;
                self.outpoints.remove(&(op.hash.0, op.index, op.tree));
            }
            view.remove_transaction(tx_hash, update_descendant_stats);
            self.pool.remove(&tx_hash.0);
        }
    }
}

#[test]
fn miningview_vectors() {
    let data = include_str!("data/miningview_vectors.txt");

    let mut names: HashMap<String, Rc<TxDesc>> = HashMap::new();
    let mut hash_names: HashMap<[u8; 32], String> = HashMap::new();
    let mut src = ThinSource::default();
    let mut view = TxMiningView::new(true);
    let mut snapshot: Option<TxMiningView> = None;
    let mut pq = TxPriorityQueue::new(0, tx_pq_by_stake_and_fee);
    let mut counts = [0usize; 7];

    let sorted_names = |items: Vec<String>| -> String {
        let mut items = items;
        items.sort();
        if items.is_empty() {
            "-".to_string()
        } else {
            items.join(",")
        }
    };

    let mut lines = data.lines().peekable();
    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "tx" => {
                // tx <name> <hex> <fee> <sigops>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tx");
                let tx_hash = tx.tx_hash();
                let tx_size = tx.serialize_size() as i64;
                let desc = Rc::new(TxDesc {
                    tx,
                    tx_hash,
                    tree: TX_TREE_REGULAR,
                    tx_type: TxType::Regular,
                    added_unix: 0,
                    height: 1,
                    fee: f[3].parse().expect("fee"),
                    total_sig_ops: f[4].parse().expect("sigops"),
                    tx_size,
                });
                hash_names.insert(tx_hash.0, f[1].to_string());
                names.insert(f[1].to_string(), desc);
            }
            "add" => {
                let desc = names[f[1]].clone();
                src.add(&mut view, desc);
            }
            "del" => {
                let desc = names[f[1]].clone();
                src.remove(&mut view, &desc.tx_hash, f[2] == "true");
            }
            "reset" => {
                src = ThinSource::default();
                view = TxMiningView::new(true);
            }
            "chk" => {
                // chk <sorted pool names>: st rows follow, one per
                // pool transaction in sorted name order.
                let pool_names =
                    sorted_names(src.pool.keys().map(|k| hash_names[k].clone()).collect());
                assert_eq!(pool_names, f[1], "{line}");
                counts[0] += 1;
            }
            "st" => {
                // st <name> <stats|none> <parents> <children> <descendants>
                let desc = &names[f[1]];
                let (stats, has_stats) = view.ancestor_stats(&desc.tx_hash);
                let stat_str = if has_stats {
                    format!(
                        "{}:{}:{}:{}:{}",
                        stats.fees,
                        stats.size_bytes,
                        stats.total_sig_ops,
                        stats.num_ancestors,
                        stats.num_descendants
                    )
                } else {
                    "none".to_string()
                };
                assert_eq!(stat_str, f[2], "{line}: stats");
                let parents = sorted_names(
                    view.parents(&desc.tx_hash)
                        .iter()
                        .map(|p| hash_names[&p.tx_hash.0].clone())
                        .collect(),
                );
                assert_eq!(parents, f[3], "{line}: parents");
                let children = sorted_names(
                    view.children(&desc.tx_hash)
                        .iter()
                        .map(|c| hash_names[&c.tx_hash.0].clone())
                        .collect(),
                );
                assert_eq!(children, f[4], "{line}: children");
                let descendants = sorted_names(
                    view.descendants(&desc.tx_hash)
                        .iter()
                        .map(|d| hash_names[&d.0].clone())
                        .collect(),
                );
                assert_eq!(descendants, f[5], "{line}: descendants");
                counts[1] += 1;
            }
            "clonechildren" => {
                // clonechildren d <snapshot count> <live count>: the
                // snapshot was taken just before the preceding add.
                let desc = &names[f[1]];
                let snap = snapshot.as_ref().expect("snapshot");
                assert_eq!(
                    snap.children(&desc.tx_hash).len().to_string(),
                    f[2],
                    "{line}: snapshot"
                );
                assert_eq!(
                    view.children(&desc.tx_hash).len().to_string(),
                    f[3],
                    "{line}: live"
                );
                counts[2] += 1;
            }
            "clonestats" => {
                // clonestats e <snap has> <snap fees> <live has> <live fees>
                // after removing b from the snapshot only.
                let desc = &names[f[1]];
                let snap = snapshot.as_mut().expect("snapshot");
                snap.remove_transaction(&names["b"].tx_hash, true);
                let (snap_stats, snap_has) = snap.ancestor_stats(&desc.tx_hash);
                let (live_stats, live_has) = view.ancestor_stats(&desc.tx_hash);
                assert_eq!(snap_has.to_string(), f[2], "{line}: snap has");
                assert_eq!(snap_stats.fees.to_string(), f[3], "{line}: snap fees");
                assert_eq!(live_has.to_string(), f[4], "{line}: live has");
                assert_eq!(live_stats.fees.to_string(), f[5], "{line}: live fees");
                counts[3] += 1;
            }
            "reject" => {
                let desc = names[f[1]].clone();
                view.reject(&desc.tx_hash);
            }
            "rejected" => {
                let mut rejected = Vec::new();
                for name in ["a", "b", "c", "d", "e", "f"] {
                    if view.is_rejected(&names[name].tx_hash) {
                        rejected.push(name.to_string());
                    }
                }
                assert_eq!(sorted_names(rejected), f[1], "{line}");
                counts[4] += 1;
            }
            "pqpush" => {
                // pqpush <idx> <type> <autorev> <fee> <priobits> <feekbbits>
                let idx: i64 = f[1].parse().expect("idx");
                let dummy = Rc::new(TxDesc {
                    tx: MsgTx::from_bytes(&unhex("010000000000000000000000000000"))
                        .map(|(tx, _)| tx)
                        .unwrap_or_else(|_| panic!("dummy tx")),
                    tx_hash: Hash::ZERO,
                    tree: TX_TREE_REGULAR,
                    tx_type: TxType::Regular,
                    added_unix: 0,
                    height: idx,
                    fee: 0,
                    total_sig_ops: 0,
                    tx_size: 0,
                });
                pq.push(TxPrioItem {
                    tx_desc: dummy,
                    tx_type: tx_type(f[2]),
                    auto_revocation: f[3] == "true",
                    fee: f[4].parse().expect("fee"),
                    priority: f64::from_bits(u64::from_str_radix(f[5], 16).expect("prio")),
                    fee_per_kb: f64::from_bits(u64::from_str_radix(f[6], 16).expect("feekb")),
                });
            }
            "pqpop" => {
                let mut popped = Vec::new();
                while let Some(item) = pq.pop() {
                    popped.push(item.tx_desc.height.to_string());
                }
                assert_eq!(popped.join(","), f[1], "{line}");
                counts[5] += 1;
            }
            "prio" => {
                // prio <txhex> <mode> <nextheight> <priobits> <agebits>
                // mode 1: input known at height 1; mode 2: unmined
                // input; mode 0: unknown input.
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let mode: u8 = f[2].parse().expect("mode");
                let next_height: i64 = f[3].parse().expect("height");
                let prev = tx.tx_in[0].previous_out_point;
                let lookup = move |op: &OutPoint| -> Option<(i64, i64)> {
                    if *op != prev {
                        return None;
                    }
                    match mode {
                        1 => Some((1, 2500000000)),
                        2 => Some((UNMINED_HEIGHT, 2500000000)),
                        _ => None,
                    }
                };
                let prio = calc_priority(&tx, lookup, next_height);
                let age = calc_input_value_age(&tx, lookup, next_height);
                assert_eq!(format!("{:016x}", prio.to_bits()), f[4], "{line}: prio");
                assert_eq!(format!("{:016x}", age.to_bits()), f[5], "{line}: age");
                counts[6] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }

        // The snapshot in the diamond scenario is taken immediately
        // before adding f.
        if f[0] == "add" && f[1] == "f" && snapshot.is_none() {
            // Too late: the snapshot must be taken before the add.
        }
        if f[0] == "del" && f[1] == "c" && f[2] == "false" {
            // Nothing.
        }
        // Take the snapshot right before "add f" appears next.
        if snapshot.is_none() {
            if let Some(next) = lines.peek() {
                if *next == "add f" {
                    let pool = &src.pool;
                    snapshot =
                        Some(view.clone_view(Vec::new(), &|hash| pool.get(&hash.0).cloned()));
                }
            }
        }
    }
    assert_eq!(counts, [18, 225, 1, 1, 1, 1, 5], "row counts");
}
