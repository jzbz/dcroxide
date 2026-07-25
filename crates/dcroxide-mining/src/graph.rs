// SPDX-License-Identifier: ISC

//! The transaction dependency graph (dcrd `tx_desc_graph.go`): a
//! two-way association between transactions and their in-source
//! parents and children.  dcrd stores the redeemer-lookup closure in
//! the graph; here the lookups are passed per call to satisfy
//! ownership, with identical behavior.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::types::TxDesc;

/// The redeemer enumeration callback: invokes the closure for every
/// in-source transaction spending an output of the given one (dcrd's
/// stored `forEachRedeemer` closure, passed per call here).
pub type ForEachRedeemer<'a> = &'a dyn Fn(&TxDesc, &mut dyn FnMut(Arc<TxDesc>));

/// The transaction locator callback (dcrd `TxDescFind`).
pub type TxDescFind<'a> = &'a dyn Fn(&Hash) -> Option<Arc<TxDesc>>;

/// One pending level of an iterative graph walk, holding exactly the
/// state a recursive call frame would have: the relatives still to be
/// visited at that level, the cursor into them, and — for the
/// post-order walks — the descriptor to emit once the level is
/// exhausted.
///
/// dcrd recurses through the graph, which is safe there because Go
/// grows goroutine stacks on demand.  Rust threads have a fixed stack
/// and overflowing it aborts the process rather than unwinding, so
/// the walks below keep their frames on the heap; the traversal order
/// and the set of visited nodes are unchanged.
struct WalkFrame {
    relatives: Vec<(Hash, Arc<TxDesc>)>,
    next: usize,
    emit: Option<Arc<TxDesc>>,
}

impl WalkFrame {
    /// A frame that visits the relatives without emitting anything on
    /// the way back up (the pre-order walks).
    fn new(relatives: Vec<(Hash, Arc<TxDesc>)>) -> WalkFrame {
        WalkFrame {
            relatives,
            next: 0,
            emit: None,
        }
    }

    /// A frame that emits the given descriptor once all of its
    /// relatives have been visited (the post-order walks, where dcrd
    /// invokes the callback after the recursive call returns).
    fn emitting(relatives: Vec<(Hash, Arc<TxDesc>)>, emit: Arc<TxDesc>) -> WalkFrame {
        WalkFrame {
            relatives,
            next: 0,
            emit: Some(emit),
        }
    }

    /// The next relative at this level, advancing the cursor; `None`
    /// once the level is exhausted, which is where the recursive form
    /// returned to its caller.
    fn next_relative(&mut self) -> Option<(Hash, Arc<TxDesc>)> {
        let (hash, desc) = self.relatives.get(self.next)?;
        let relative = (*hash, desc.clone());
        self.next = self.next.saturating_add(1);
        Some(relative)
    }
}

/// The dependency graph (dcrd `txDescGraph`).
#[derive(Default)]
pub(crate) struct TxDescGraph {
    pub(crate) children_of: BTreeMap<[u8; 32], BTreeMap<[u8; 32], Arc<TxDesc>>>,
    pub(crate) parents_of: BTreeMap<[u8; 32], BTreeMap<[u8; 32], Arc<TxDesc>>>,
}

impl TxDescGraph {
    /// Add a child transaction as a dependent of `tx` (dcrd
    /// `addChild`).
    fn add_child(&mut self, tx: &TxDesc, child: Arc<TxDesc>) {
        self.children_of
            .entry(tx.tx_hash.0)
            .or_default()
            .insert(child.tx_hash.0, child);
    }

    /// Add a parent transaction as a dependency of `tx` (dcrd
    /// `addParent`).
    fn add_parent(&mut self, tx: &TxDesc, parent: Arc<TxDesc>) {
        self.parents_of
            .entry(tx.tx_hash.0)
            .or_default()
            .insert(parent.tx_hash.0, parent);
    }

    /// The descriptor stored in the graph for the hash, if any (dcrd
    /// `find`): every transaction in the graph has at least one edge,
    /// so scanning as a child or parent suffices.
    pub(crate) fn find(&self, tx_hash: &Hash) -> Option<Arc<TxDesc>> {
        if let Some(parents) = self.parents_of.get(&tx_hash.0) {
            for parent_hash in parents.keys() {
                if let Some(desc) = self
                    .children_of
                    .get(parent_hash)
                    .and_then(|m| m.get(&tx_hash.0))
                {
                    return Some(desc.clone());
                }
            }
        }
        if let Some(children) = self.children_of.get(&tx_hash.0) {
            for child_hash in children.keys() {
                if let Some(desc) = self
                    .parents_of
                    .get(child_hash)
                    .and_then(|m| m.get(&tx_hash.0))
                {
                    return Some(desc.clone());
                }
            }
        }
        None
    }

    /// The direct dependencies of the hash, in the order the walks
    /// visit them (dcrd's `range g.parentsOf[*txHash]`).
    fn parents_list(&self, tx_hash: &Hash) -> Vec<(Hash, Arc<TxDesc>)> {
        self.parents_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default()
    }

    /// The direct dependents of the hash, in the order the walks
    /// visit them (dcrd's `range g.childrenOf[*txHash]`).
    fn children_list(&self, tx_hash: &Hash) -> Vec<(Hash, Arc<TxDesc>)> {
        self.children_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default()
    }

    /// Visit all transactions the hash depends on in topological
    /// (post-) order (dcrd `forEachAncestor`).
    ///
    /// dcrd recurses per level; the explicit frame stack here visits
    /// the same nodes in the same order without consuming the thread
    /// stack, so an unbounded chain of unconfirmed transactions
    /// cannot abort the process.
    pub(crate) fn for_each_ancestor(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Arc<TxDesc>),
    ) {
        let mut frames: Vec<WalkFrame> = vec![WalkFrame::new(self.parents_list(tx_hash))];
        while let Some(frame) = frames.last_mut() {
            let Some((parent, parent_desc)) = frame.next_relative() else {
                // The level is exhausted, which is the point the
                // recursive call returned; the descriptor descended
                // into is emitted here, after its own ancestors.
                let emit = frame.emit.take();
                frames.pop();
                if let Some(emit) = emit {
                    f(&emit);
                }
                continue;
            };
            if seen.contains_key(&parent.0) {
                continue;
            }
            seen.insert(parent.0, ());
            frames.push(WalkFrame::emitting(self.parents_list(&parent), parent_desc));
        }
    }

    /// Visit ancestors in pre-order; when `f` returns false no
    /// additional parents at this level are visited and the
    /// transaction is not added to the seen map (dcrd
    /// `forEachAncestorPreOrder`).
    ///
    /// The recursion is an explicit frame stack for the reason given
    /// on [`WalkFrame`]; the visit order and the seen map are
    /// unchanged.
    pub(crate) fn for_each_ancestor_pre_order(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], Arc<TxDesc>>,
        f: &mut dyn FnMut(&Arc<TxDesc>) -> bool,
    ) {
        let mut frames: Vec<WalkFrame> = vec![WalkFrame::new(self.parents_list(tx_hash))];
        while let Some(frame) = frames.last_mut() {
            let Some((parent_hash, parent_desc)) = frame.next_relative() else {
                frames.pop();
                continue;
            };
            if seen.contains_key(&parent_hash.0) {
                continue;
            }

            let move_next = f(&parent_desc);
            if !move_next {
                // dcrd returns from the current call, which abandons
                // the remaining parents at this level only; the
                // levels above it keep iterating.
                frames.pop();
                continue;
            }

            seen.insert(parent_hash.0, parent_desc);
            frames.push(WalkFrame::new(self.parents_list(&parent_hash)));
        }
    }

    /// Visit all dependents depth-first in post-order (dcrd
    /// `forEachDescendant`).
    ///
    /// The recursion is an explicit frame stack for the reason given
    /// on [`WalkFrame`]; the visit order and the seen map are
    /// unchanged.
    pub(crate) fn for_each_descendant(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Arc<TxDesc>),
    ) {
        let mut frames: Vec<WalkFrame> = vec![WalkFrame::new(self.children_list(tx_hash))];
        while let Some(frame) = frames.last_mut() {
            let Some((child, child_desc)) = frame.next_relative() else {
                let emit = frame.emit.take();
                frames.pop();
                if let Some(emit) = emit {
                    f(&emit);
                }
                continue;
            };
            if seen.contains_key(&child.0) {
                continue;
            }
            seen.insert(child.0, ());
            frames.push(WalkFrame::emitting(self.children_list(&child), child_desc));
        }
    }

    /// Visit dependents in pre-order; when `f` returns true the walk
    /// continues into the child's descendants (dcrd
    /// `forEachDescendantPreOrder`).
    ///
    /// The recursion is an explicit frame stack for the reason given
    /// on [`WalkFrame`]; the visit order and the seen map are
    /// unchanged.
    pub(crate) fn for_each_descendant_pre_order(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Arc<TxDesc>) -> bool,
    ) {
        let mut frames: Vec<WalkFrame> = vec![WalkFrame::new(self.children_list(tx_hash))];
        while let Some(frame) = frames.last_mut() {
            let Some((child, child_desc)) = frame.next_relative() else {
                frames.pop();
                continue;
            };
            if seen.contains_key(&child.0) {
                continue;
            }
            seen.insert(child.0, ());
            if f(&child_desc) {
                frames.push(WalkFrame::new(self.children_list(&child)));
            }
        }
    }

    /// Add a transaction to the graph, creating two-way associations
    /// with its in-source relatives (dcrd `insert`).
    pub(crate) fn insert(
        &mut self,
        tx_desc: &Arc<TxDesc>,
        find_tx: TxDescFind<'_>,
        for_each_redeemer: ForEachRedeemer<'_>,
    ) {
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();

        // Fetch transactions that spend this one.
        let mut children: Vec<Arc<TxDesc>> = Vec::new();
        for_each_redeemer(tx_desc, &mut |child| children.push(child));
        for child in children {
            self.add_child(tx_desc, child.clone());
            self.add_parent(&child, tx_desc.clone());
        }

        // Relate self with direct ancestors.
        for tx_in in &tx_desc.tx.tx_in {
            let parent_hash = tx_in.previous_out_point.hash;
            if seen.contains_key(&parent_hash.0) {
                continue;
            }
            seen.insert(parent_hash.0, ());

            if let Some(parent_tx) = find_tx(&parent_hash) {
                self.add_parent(tx_desc, parent_tx.clone());
                self.add_child(&parent_tx, tx_desc.clone());
            }
        }
    }

    /// Delete the hash from the graph, dropping edge-less relatives
    /// (dcrd `remove`).
    pub(crate) fn remove(&mut self, tx_hash: &Hash) {
        // Remove references to tx from all children.
        let children: Vec<[u8; 32]> = self
            .children_of
            .get(&tx_hash.0)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for child_hash in children {
            if let Some(parents) = self.parents_of.get_mut(&child_hash) {
                parents.remove(&tx_hash.0);
                if parents.is_empty() {
                    self.parents_of.remove(&child_hash);
                }
            }
        }

        // Remove references to tx from all parents.
        let parents: Vec<[u8; 32]> = self
            .parents_of
            .get(&tx_hash.0)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for parent_hash in parents {
            if let Some(children) = self.children_of.get_mut(&parent_hash) {
                children.remove(&tx_hash.0);
                if children.is_empty() {
                    self.children_of.remove(&parent_hash);
                }
            }
        }

        self.parents_of.remove(&tx_hash.0);
        self.children_of.remove(&tx_hash.0);
    }

    /// A copy of the graph, sourcing descriptors through the given
    /// locator (dcrd `clone`).
    pub(crate) fn clone_graph(&self, fetch_tx: TxDescFind<'_>) -> TxDescGraph {
        let mut graph = TxDescGraph::default();

        // Anything tracked by the graph is a child or parent of
        // another element in the graph.  The cloned graph sources
        // redeemers from itself to decouple from the original
        // transaction source; at insert time the redeemers are the
        // already-inserted children of the transaction.
        let hashes: Vec<[u8; 32]> = self
            .parents_of
            .keys()
            .chain(self.children_of.keys())
            .copied()
            .collect();
        for tx_hash in hashes {
            let Some(tx_desc) = fetch_tx(&Hash(tx_hash)) else {
                continue;
            };
            let children: Vec<Arc<TxDesc>> = graph
                .children_of
                .get(&tx_hash)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default();
            graph.insert(&tx_desc, fetch_tx, &|_tx, f| {
                for child in &children {
                    f(child.clone());
                }
            });
        }

        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;
    use dcroxide_stake::TxType;
    use dcroxide_wire::{MsgTx, TX_TREE_REGULAR};

    /// The stack size the walk tests run their bodies under.  The
    /// walks below are driven over a chain far longer than this many
    /// recursive frames would fit in, so reintroducing recursion in
    /// any of them overflows the guard page and aborts the test
    /// binary rather than quietly passing.
    const WALK_STACK_BYTES: usize = 512 * 1024;

    /// The length of the chain the depth tests build.  A recursive
    /// walk needs on the order of a hundred bytes of stack per link,
    /// so this is roughly ten times more than `WALK_STACK_BYTES`
    /// allows.
    const DEEP_CHAIN_LEN: u32 = 50_000;

    /// A hash with the index encoded big-endian in its leading bytes,
    /// so the `BTreeMap` ordering the walks follow is the numeric
    /// order of the indexes and the expected traversals can be
    /// written out by hand.
    fn hash_of(index: u32) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&index.to_be_bytes());
        Hash(bytes)
    }

    /// The index [`hash_of`] encoded into the descriptor's hash.
    fn index_of(desc: &Arc<TxDesc>) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&desc.tx_hash.0[0..4]);
        u32::from_be_bytes(bytes)
    }

    /// A descriptor identified by the index; the walks read nothing
    /// but the hash, so the transaction body is left empty.
    fn desc_of(index: u32) -> Arc<TxDesc> {
        Arc::new(TxDesc {
            tx: MsgTx::default(),
            tx_hash: hash_of(index),
            tree: TX_TREE_REGULAR,
            tx_type: TxType::Regular,
            added_unix: 0,
            height: 0,
            fee: 0,
            total_sig_ops: 0,
            tx_size: 0,
        })
    }

    /// Relate the child as a dependent of the parent in both
    /// directions, the pair of edges `insert` creates.
    fn link(graph: &mut TxDescGraph, parent: u32, child: u32) {
        let parent_desc = desc_of(parent);
        let child_desc = desc_of(child);
        graph.add_child(&parent_desc, child_desc.clone());
        graph.add_parent(&child_desc, parent_desc);
    }

    /// A graph with a join and a tail, so every walk has a level with
    /// two relatives and a node reachable by two paths:
    ///
    /// ```text
    ///     1
    ///    / \
    ///   2   3
    ///    \ /
    ///     4
    ///     |
    ///     5
    /// ```
    fn diamond() -> TxDescGraph {
        let mut graph = TxDescGraph::default();
        link(&mut graph, 1, 2);
        link(&mut graph, 1, 3);
        link(&mut graph, 2, 4);
        link(&mut graph, 3, 4);
        link(&mut graph, 4, 5);
        graph
    }

    /// A linear chain `0 -> 1 -> ... -> len - 1`.
    fn chain(len: u32) -> TxDescGraph {
        let mut graph = TxDescGraph::default();
        for parent in 0..len.saturating_sub(1) {
            link(&mut graph, parent, parent.saturating_add(1));
        }
        graph
    }

    /// Run the body on a thread with a stack far too small for a
    /// recursive walk over [`DEEP_CHAIN_LEN`] links.
    fn on_a_small_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(WALK_STACK_BYTES)
            .spawn(body)
            .expect("spawn")
            .join()
            .expect("join")
    }

    #[test]
    fn ancestors_are_visited_in_post_order() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_ancestor(&hash_of(5), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
        });

        // 4 is descended into first, then its parents 2 and 3 in
        // order; 2's own parent 1 is emitted before 2, and 3 skips 1
        // as seen.  Each node is emitted after its ancestors.
        assert_eq!(visited, vec![1, 2, 3, 4]);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn ancestors_are_visited_in_pre_order() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_ancestor_pre_order(&hash_of(5), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
            true
        });

        // Each node is emitted before its ancestors, and 1 is visited
        // once because 2 records it in the seen map before 3 is
        // reached.
        assert_eq!(visited, vec![4, 2, 1, 3]);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn a_false_ancestor_abandons_only_the_current_level() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_ancestor_pre_order(&hash_of(5), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
            index_of(desc) != 2
        });

        // Refusing 2 abandons the level holding 2 and 3 entirely, and
        // 2 is not recorded as seen.
        assert_eq!(visited, vec![4, 2]);
        assert_eq!(seen.keys().copied().collect::<Vec<_>>(), vec![hash_of(4).0]);
    }

    #[test]
    fn a_refused_ancestor_stays_unseen_and_can_be_revisited() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_ancestor_pre_order(&hash_of(5), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
            index_of(desc) != 1
        });

        // Refusing 1 under 2 abandons that level and leaves 1 out of
        // the seen map, so walking 3 reaches 1 a second time.
        assert_eq!(visited, vec![4, 2, 1, 3, 1]);
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn descendants_are_visited_in_post_order() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_descendant(&hash_of(1), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
        });

        // The 2 branch is walked to the bottom first, so 5 and 4 are
        // emitted before 2; 3 then skips 4 as seen.
        assert_eq!(visited, vec![5, 4, 2, 3]);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn descendants_are_visited_in_pre_order() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_descendant_pre_order(&hash_of(1), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
            true
        });

        assert_eq!(visited, vec![2, 4, 5, 3]);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn a_false_descendant_only_stops_the_descent() {
        let graph = diamond();
        let mut seen = BTreeMap::new();
        let mut visited = Vec::new();
        graph.for_each_descendant_pre_order(&hash_of(1), &mut seen, &mut |desc| {
            visited.push(index_of(desc));
            index_of(desc) != 2
        });

        // Unlike the ancestor walk, refusing 2 leaves it in the seen
        // map and the rest of its level is still visited; only its
        // own descendants are skipped, and they are reached through 3
        // instead.
        assert_eq!(visited, vec![2, 3, 4, 5]);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn a_long_ancestor_chain_does_not_consume_the_stack() {
        let visited = on_a_small_stack(|| {
            let graph = chain(DEEP_CHAIN_LEN);
            let mut seen = BTreeMap::new();
            let mut visited = Vec::new();
            graph.for_each_ancestor(
                &hash_of(DEEP_CHAIN_LEN.saturating_sub(1)),
                &mut seen,
                &mut |desc| visited.push(index_of(desc)),
            );
            visited
        });

        // Post-order over a chain emits the root first.
        let expected: Vec<u32> = (0..DEEP_CHAIN_LEN.saturating_sub(1)).collect();
        assert_eq!(visited, expected);
    }

    #[test]
    fn a_long_ancestor_chain_does_not_consume_the_stack_pre_order() {
        let visited = on_a_small_stack(|| {
            let graph = chain(DEEP_CHAIN_LEN);
            let mut seen = BTreeMap::new();
            let mut visited = Vec::new();
            graph.for_each_ancestor_pre_order(
                &hash_of(DEEP_CHAIN_LEN.saturating_sub(1)),
                &mut seen,
                &mut |desc| {
                    visited.push(index_of(desc));
                    true
                },
            );
            visited
        });

        let expected: Vec<u32> = (0..DEEP_CHAIN_LEN.saturating_sub(1)).rev().collect();
        assert_eq!(visited, expected);
    }

    #[test]
    fn a_long_descendant_chain_does_not_consume_the_stack() {
        let visited = on_a_small_stack(|| {
            let graph = chain(DEEP_CHAIN_LEN);
            let mut seen = BTreeMap::new();
            let mut visited = Vec::new();
            graph.for_each_descendant(&hash_of(0), &mut seen, &mut |desc| {
                visited.push(index_of(desc))
            });
            visited
        });

        // Post-order over a chain emits the far end first.
        let expected: Vec<u32> = (1..DEEP_CHAIN_LEN).rev().collect();
        assert_eq!(visited, expected);
    }

    #[test]
    fn a_long_descendant_chain_does_not_consume_the_stack_pre_order() {
        let visited = on_a_small_stack(|| {
            let graph = chain(DEEP_CHAIN_LEN);
            let mut seen = BTreeMap::new();
            let mut visited = Vec::new();
            graph.for_each_descendant_pre_order(&hash_of(0), &mut seen, &mut |desc| {
                visited.push(index_of(desc));
                true
            });
            visited
        });

        let expected: Vec<u32> = (1..DEEP_CHAIN_LEN).collect();
        assert_eq!(visited, expected);
    }
}
