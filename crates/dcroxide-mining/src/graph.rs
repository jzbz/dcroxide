// SPDX-License-Identifier: ISC

//! The transaction dependency graph (dcrd `tx_desc_graph.go`): a
//! two-way association between transactions and their in-source
//! parents and children.  dcrd stores the redeemer-lookup closure in
//! the graph; here the lookups are passed per call to satisfy
//! ownership, with identical behavior.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::types::TxDesc;

/// The redeemer enumeration callback: invokes the closure for every
/// in-source transaction spending an output of the given one (dcrd's
/// stored `forEachRedeemer` closure, passed per call here).
pub type ForEachRedeemer<'a> = &'a dyn Fn(&TxDesc, &mut dyn FnMut(Rc<TxDesc>));

/// The transaction locator callback (dcrd `TxDescFind`).
pub type TxDescFind<'a> = &'a dyn Fn(&Hash) -> Option<Rc<TxDesc>>;

/// The dependency graph (dcrd `txDescGraph`).
#[derive(Default)]
pub(crate) struct TxDescGraph {
    pub(crate) children_of: BTreeMap<[u8; 32], BTreeMap<[u8; 32], Rc<TxDesc>>>,
    pub(crate) parents_of: BTreeMap<[u8; 32], BTreeMap<[u8; 32], Rc<TxDesc>>>,
}

impl TxDescGraph {
    /// Add a child transaction as a dependent of `tx` (dcrd
    /// `addChild`).
    fn add_child(&mut self, tx: &TxDesc, child: Rc<TxDesc>) {
        self.children_of
            .entry(tx.tx_hash.0)
            .or_default()
            .insert(child.tx_hash.0, child);
    }

    /// Add a parent transaction as a dependency of `tx` (dcrd
    /// `addParent`).
    fn add_parent(&mut self, tx: &TxDesc, parent: Rc<TxDesc>) {
        self.parents_of
            .entry(tx.tx_hash.0)
            .or_default()
            .insert(parent.tx_hash.0, parent);
    }

    /// The descriptor stored in the graph for the hash, if any (dcrd
    /// `find`): every transaction in the graph has at least one edge,
    /// so scanning as a child or parent suffices.
    pub(crate) fn find(&self, tx_hash: &Hash) -> Option<Rc<TxDesc>> {
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

    /// Visit all transactions the hash depends on in topological
    /// (post-) order (dcrd `forEachAncestor`).
    pub(crate) fn for_each_ancestor(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Rc<TxDesc>),
    ) {
        let parents: Vec<(Hash, Rc<TxDesc>)> = self
            .parents_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default();
        for (parent, parent_desc) in parents {
            if seen.contains_key(&parent.0) {
                continue;
            }
            seen.insert(parent.0, ());
            self.for_each_ancestor(&parent, seen, f);
            f(&parent_desc);
        }
    }

    /// Visit ancestors in pre-order; when `f` returns false no
    /// additional parents at this level are visited and the
    /// transaction is not added to the seen map (dcrd
    /// `forEachAncestorPreOrder`).
    pub(crate) fn for_each_ancestor_pre_order(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], Rc<TxDesc>>,
        f: &mut dyn FnMut(&Rc<TxDesc>) -> bool,
    ) {
        let parents: Vec<(Hash, Rc<TxDesc>)> = self
            .parents_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default();
        for (parent_hash, parent_desc) in parents {
            if seen.contains_key(&parent_hash.0) {
                continue;
            }

            let move_next = f(&parent_desc);
            if !move_next {
                return;
            }

            seen.insert(parent_hash.0, parent_desc);
            self.for_each_ancestor_pre_order(&parent_hash, seen, f);
        }
    }

    /// Visit all dependents depth-first in post-order (dcrd
    /// `forEachDescendant`).
    pub(crate) fn for_each_descendant(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Rc<TxDesc>),
    ) {
        let children: Vec<(Hash, Rc<TxDesc>)> = self
            .children_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default();
        for (child, child_desc) in children {
            if seen.contains_key(&child.0) {
                continue;
            }
            seen.insert(child.0, ());
            self.for_each_descendant(&child, seen, f);
            f(&child_desc);
        }
    }

    /// Visit dependents in pre-order; when `f` returns true the walk
    /// continues into the child's descendants (dcrd
    /// `forEachDescendantPreOrder`).
    pub(crate) fn for_each_descendant_pre_order(
        &self,
        tx_hash: &Hash,
        seen: &mut BTreeMap<[u8; 32], ()>,
        f: &mut dyn FnMut(&Rc<TxDesc>) -> bool,
    ) {
        let children: Vec<(Hash, Rc<TxDesc>)> = self
            .children_of
            .get(&tx_hash.0)
            .map(|m| m.iter().map(|(k, v)| (Hash(*k), v.clone())).collect())
            .unwrap_or_default();
        for (child, child_desc) in children {
            if seen.contains_key(&child.0) {
                continue;
            }
            seen.insert(child.0, ());
            if f(&child_desc) {
                self.for_each_descendant_pre_order(&child, seen, f);
            }
        }
    }

    /// Add a transaction to the graph, creating two-way associations
    /// with its in-source relatives (dcrd `insert`).
    pub(crate) fn insert(
        &mut self,
        tx_desc: &Rc<TxDesc>,
        find_tx: TxDescFind<'_>,
        for_each_redeemer: ForEachRedeemer<'_>,
    ) {
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();

        // Fetch transactions that spend this one.
        let mut children: Vec<Rc<TxDesc>> = Vec::new();
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
            let children: Vec<Rc<TxDesc>> = graph
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
