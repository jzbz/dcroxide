// SPDX-License-Identifier: ISC

//! The mining view (dcrd `mining_view.go`): a snapshot of the
//! transactions ready to be mined, their dependency hierarchy, and
//! cached ancestor statistics bounded by the tracking limit.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::graph::{ForEachRedeemer, TxDescFind, TxDescGraph};
use crate::types::{TxAncestorStats, TxDesc};

/// The maximum number of ancestors a transaction can have ancestor
/// stats calculated for (dcrd `ancestorTrackingLimit`).
pub const ANCESTOR_TRACKING_LIMIT: usize = 25;

fn add_ancestor_to(stats: &mut TxAncestorStats, tx_desc: &TxDesc) {
    stats.fees += tx_desc.fee;
    stats.size_bytes += tx_desc.tx_size;
    stats.total_sig_ops += tx_desc.total_sig_ops;
    stats.num_ancestors += 1;
}

fn remove_ancestor_from(stats: &mut TxAncestorStats, tx_desc: &TxDesc) {
    stats.fees -= tx_desc.fee;
    stats.size_bytes -= tx_desc.tx_size;
    stats.total_sig_ops -= tx_desc.total_sig_ops;
    stats.num_ancestors -= 1;
}

/// A snapshot of all transactions ready to be mined along with their
/// hierarchy (dcrd `TxMiningView`).
pub struct TxMiningView {
    rejected: BTreeSet<[u8; 32]>,
    tx_graph: TxDescGraph,
    tx_descs: Vec<Rc<TxDesc>>,
    track_ancestor_stats: bool,
    ancestor_stats: BTreeMap<[u8; 32], TxAncestorStats>,
}

impl TxMiningView {
    /// A new mining view instance (dcrd `NewTxMiningView`; the
    /// redeemer lookup is passed per call instead of stored).
    pub fn new(enable_ancestor_tracking: bool) -> TxMiningView {
        TxMiningView {
            rejected: BTreeSet::new(),
            tx_graph: TxDescGraph::default(),
            tx_descs: Vec::new(),
            track_ancestor_stats: enable_ancestor_tracking,
            ancestor_stats: BTreeMap::new(),
        }
    }

    /// All transactions the given hash depends on along with a
    /// refresh of its cached bundle statistics (dcrd `ancestors`).
    pub fn ancestors(&mut self, tx_hash: &Hash) -> Vec<Rc<TxDesc>> {
        if !self.track_ancestor_stats {
            return Vec::new();
        }

        let mut ancestors: Vec<Rc<TxDesc>> = Vec::with_capacity(ANCESTOR_TRACKING_LIMIT);
        // Preserve the up-to-date descendant count when statistics
        // were already tracked.
        let mut base_tx_stats: Option<TxAncestorStats> =
            self.ancestor_stats
                .get(&tx_hash.0)
                .map(|old| TxAncestorStats {
                    num_descendants: old.num_descendants,
                    ..TxAncestorStats::default()
                });

        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        self.tx_graph
            .for_each_ancestor(tx_hash, &mut seen, &mut |tx_desc| {
                let stats = base_tx_stats.get_or_insert_with(TxAncestorStats::default);
                add_ancestor_to(stats, tx_desc);
                ancestors.push(tx_desc.clone());
            });

        match base_tx_stats {
            None => {
                self.ancestor_stats.remove(&tx_hash.0);
            }
            Some(stats) => {
                self.ancestor_stats.insert(tx_hash.0, stats);
            }
        }

        ancestors
    }

    /// The cached ancestor statistics for the transaction along with
    /// whether they are tracked (dcrd `AncestorStats`).
    pub fn ancestor_stats(&self, tx_hash: &Hash) -> (TxAncestorStats, bool) {
        if !self.track_ancestor_stats {
            return (TxAncestorStats::default(), false);
        }
        match self.ancestor_stats.get(&tx_hash.0) {
            Some(stats) => (*stats, true),
            None => (TxAncestorStats::default(), false),
        }
    }

    /// The transactions that directly spend from the hash (dcrd
    /// `children`).
    pub fn children(&self, tx_hash: &Hash) -> Vec<Rc<TxDesc>> {
        self.tx_graph
            .children_of
            .get(&tx_hash.0)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// A deep copy of the view and underlying graph over the given
    /// descriptor snapshot (dcrd `Clone`).
    pub fn clone_view(&self, tx_descs: Vec<Rc<TxDesc>>, fetch_tx: TxDescFind<'_>) -> TxMiningView {
        TxMiningView {
            rejected: BTreeSet::new(),
            tx_graph: self.tx_graph.clone_graph(fetch_tx),
            tx_descs,
            track_ancestor_stats: self.track_ancestor_stats,
            ancestor_stats: self.ancestor_stats.clone(),
        }
    }

    /// The transactions in the view that depend on the hash (dcrd
    /// `descendants`).
    pub fn descendants(&self, tx_hash: &Hash) -> Vec<Hash> {
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut descendants = Vec::new();
        self.tx_graph
            .for_each_descendant(tx_hash, &mut seen, &mut |descendant| {
                descendants.push(descendant.tx_hash);
            });
        descendants
    }

    /// Whether the hash spends from another transaction in the view
    /// (dcrd `hasParents`).
    pub fn has_parents(&self, tx_hash: &Hash) -> bool {
        self.tx_graph
            .parents_of
            .get(&tx_hash.0)
            .is_some_and(|m| !m.is_empty())
    }

    /// Whether the hash has been rejected on this view instance (dcrd
    /// `isRejected`).
    pub fn is_rejected(&self, tx_hash: &Hash) -> bool {
        self.rejected.contains(&tx_hash.0)
    }

    /// The transactions the hash directly spends from (dcrd
    /// `parents`).
    pub fn parents(&self, tx_hash: &Hash) -> Vec<Rc<TxDesc>> {
        self.tx_graph
            .parents_of
            .get(&tx_hash.0)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Attempt to update the ancestor stats for the transaction,
    /// treating the given hash as though it does not exist in the
    /// graph (dcrd `maybeUpdateAncestorStats`).
    fn maybe_update_ancestor_stats(&mut self, tx_desc: &TxDesc, ignore_tx_hash: &Hash) -> bool {
        let base_tx_hash = tx_desc.tx_hash;
        let mut can_track_ancestors = true;
        let mut seen_ancestors: BTreeMap<[u8; 32], Rc<TxDesc>> = BTreeMap::new();
        // The walk inserts into the seen map exactly when the callback
        // returns true, so a parallel counter mirrors dcrd's
        // len(seenAncestors) reads inside the callback.
        let mut seen_count = 0usize;
        let graph = &self.tx_graph;
        let ancestor_stats = &self.ancestor_stats;
        graph.for_each_ancestor_pre_order(
            &base_tx_hash,
            &mut seen_ancestors,
            &mut |ancestor_tx_desc| {
                if !can_track_ancestors {
                    // Short circuit once the transaction is known to
                    // be untrackable; this also stops adding to the
                    // seen map.
                    return false;
                }

                let ancestor_tx_hash = ancestor_tx_desc.tx_hash;
                if ancestor_tx_hash == *ignore_tx_hash {
                    // Skip this ancestor but continue walking others.
                    return false;
                }

                // Beyond this count the transaction cannot have stats
                // cached; note dcrd counts the map before insertion.
                if seen_count >= ANCESTOR_TRACKING_LIMIT {
                    can_track_ancestors = false;
                    return false;
                }

                // If any ancestor does not have stats, then the
                // provided transaction should not either.
                let Some(stats) = ancestor_stats.get(&ancestor_tx_hash.0) else {
                    can_track_ancestors = false;
                    return false;
                };

                // Any ancestor whose own ancestors would exceed the
                // limit, or whose descendant count would, disables
                // tracking.
                if stats.num_ancestors + 1 > ANCESTOR_TRACKING_LIMIT as i64 {
                    can_track_ancestors = false;
                    return false;
                }
                if stats.num_descendants + 1 > ANCESTOR_TRACKING_LIMIT as i64 {
                    can_track_ancestors = false;
                    return false;
                }
                seen_count += 1;
                true
            },
        );

        if !can_track_ancestors {
            self.ancestor_stats.remove(&base_tx_hash.0);
            return false;
        }

        // All elements of the seen map have ancestor statistics
        // tracked, guaranteed by the checks during the walk.
        let mut base_stats = TxAncestorStats::default();
        for (ancestor_tx_hash, ancestor_tx_desc) in &seen_ancestors {
            add_ancestor_to(&mut base_stats, ancestor_tx_desc);
            if let Some(stats) = self.ancestor_stats.get_mut(ancestor_tx_hash) {
                stats.num_descendants += 1;
            }
        }
        self.ancestor_stats.insert(base_tx_hash.0, base_stats);
        true
    }

    /// Add the transaction's stats to all dependents (dcrd
    /// `updateStatsDescendantsAdded`).
    fn update_stats_descendants_added(&mut self, base_tx_desc: &TxDesc) {
        let base_tx_hash = base_tx_desc.tx_hash;
        if self
            .tx_graph
            .children_of
            .get(&base_tx_hash.0)
            .is_none_or(|m| m.is_empty())
        {
            return;
        }

        let base_tx_has_stats = self.ancestor_stats.contains_key(&base_tx_hash.0);
        let mut base_descendants_added: i64 = 0;
        let base_initial_descendants = self
            .ancestor_stats
            .get(&base_tx_hash.0)
            .map(|s| s.num_descendants)
            .unwrap_or_default();
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();

        let graph = &self.tx_graph;
        let ancestor_stats = &mut self.ancestor_stats;
        graph.for_each_descendant_pre_order(&base_tx_hash, &mut seen, &mut |descendant| {
            let descendant_tx_hash = descendant.tx_hash;
            let Some(descendant_stats) = ancestor_stats.get(&descendant_tx_hash.0).copied() else {
                // Cannot update stats for a transaction or its
                // descendants when it has none tracked.
                return false;
            };

            if !base_tx_has_stats {
                // The base tx has no ancestor stats, so remove them
                // from all of its descendants (reorg/disapproval
                // joins).
                ancestor_stats.remove(&descendant_tx_hash.0);
                return true;
            }

            if base_initial_descendants + base_descendants_added + 1
                > ANCESTOR_TRACKING_LIMIT as i64
            {
                // The base transaction has enough tracked descendants.
                ancestor_stats.remove(&descendant_tx_hash.0);
                return true;
            }

            if descendant_stats.num_ancestors + 1 > ANCESTOR_TRACKING_LIMIT as i64 {
                // The descendant has too many tracked ancestors.
                ancestor_stats.remove(&descendant_tx_hash.0);
                return true;
            }

            // Update the stats for this descendant and account for it
            // on the base transaction.
            if let Some(stats) = ancestor_stats.get_mut(&descendant_tx_hash.0) {
                add_ancestor_to(stats, base_tx_desc);
            }
            base_descendants_added += 1;
            true
        });
        if base_tx_has_stats
            && base_descendants_added > 0
            && let Some(stats) = self.ancestor_stats.get_mut(&base_tx_hash.0)
        {
            stats.num_descendants += base_descendants_added;
        }
    }

    /// Remove the transaction's stats from all dependents (dcrd
    /// `updateStatsDescendantsRemoved`).
    fn update_stats_descendants_removed(&mut self, base_tx_desc: &Rc<TxDesc>) {
        let base_tx_hash = base_tx_desc.tx_hash;
        if !self.ancestor_stats.contains_key(&base_tx_hash.0) {
            // If the transaction does not have ancestor tracking
            // enabled, then none of its descendants should either.
            return;
        }

        let mut num_untracked_descendants = 0usize;
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut retrack: Vec<Rc<TxDesc>> = Vec::new();
        {
            let graph = &self.tx_graph;
            let ancestor_stats = &mut self.ancestor_stats;
            graph.for_each_descendant_pre_order(&base_tx_hash, &mut seen, &mut |descendant| {
                let descendant_tx_hash = descendant.tx_hash;
                let has_stats = ancestor_stats.contains_key(&descendant_tx_hash.0);

                // Attempt to track the descendant's ancestor stats if
                // it was not tracked previously, bounded to limit the
                // number of ancestor walks.
                if !has_stats && num_untracked_descendants < ANCESTOR_TRACKING_LIMIT {
                    num_untracked_descendants += 1;
                    retrack.push(descendant.clone());

                    // Do not walk descendants of this descendant: it
                    // was on the edge of the ancestor limit, so its
                    // descendants exceed the limit by at least one.
                    return false;
                }

                if has_stats {
                    if let Some(stats) = ancestor_stats.get_mut(&descendant_tx_hash.0) {
                        remove_ancestor_from(stats, base_tx_desc);
                    }
                    return true;
                }

                false
            });
        }
        for descendant in retrack {
            // Note that this retrieves ancestors while walking the
            // descendants of another transaction, ignoring the
            // transaction pending removal.
            self.maybe_update_ancestor_stats(&descendant, &base_tx_hash);
        }

        // Update all ancestors to account for the removal of a
        // descendant.
        let mut seen_ancestors: BTreeMap<[u8; 32], Rc<TxDesc>> = BTreeMap::new();
        let graph = &self.tx_graph;
        let ancestor_stats = &mut self.ancestor_stats;
        graph.for_each_ancestor_pre_order(&base_tx_hash, &mut seen_ancestors, &mut |ancestor| {
            if let Some(stats) = ancestor_stats.get_mut(&ancestor.tx_hash.0) {
                stats.num_descendants -= 1;
            }
            true
        });
    }

    /// Insert a descriptor into the view, relating it to parents and
    /// children through the provided lookups (dcrd `AddTransaction`).
    pub fn add_transaction(
        &mut self,
        tx_desc: &Rc<TxDesc>,
        find_tx: TxDescFind<'_>,
        for_each_redeemer: ForEachRedeemer<'_>,
    ) {
        self.tx_graph.insert(tx_desc, find_tx, for_each_redeemer);

        if self.track_ancestor_stats {
            self.maybe_update_ancestor_stats(tx_desc, &Hash::ZERO);
            // When a transaction is added back to the view, update the
            // stats of its descendants.
            self.update_stats_descendants_added(tx_desc);
        }
    }

    /// Stop tracking the transaction, optionally updating descendant
    /// statistics (dcrd `RemoveTransaction`).
    pub fn remove_transaction(&mut self, tx_hash: &Hash, update_descendant_stats: bool) {
        if self.track_ancestor_stats
            && update_descendant_stats
            && let Some(tx_desc) = self.tx_graph.find(tx_hash)
        {
            self.update_stats_descendants_removed(&tx_desc);
        }

        self.tx_graph.remove(tx_hash);
        self.ancestor_stats.remove(&tx_hash.0);
    }

    /// Stop tracking the transaction and all of its descendants,
    /// flagging them as rejected on this view instance (dcrd
    /// `reject`).
    pub fn reject(&mut self, tx_hash: &Hash) {
        let mut seen: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut descendants: Vec<Hash> = Vec::new();
        self.tx_graph
            .for_each_descendant(tx_hash, &mut seen, &mut |descendant| {
                descendants.push(descendant.tx_hash);
            });
        for descendant in descendants {
            self.remove_transaction(&descendant, false);
            self.rejected.insert(descendant.0);
        }

        self.remove_transaction(tx_hash, false);
        self.rejected.insert(tx_hash.0);
    }

    /// All transactions available in the view snapshot (dcrd
    /// `TxDescs`).
    pub fn tx_descs(&self) -> &[Rc<TxDesc>] {
        &self.tx_descs
    }
}
