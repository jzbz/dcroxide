// SPDX-License-Identifier: ISC
//! The immutable treap backing the live/missed/revoked ticket sets
//! (dcrd `blockchain/stake/internal/tickettreap`).
//!
//! Nodes are ordered by ticket hash and heap-ordered by the ticket
//! height as the priority, which makes the structure fully
//! deterministic for a given insertion sequence — important because
//! `ForEachByHeight` exploits the heap property and dcrd's tie
//! handling (equal heights) makes the shape algorithm-dependent.  The
//! insert and delete cascades therefore mirror dcrd's exact rotation
//! choices.  Structural sharing uses reference counting in place of
//! Go's garbage-collected pointers, and the size accounting fixes the
//! pointer width at dcrd's 64-bit values.

use alloc::sync::Arc;
use alloc::vec::Vec;

/// A key in the treap: a ticket hash (dcrd `tickettreap.Key`).
pub type Key = [u8; 32];

/// The value associated with a ticket (dcrd `tickettreap.Value`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Value {
    /// The block height the ticket matured at (also the treap
    /// priority).
    pub height: u32,
    /// Whether the ticket was missed.
    pub missed: bool,
    /// Whether the ticket was revoked.
    pub revoked: bool,
    /// Whether the ticket was spent.
    pub spent: bool,
    /// Whether the ticket was expired.
    pub expired: bool,
}

impl Value {
    /// A value with the given height and no flags set.
    pub fn new(height: u32) -> Value {
        Value {
            height,
            missed: false,
            revoked: false,
            spent: false,
            expired: false,
        }
    }
}

// The node size accounting from dcrd with the pointer size fixed at
// 64 bits: key array + value pointer + priority + size + two child
// pointers, plus the key length and value fields.
const NODE_FIELDS_SIZE: u64 = 32 + 8 + 4 + 4 + 2 * 8;
const NODE_VALUE_SIZE: u64 = 8;
const NODE_SIZE: u64 = NODE_FIELDS_SIZE + 32 + NODE_VALUE_SIZE;

struct TreapNode {
    key: Key,
    value: Value,
    priority: u32,
    size: u32,
    left: Option<Arc<TreapNode>>,
    right: Option<Arc<TreapNode>>,
}

fn subtree_size(node: &Option<Arc<TreapNode>>) -> u32 {
    node.as_ref().map_or(0, |n| n.size)
}

/// An efficient immutable (persistent) treap keyed by ticket hash with
/// the ticket height as the priority (dcrd `tickettreap.Immutable`).
#[derive(Default, Clone)]
pub struct Immutable {
    root: Option<Arc<TreapNode>>,
    count: usize,
    total_size: u64,
}

impl Immutable {
    /// An empty treap (dcrd `NewImmutable`).
    pub fn new() -> Immutable {
        Immutable::default()
    }

    /// The number of items in the treap (dcrd `Len`).
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the treap is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// A best estimate of the memory footprint per dcrd's accounting
    /// (dcrd `Size`).
    pub fn size(&self) -> u64 {
        self.total_size
    }

    fn get(&self, key: &Key) -> Option<&TreapNode> {
        let mut node = self.root.as_deref();
        while let Some(n) = node {
            node = match key.cmp(&n.key) {
                core::cmp::Ordering::Less => n.left.as_deref(),
                core::cmp::Ordering::Greater => n.right.as_deref(),
                core::cmp::Ordering::Equal => return Some(n),
            };
        }
        None
    }

    /// Whether the treap contains the key (dcrd `Has`).
    pub fn has(&self, key: &Key) -> bool {
        self.get(key).is_some()
    }

    /// The value for the key, if present (dcrd `Get`).
    pub fn value(&self, key: &Key) -> Option<Value> {
        self.get(key).map(|n| n.value)
    }

    /// The key and value at the given in-order index; panics when the
    /// index is out of bounds exactly like dcrd (dcrd `GetByIndex`).
    pub fn get_by_index(&self, idx: usize) -> (Key, Value) {
        let root = self.root.as_deref().expect("getByIndex on empty treap");
        assert!(idx <= root.size as usize, "getByIndex index out of bounds");
        let mut node = root;
        let mut idx = idx;
        loop {
            match node.left.as_deref() {
                None => {
                    if idx == 0 {
                        return (node.key, node.value);
                    }
                    node = node.right.as_deref().expect("index within subtree");
                    idx -= 1;
                }
                Some(left) => {
                    let left_size = left.size as usize;
                    if idx < left_size {
                        node = left;
                    } else if idx == left_size {
                        return (node.key, node.value);
                    } else {
                        node = node.right.as_deref().expect("index within subtree");
                        idx -= left_size + 1;
                    }
                }
            }
        }
    }

    /// Insert or replace the value for the key, returning the new
    /// version of the treap (dcrd `Put`).  The priority is the value
    /// height, and ties stay below their parent exactly as in dcrd.
    /// The rebuild is iterative like dcrd's parent stack so degenerate
    /// spines (sorted keys and heights) cannot exhaust the stack.
    pub fn put(&self, key: Key, value: Value) -> Immutable {
        // Descend to the insertion point recording the path.
        let mut path: Vec<(Arc<TreapNode>, bool)> = Vec::new();
        let mut node = self.root.clone();
        let mut found = false;
        while let Some(n) = node {
            match key.cmp(&n.key) {
                core::cmp::Ordering::Less => {
                    let next = n.left.clone();
                    path.push((n, true));
                    node = next;
                }
                core::cmp::Ordering::Greater => {
                    let next = n.right.clone();
                    path.push((n, false));
                    node = next;
                }
                core::cmp::Ordering::Equal => {
                    path.push((n, false));
                    found = true;
                    node = None;
                }
            }
        }

        if found {
            // Replace the value in the located node and rebuild the
            // path with sizes unchanged.
            let (target, _) = path.pop().expect("found node on path");
            let mut acc = Arc::new(TreapNode {
                key: target.key,
                value,
                priority: target.priority,
                size: target.size,
                left: target.left.clone(),
                right: target.right.clone(),
            });
            while let Some((parent, went_left)) = path.pop() {
                let (left, right) = if went_left {
                    (Some(acc), parent.right.clone())
                } else {
                    (parent.left.clone(), Some(acc))
                };
                acc = Arc::new(TreapNode {
                    key: parent.key,
                    value: parent.value,
                    priority: parent.priority,
                    size: parent.size,
                    left,
                    right,
                });
            }
            return Immutable {
                root: Some(acc),
                count: self.count,
                total_size: self.total_size,
            };
        }

        // Attach the new node and bubble it up while it has a strictly
        // smaller priority than its parent, exactly like dcrd; the
        // first non-rotation ends the cascade.
        let mut acc = Arc::new(TreapNode {
            key,
            value,
            priority: value.height,
            size: 1,
            left: None,
            right: None,
        });
        let mut bubbling = true;
        while let Some((parent, went_left)) = path.pop() {
            if bubbling && acc.priority < parent.priority {
                if went_left {
                    // Rotate right: the parent adopts acc's right
                    // subtree as its new left child.
                    let new_parent = Arc::new(TreapNode {
                        key: parent.key,
                        value: parent.value,
                        priority: parent.priority,
                        size: 1 + subtree_size(&acc.right) + subtree_size(&parent.right),
                        left: acc.right.clone(),
                        right: parent.right.clone(),
                    });
                    acc = Arc::new(TreapNode {
                        key: acc.key,
                        value: acc.value,
                        priority: acc.priority,
                        size: 1 + subtree_size(&acc.left) + new_parent.size,
                        left: acc.left.clone(),
                        right: Some(new_parent),
                    });
                } else {
                    // Rotate left.
                    let new_parent = Arc::new(TreapNode {
                        key: parent.key,
                        value: parent.value,
                        priority: parent.priority,
                        size: 1 + subtree_size(&parent.left) + subtree_size(&acc.left),
                        left: parent.left.clone(),
                        right: acc.left.clone(),
                    });
                    acc = Arc::new(TreapNode {
                        key: acc.key,
                        value: acc.value,
                        priority: acc.priority,
                        size: 1 + new_parent.size + subtree_size(&acc.right),
                        left: Some(new_parent),
                        right: acc.right.clone(),
                    });
                }
            } else {
                bubbling = false;
                let (left, right) = if went_left {
                    (Some(acc), parent.right.clone())
                } else {
                    (parent.left.clone(), Some(acc))
                };
                acc = Arc::new(TreapNode {
                    key: parent.key,
                    value: parent.value,
                    priority: parent.priority,
                    size: parent.size + 1,
                    left,
                    right,
                });
            }
        }
        Immutable {
            root: Some(acc),
            count: self.count + 1,
            total_size: self.total_size + NODE_SIZE,
        }
    }

    /// Remove the key, returning the new version of the treap; the
    /// original is returned unchanged when the key is missing (dcrd
    /// `Delete`).  The push-down cascade picks the left child on
    /// priority ties exactly as in dcrd, implemented iteratively.
    pub fn delete(&self, key: &Key) -> Immutable {
        // Descend to the node being deleted, recording the path.
        let mut path: Vec<(Arc<TreapNode>, bool)> = Vec::new();
        let mut node = self.root.clone();
        let mut del_node: Option<Arc<TreapNode>> = None;
        while let Some(n) = node {
            match key.cmp(&n.key) {
                core::cmp::Ordering::Less => {
                    let next = n.left.clone();
                    path.push((n, true));
                    node = next;
                }
                core::cmp::Ordering::Greater => {
                    let next = n.right.clone();
                    path.push((n, false));
                    node = next;
                }
                core::cmp::Ordering::Equal => {
                    del_node = Some(n);
                    node = None;
                }
            }
        }
        let Some(del_node) = del_node else {
            return self.clone();
        };

        // Cascade the smaller-priority child of the deleted node up,
        // collecting the winners, then fold them back together from
        // the bottom.
        let mut winners: Vec<(Arc<TreapNode>, bool)> = Vec::new();
        let mut left = del_node.left.clone();
        let mut right = del_node.right.clone();
        loop {
            match (left.clone(), right.clone()) {
                (None, None) => break,
                (Some(l), None) => {
                    right = None;
                    left = l.right.clone();
                    winners.push((l, true));
                }
                (None, Some(r)) => {
                    left = None;
                    right = r.left.clone();
                    winners.push((r, false));
                }
                (Some(l), Some(r)) => {
                    if l.priority <= r.priority {
                        left = l.right.clone();
                        winners.push((l, true));
                    } else {
                        right = r.left.clone();
                        winners.push((r, false));
                    }
                }
            }
        }
        let mut acc: Option<Arc<TreapNode>> = None;
        while let Some((w, took_left)) = winners.pop() {
            let acc_size = acc.as_ref().map_or(0, |n| n.size);
            acc = Some(if took_left {
                Arc::new(TreapNode {
                    key: w.key,
                    value: w.value,
                    priority: w.priority,
                    size: 1 + subtree_size(&w.left) + acc_size,
                    left: w.left.clone(),
                    right: acc,
                })
            } else {
                Arc::new(TreapNode {
                    key: w.key,
                    value: w.value,
                    priority: w.priority,
                    size: 1 + acc_size + subtree_size(&w.right),
                    left: acc,
                    right: w.right.clone(),
                })
            });
        }

        // Rebuild the ancestors with the sizes reduced by one.
        while let Some((parent, went_left)) = path.pop() {
            let (left, right) = if went_left {
                (acc, parent.right.clone())
            } else {
                (parent.left.clone(), acc)
            };
            acc = Some(Arc::new(TreapNode {
                key: parent.key,
                value: parent.value,
                priority: parent.priority,
                size: parent.size - 1,
                left,
                right,
            }));
        }
        Immutable {
            root: acc,
            count: self.count - 1,
            total_size: self.total_size - NODE_SIZE,
        }
    }

    /// Call the function with every key/value pair in key order,
    /// stopping early when it returns false (dcrd `ForEach`).
    pub fn for_each(&self, mut f: impl FnMut(&Key, &Value) -> bool) {
        let mut parents: Vec<&TreapNode> = Vec::new();
        let mut node = self.root.as_deref();
        while let Some(n) = node {
            parents.push(n);
            node = n.left.as_deref();
        }
        while let Some(pnode) = parents.pop() {
            if !f(&pnode.key, &pnode.value) {
                return;
            }
            let mut node = pnode.right.as_deref();
            while let Some(n) = node {
                parents.push(n);
                node = n.left.as_deref();
            }
        }
    }

    /// Call the function with every key/value pair whose height is
    /// less than the given height, in key order, exploiting the heap
    /// property (dcrd `ForEachByHeight`).
    pub fn for_each_by_height(
        &self,
        height_less_than: u32,
        mut f: impl FnMut(&Key, &Value) -> bool,
    ) {
        let mut parents: Vec<&TreapNode> = Vec::new();
        let mut node = self.root.as_deref();
        while let Some(n) = node {
            if n.priority >= height_less_than {
                break;
            }
            parents.push(n);
            node = n.left.as_deref();
        }
        while let Some(pnode) = parents.pop() {
            if !f(&pnode.key, &pnode.value) {
                return;
            }
            let mut node = pnode.right.as_deref();
            while let Some(n) = node {
                if n.priority >= height_less_than {
                    break;
                }
                parents.push(n);
                node = n.left.as_deref();
            }
        }
    }

    /// Whether every node satisfies the min-heap priority invariant;
    /// a test aid mirroring the `isHeap` helper in dcrd's treap tests.
    pub fn heap_invariant_ok(&self) -> bool {
        fn is_heap(node: &TreapNode) -> bool {
            let left_ok = node
                .left
                .as_deref()
                .is_none_or(|l| l.priority >= node.priority && is_heap(l));
            let right_ok = node
                .right
                .as_deref()
                .is_none_or(|r| r.priority >= node.priority && is_heap(r));
            left_ok && right_ok
        }
        self.root.as_deref().is_none_or(is_heap)
    }

    /// The winning ticket keys for the given sorted-or-not indexes and
    /// the keys expired at the given height (dcrd
    /// `FetchWinnersAndExpired`).  `None` indexes yield no results;
    /// empty indexes panic exactly as dcrd indexes an empty slice.
    pub fn fetch_winners_and_expired(
        &self,
        idxs: Option<&[usize]>,
        height: u32,
    ) -> (Vec<Key>, Vec<Key>) {
        let Some(idxs) = idxs else {
            return (Vec::new(), Vec::new());
        };
        let mut sorted_idxs = idxs.to_vec();
        sorted_idxs.sort_unstable();

        let mut idx = 0usize;
        let mut winners: Vec<Key> = Vec::new();
        let mut expired: Vec<Key> = Vec::new();
        let mut winner_idx = 0usize;
        self.for_each(|k, v| {
            if v.height <= height {
                expired.push(*k);
            }
            if idx == sorted_idxs[winner_idx] {
                winners.push(*k);
                if winner_idx + 1 < sorted_idxs.len() {
                    winner_idx += 1;
                }
            }
            idx += 1;
            true
        });
        (winners, expired)
    }
}
