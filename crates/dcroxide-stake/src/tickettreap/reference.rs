// SPDX-License-Identifier: ISC
//! The ticket treap as it was before its descents stopped allocating a
//! path and calling the C library to compare keys: the reference the
//! differential test holds the treap to.
//!
//! `get`, `get_by_index`, `put` and `delete` are that implementation
//! unchanged, down to which nodes an operation copies and which it
//! shares with the version it started from.  The path of a descent is
//! a vector of counted references grown as it goes, and keys compare
//! through the array's derived order.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Key, NODE_SIZE, NodeShape, Value};

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

/// The treap as it was (dcrd `tickettreap.Immutable`).
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
    ///
    /// The bound is `<` rather than `<=`: an index equal to the size is
    /// one past the last element.  dcrd carried the same off-by-one and
    /// fixed it in `036b7090`, noting that its own test had not caught
    /// it because the out-of-range index still panicked -- just from the
    /// runtime walking off the end rather than from this check, so the
    /// test's "did it panic" assertion was satisfied by the wrong panic.
    /// The port inherited both the bug and that blind spot until
    /// `eebcea3` carried the fix over.
    pub fn get_by_index(&self, idx: usize) -> (Key, Value) {
        let root = self.root.as_deref().expect("getByIndex on empty treap");
        assert!(idx < root.size as usize, "getByIndex index out of bounds");
        let mut node = root;
        let mut idx = idx;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "idx != 0 before idx -= 1, and idx > left_size before idx -= left_size + \
                      1, where left_size < root.size <= u32::MAX"
        )]
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
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "subtree sizes are at most self.count + 1, and every entry is a ticket \
                          from a block's fresh stake, at most max_fresh_stake_per_block (20 on \
                          every network) per block, so u32::MAX takes over 214 million blocks"
            )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "count and total_size = count * NODE_SIZE (104) track this treap's \
                      entries, each a ticket from a block's fresh stake (a u8 header field) over \
                      at most 2^32 blocks, so count < 2^40 and total_size < 2^47"
        )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "each folded size sums disjoint subtrees of del_node without del_node \
                      itself, so every partial sum is at most del_node.size - 1 < u32::MAX"
        )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "each ancestor on the path holds itself and the deleted node, so \
                      parent.size >= 2"
        )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the deleted key was found, so count >= 1 and total_size = count * \
                      NODE_SIZE >= NODE_SIZE"
        )]
        Immutable {
            root: acc,
            count: self.count - 1,
            total_size: self.total_size - NODE_SIZE,
        }
    }

    /// Every node in pre-order, each with the address it lives at.
    pub(super) fn shape(&self) -> Vec<NodeShape> {
        let mut shape = Vec::new();
        let mut pending: Vec<&Arc<TreapNode>> = self.root.iter().collect();
        while let Some(node) = pending.pop() {
            shape.push(NodeShape {
                address: Arc::as_ptr(node).cast(),
                key: node.key,
                value: node.value,
                priority: node.priority,
                size: node.size,
                has_left: node.left.is_some(),
                has_right: node.right.is_some(),
            });
            pending.extend(node.right.iter());
            pending.extend(node.left.iter());
        }
        shape
    }
}
