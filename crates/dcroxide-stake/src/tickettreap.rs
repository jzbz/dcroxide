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
use core::cmp::Ordering;

#[cfg(test)]
mod reference;

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

/// Compare two keys as byte strings: the order dcrd's `bytes.Compare`
/// gives them (immutable.go:89, :168, :261), which is the order the
/// array's derived comparison gives them.
///
/// It has to be exactly that order.  The treap's shape follows from
/// it, and so do the in-order sequence the lottery indexes into and
/// the order the tickets of a set are listed in.  The array's derived
/// comparison goes through the C library's `memcmp`, a call for every
/// node a descent visits.  This one reads the key as four big-endian
/// words, which compare as the bytes they are made of do, and is
/// inlined into the descent.
#[inline]
fn compare_keys(a: &Key, b: &Key) -> Ordering {
    let (a_words, _) = a.as_chunks::<8>();
    let (b_words, _) = b.as_chunks::<8>();
    for (a_word, b_word) in a_words.iter().zip(b_words) {
        // Big-endian, so the first byte that differs decides, as it
        // does between the byte strings.
        let a_word = u64::from_be_bytes(*a_word);
        let b_word = u64::from_be_bytes(*b_word);
        if a_word != b_word {
            return a_word.cmp(&b_word);
        }
    }
    Ordering::Equal
}

/// The number of nodes a [`NodeStack`] holds in place (dcrd
/// `staticDepth`, common.go:18-23, which is 128 for a stack of bare
/// pointers).  A search path in a treap of ticket hashes is a few
/// dozen nodes long; a longer one spills into the overflow, so the
/// number decides when a stack allocates and never what it holds.
const NODE_STACK_INLINE: usize = 64;

/// A stack of nodes borrowed from a treap, each with the side that was
/// taken at it (dcrd `parentStack`, common.go:116-191).
///
/// Like dcrd's, it holds its first entries in place and the rest in an
/// overflow that only a path longer than that reaches, so recording
/// the path of a descent allocates nothing.  The nodes are borrowed
/// from the version being read, which keeps them alive, so recording
/// one touches no reference count either.  The side is kept beside the
/// node where dcrd recovers it by comparing child pointers.
struct NodeStack<'a> {
    inline: [Option<(&'a TreapNode, bool)>; NODE_STACK_INLINE],
    /// How many entries of `inline` are in use; the overflow holds
    /// entries only while this is `NODE_STACK_INLINE`.
    len: usize,
    overflow: Vec<(&'a TreapNode, bool)>,
}

impl<'a> NodeStack<'a> {
    fn new() -> NodeStack<'a> {
        NodeStack {
            inline: [None; NODE_STACK_INLINE],
            len: 0,
            overflow: Vec::new(),
        }
    }

    fn push(&mut self, node: &'a TreapNode, side: bool) {
        match self.inline.get_mut(self.len) {
            Some(slot) => {
                *slot = Some((node, side));
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "len indexed a slot, so len < NODE_STACK_INLINE"
                )]
                {
                    self.len += 1;
                }
            }
            None => self.overflow.push((node, side)),
        }
    }

    fn pop(&mut self) -> Option<(&'a TreapNode, bool)> {
        if let Some(entry) = self.overflow.pop() {
            return Some(entry);
        }
        self.len = self.len.checked_sub(1)?;
        // Every slot below the length was filled by a push.
        self.inline[self.len]
    }
}

/// One node of a treap as a test sees it: what it holds, which
/// children it has, and the address it lives at, which tells a node
/// shared between two versions from a copy of it.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeShape {
    pub(crate) address: *const (),
    pub(crate) key: Key,
    pub(crate) value: Value,
    pub(crate) priority: u32,
    pub(crate) size: u32,
    pub(crate) has_left: bool,
    pub(crate) has_right: bool,
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
            node = match compare_keys(key, &n.key) {
                Ordering::Less => n.left.as_deref(),
                Ordering::Greater => n.right.as_deref(),
                Ordering::Equal => return Some(n),
            };
        }
        None
    }

    /// Descend towards the key, pushing every node passed together
    /// with whether the descent went to its left, and return the node
    /// holding the key, if there is one; that node is not pushed.
    fn descend<'a>(&'a self, key: &Key, path: &mut NodeStack<'a>) -> Option<&'a TreapNode> {
        let mut node = self.root.as_deref();
        while let Some(n) = node {
            node = match compare_keys(key, &n.key) {
                Ordering::Less => {
                    path.push(n, true);
                    n.left.as_deref()
                }
                Ordering::Greater => {
                    path.push(n, false);
                    n.right.as_deref()
                }
                Ordering::Equal => return Some(n),
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
        let mut path = NodeStack::new();
        match self.descend(&key, &mut path) {
            Some(target) => self.replace(target, value, &mut path),
            None => self.insert(key, value, &mut path),
        }
    }

    /// Insert the key, which must not be in the treap yet: the new
    /// version, or `None` when the key is already present.
    ///
    /// The one descent that finds where the key goes also finds
    /// whether it is there, where dcrd's `safePut` asks `Has` and then
    /// descends again in `Put` (tickets.go:491-497).  The version
    /// returned is the one [`Immutable::put`] returns for a key that
    /// is absent.
    pub(crate) fn put_new(&self, key: Key, value: Value) -> Option<Immutable> {
        let mut path = NodeStack::new();
        if self.descend(&key, &mut path).is_some() {
            return None;
        }
        Some(self.insert(key, value, &mut path))
    }

    /// The version in which the node `path` leads to holds the given
    /// value: the located node and its ancestors are rebuilt with their
    /// sizes unchanged, and the node keeps its priority.
    fn replace(&self, target: &TreapNode, value: Value, path: &mut NodeStack<'_>) -> Immutable {
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
        Immutable {
            root: Some(acc),
            count: self.count,
            total_size: self.total_size,
        }
    }

    /// The version with the key, which the descent recorded in `path`
    /// did not find, added below the last node of that path.
    fn insert(&self, key: Key, value: Value, path: &mut NodeStack<'_>) -> Immutable {
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
        match self.take(key) {
            Some((_, treap)) => treap,
            None => self.clone(),
        }
    }

    /// Remove the key, returning the value it held and the new version
    /// of the treap, or `None` when the key is missing.
    ///
    /// The one descent that finds the node also reads its value and
    /// records the path the removal rebuilds, where dcrd's `safeGet`
    /// and `safeDelete` descend for `Get`, for `Has` and again in
    /// `Delete` (tickets.go:468, :504-510).  The version returned is
    /// the one [`Immutable::delete`] returns for a key that is present.
    pub(crate) fn take(&self, key: &Key) -> Option<(Value, Immutable)> {
        // Descend to the node being deleted, recording the path.
        let mut path = NodeStack::new();
        let del_node = self.descend(key, &mut path)?;

        // Cascade the smaller-priority child of the deleted node up,
        // collecting the winners, then fold them back together from
        // the bottom.
        let mut winners = NodeStack::new();
        let mut left = del_node.left.as_deref();
        let mut right = del_node.right.as_deref();
        loop {
            match (left, right) {
                (None, None) => break,
                (Some(l), None) => {
                    left = l.right.as_deref();
                    winners.push(l, true);
                }
                (None, Some(r)) => {
                    right = r.left.as_deref();
                    winners.push(r, false);
                }
                (Some(l), Some(r)) => {
                    if l.priority <= r.priority {
                        left = l.right.as_deref();
                        winners.push(l, true);
                    } else {
                        right = r.left.as_deref();
                        winners.push(r, false);
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
        let treap = Immutable {
            root: acc,
            count: self.count - 1,
            total_size: self.total_size - NODE_SIZE,
        };
        Some((del_node.value, treap))
    }

    /// Every node in pre-order, which with the children each node says
    /// it has gives the whole structure.
    #[cfg(test)]
    pub(crate) fn shape(&self) -> Vec<NodeShape> {
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "winner_idx < sorted_idxs.len() since it was just used as an index, and idx \
                      counts visited nodes, at most self.len()"
        )]
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

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small bounded values"
)]
mod tests {
    use super::*;

    use alloc::collections::BTreeMap;
    use dcroxide_testutil::SplitMix64;

    /// A value in `0..n`.
    fn below(rng: &mut SplitMix64, n: usize) -> usize {
        rng.below(n as u64) as usize
    }

    fn random_key(rng: &mut SplitMix64) -> Key {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        key
    }

    /// The key dcrd's treap tests make of a counter (`uint32ToKey`,
    /// immutable_test.go).
    fn counter_key(counter: u32) -> Key {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&counter.to_be_bytes());
        key
    }

    /// The order of two byte strings as `bytes.Compare` defines it: the
    /// first position at which they differ decides, the bytes compared
    /// unsigned.
    fn compare_bytewise(a: &Key, b: &Key) -> Ordering {
        for (x, y) in a.iter().zip(b) {
            if x < y {
                return Ordering::Less;
            }
            if x > y {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }

    /// Keys chosen to separate the byte order from every near miss of
    /// it, then random ones.
    fn order_test_keys() -> Vec<Key> {
        let mut keys: Vec<Key> = Vec::new();
        // One byte set to each boundary value at each position of an
        // all-zero and an all-one key.  A pair of these differs in one
        // or two bytes, so it tells a big-endian word from a
        // little-endian one, an unsigned word from a signed one, and
        // the first word from the last.
        for base in [0x00u8, 0xff] {
            for position in 0..32 {
                for value in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                    let mut key = [base; 32];
                    key[position] = value;
                    keys.push(key);
                }
            }
        }
        // Random keys, half of them sharing a prefix of random length
        // with the key before, so the later words decide as often as
        // the first does.
        let mut rng = SplitMix64::from_entropy("ticket treap key order");
        for _ in 0..600 {
            let mut key = random_key(&mut rng);
            if below(&mut rng, 2) == 0 {
                let previous = keys.last().expect("keys above");
                let shared = below(&mut rng, 33);
                key[..shared].copy_from_slice(&previous[..shared]);
            }
            keys.push(key);
        }
        keys
    }

    /// The treap's shape, its in-order sequence and what the lottery
    /// selects by index all follow from the order of the keys, so the
    /// comparison the descents run must order every pair of keys as
    /// dcrd's `bytes.Compare` does, which is as the array's derived
    /// comparison did.
    #[test]
    fn keys_compare_as_their_bytes_do() {
        let keys = order_test_keys();
        let mut decided_by = [0usize; 4];
        for a in &keys {
            for b in &keys {
                let want = compare_bytewise(a, b);
                assert_eq!(a.cmp(b), want, "the array's order, {a:?} against {b:?}");
                assert_eq!(compare_keys(a, b), want, "{a:?} against {b:?}");
                if let Some(position) = a.iter().zip(b).position(|(x, y)| x != y) {
                    decided_by[position / 8] += 1;
                }
            }
        }
        // Each of the four words decided some of the pairs.
        assert!(
            decided_by.iter().all(|&pairs| pairs >= 5_000),
            "{decided_by:?}"
        );

        // And so a treap of the keys lists them, and indexes them, in
        // the order of the byte strings.
        let mut rng = SplitMix64::from_entropy("ticket treap key order heights");
        let mut treap = Immutable::new();
        let mut sorted: BTreeMap<Key, Value> = BTreeMap::new();
        for key in &keys {
            // A key that comes twice has its value replaced.
            let value = Value::new(below(&mut rng, 50) as u32);
            sorted.insert(*key, value);
            treap = treap.put(*key, value);
        }
        assert!(sorted.len() > 800, "{} distinct keys", sorted.len());
        let mut listed = Vec::new();
        treap.for_each(|key, value| {
            listed.push((*key, *value));
            true
        });
        assert!(
            sorted
                .iter()
                .map(|(k, v)| (*k, *v))
                .eq(listed.iter().copied()),
            "the treap lists its keys in another order than the byte strings'"
        );
        for (index, entry) in listed.iter().enumerate() {
            assert_eq!(treap.get_by_index(index), *entry, "index {index}");
        }
    }

    /// A version of the treap and the reference's version made by the
    /// same operations, with the nodes each was made of.
    struct Version {
        treap: Immutable,
        reference: reference::Immutable,
        shape: Vec<NodeShape>,
        reference_shape: Vec<NodeShape>,
    }

    impl Version {
        fn new(treap: Immutable, reference: reference::Immutable) -> Version {
            let shape = treap.shape();
            let reference_shape = reference.shape();
            Version {
                treap,
                reference,
                shape,
                reference_shape,
            }
        }

        fn empty() -> Version {
            Version::new(Immutable::new(), reference::Immutable::new())
        }
    }

    /// The length of the longest path from the root, counted in nodes,
    /// of a treap given in pre-order.
    fn tallest_path(shape: &[NodeShape]) -> usize {
        let mut deepest = 0;
        let mut depth = 1;
        // The depths of the right children still to come.
        let mut pending: Vec<usize> = Vec::new();
        for node in shape {
            deepest = deepest.max(depth);
            if node.has_left {
                if node.has_right {
                    pending.push(depth + 1);
                }
                depth += 1;
            } else if node.has_right {
                depth += 1;
            } else {
                depth = pending.pop().unwrap_or(0);
            }
        }
        deepest
    }

    /// Each of the versions is the reference's version node for node:
    /// the same keys, values, priorities and sizes in the same shape.
    /// Each is still made of the nodes it was made of, which is what
    /// its holder sees.  And the versions share nodes exactly as the
    /// reference's do: a node is one node in two versions here when,
    /// and only when, it is one node in those two versions there.
    fn assert_versions_match<'a>(versions: impl IntoIterator<Item = &'a Version>, context: &str) {
        let mut here_of: BTreeMap<*const (), *const ()> = BTreeMap::new();
        let mut there_of: BTreeMap<*const (), *const ()> = BTreeMap::new();
        for (slot, version) in versions.into_iter().enumerate() {
            let shape = version.treap.shape();
            let reference_shape = version.reference.shape();
            assert_eq!(
                shape, version.shape,
                "{context}: version {slot} is no longer the nodes it was made of"
            );
            assert_eq!(
                reference_shape, version.reference_shape,
                "{context}: the reference's version {slot} changed"
            );
            assert_eq!(
                shape.len(),
                reference_shape.len(),
                "{context}: version {slot}"
            );
            assert_eq!(
                version.treap.len(),
                version.reference.len(),
                "{context}: version {slot}"
            );
            assert_eq!(
                version.treap.len(),
                shape.len(),
                "{context}: version {slot}"
            );
            assert_eq!(
                version.treap.size(),
                version.reference.size(),
                "{context}: version {slot}"
            );
            for (position, (here, there)) in shape.iter().zip(&reference_shape).enumerate() {
                assert_eq!(
                    (
                        here.key,
                        here.value,
                        here.priority,
                        here.size,
                        here.has_left,
                        here.has_right
                    ),
                    (
                        there.key,
                        there.value,
                        there.priority,
                        there.size,
                        there.has_left,
                        there.has_right
                    ),
                    "{context}: version {slot}, node {position} in pre-order"
                );
                assert_eq!(
                    *here_of.entry(there.address).or_insert(here.address),
                    here.address,
                    "{context}: version {slot}, node {position}: one node of the reference, \
                     shared between versions, is two nodes here"
                );
                assert_eq!(
                    *there_of.entry(here.address).or_insert(there.address),
                    there.address,
                    "{context}: version {slot}, node {position}: one node here, shared between \
                     versions, is two nodes in the reference"
                );
            }
        }
    }

    /// The version lists its tickets in key order, answers every index
    /// with the ticket at that place of the list, as the reference
    /// does, and keeps the heap property.
    fn assert_indexes_match(version: &Version, context: &str) {
        let mut listed: Vec<(Key, Value)> = Vec::new();
        version.treap.for_each(|key, value| {
            listed.push((*key, *value));
            true
        });
        let mut sorted: Vec<(Key, Value)> =
            version.shape.iter().map(|n| (n.key, n.value)).collect();
        sorted.sort_by(|a, b| compare_bytewise(&a.0, &b.0));
        assert_eq!(listed, sorted, "{context}: the in-order sequence");
        for (index, entry) in listed.iter().enumerate() {
            assert_eq!(
                version.treap.get_by_index(index),
                *entry,
                "{context}: index {index}"
            );
        }
        // The reference walks the same shape to an index, so a few
        // indexes compare the two walks.
        for index in (0..listed.len()).step_by(1 + listed.len() / 8) {
            assert_eq!(
                version.reference.get_by_index(index),
                listed[index],
                "{context}: the reference's index {index}"
            );
        }
        assert!(version.treap.heap_invariant_ok(), "{context}: the heap");
    }

    /// Where a run of operations takes its keys and its heights from.
    struct Profile {
        name: &'static str,
        /// The keys are the counters below this number, or ticket
        /// hashes when there is none.
        counters: Option<u32>,
        /// The height of a new ticket, given the counter its key is
        /// made of, or for a hash how many hashes came before it, and a
        /// random number.
        height: fn(u32, u32) -> u32,
        /// How many tickets the first version holds.
        seeded: usize,
        /// No version grows past this many tickets.
        most: usize,
        steps: usize,
        /// Whether the treap is one spine, as tall as it is large.
        spine: bool,
    }

    /// How many versions are alive at once.
    const LIVE_VERSIONS: usize = 5;

    /// The middle counter of the profiles whose heights rise or fall
    /// away from it.
    const MIDDLE: u32 = 120;

    const PROFILES: [Profile; 8] = [
        // Hashes at heights that rise as the chain's do, twenty
        // tickets to a height.
        Profile {
            name: "hashes at rising heights",
            counters: None,
            height: |serial, _| serial / 20,
            seeded: 60,
            most: 150,
            steps: 3000,
            spine: false,
        },
        // Hashes at a handful of heights, so most priorities tie.
        Profile {
            name: "hashes at four heights",
            counters: None,
            height: |_, random| random % 4,
            seeded: 60,
            most: 150,
            steps: 3000,
            spine: false,
        },
        // One spine to the right: the path of a descent is as long as
        // the treap is large.
        Profile {
            name: "counters at rising heights",
            counters: Some(2 * MIDDLE),
            height: |counter, _| counter,
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: true,
        },
        // One spine to the left.
        Profile {
            name: "counters at falling heights",
            counters: Some(2 * MIDDLE),
            height: |counter, _| 2 * MIDDLE - counter,
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: true,
        },
        // The middle counter at the root with a spine on each side
        // leading back towards it: removing it cascades through every
        // other node.
        Profile {
            name: "counters rising towards the middle",
            counters: Some(2 * MIDDLE),
            height: |counter, _| match counter.abs_diff(MIDDLE) {
                0 => 0,
                away => 2 * MIDDLE - away,
            },
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: false,
        },
        // The same with the heights falling towards the middle.
        Profile {
            name: "counters falling towards the middle",
            counters: Some(2 * MIDDLE),
            height: |counter, _| counter.abs_diff(MIDDLE),
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: false,
        },
        // Every priority ties.
        Profile {
            name: "counters at one height",
            counters: Some(2 * MIDDLE),
            height: |_, _| 7,
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: false,
        },
        Profile {
            name: "counters at three heights",
            counters: Some(2 * MIDDLE),
            height: |_, random| random % 3,
            seeded: MIDDLE as usize,
            most: usize::MAX,
            steps: 1200,
            spine: false,
        },
    ];

    /// What a run of operations did, to show that it did all of it.
    #[derive(Default, Debug)]
    struct Tally {
        inserted: usize,
        replaced: usize,
        replaced_alike: usize,
        removed: usize,
        refused: usize,
        missing: usize,
        looked_up: usize,
        largest: usize,
        tallest: usize,
    }

    fn random_value(rng: &mut SplitMix64, height: u32) -> Value {
        let flags = rng.next_u64();
        Value {
            height,
            missed: flags & 1 != 0,
            revoked: flags & 2 != 0,
            spent: flags & 4 != 0,
            expired: flags & 8 != 0,
        }
    }

    /// A long random run of puts, deletes and lookups, each applied to
    /// one of several live versions of the treap and to the reference's
    /// version beside it.  After every step every live version is
    /// compared with the reference's, and with them the version the
    /// step made.
    fn run_profile(profile: &Profile, rng: &mut SplitMix64, tally: &mut Tally) {
        let mut versions = alloc::vec![Version::empty()];
        // The hashes handed out so far.
        let mut hashes: Vec<Key> = Vec::new();
        for step in 0..profile.seeded + profile.steps {
            let context = alloc::format!("{}, step {step}", profile.name);
            // The first version is grown before the versions branch.
            let seeding = step < profile.seeded;
            let source = &versions[below(rng, versions.len())];
            let (treap, reference) = (source.treap.clone(), source.reference.clone());

            // A key the version holds, if it holds any, and one it
            // does not, with the height a ticket of that key has.  One
            // time in four the key it holds is the root's, whose
            // removal cascades the furthest.
            let present = (!source.shape.is_empty()).then(|| {
                let node = match below(rng, 4) {
                    0 => 0,
                    _ => below(rng, source.shape.len()),
                };
                source.shape[node].key
            });
            let absent = match profile.counters {
                Some(range) => {
                    let counter = (0..8)
                        .map(|_| rng.below(u64::from(range)) as u32)
                        .find(|counter| !reference.has(&counter_key(*counter)));
                    counter.map(|counter| (counter_key(counter), counter))
                }
                None => {
                    let mut key = random_key(rng);
                    if !hashes.is_empty() && below(rng, 2) == 0 {
                        // Share a prefix with a hash already handed
                        // out, so the later words of the key decide.
                        let other = hashes[below(rng, hashes.len())];
                        let shared = below(rng, 32);
                        key[..shared].copy_from_slice(&other[..shared]);
                    }
                    let serial = hashes.len() as u32;
                    hashes.push(key);
                    (!reference.has(&key)).then_some((key, serial))
                }
            };
            let absent = absent.map(|(key, seed)| {
                let height = (profile.height)(seed, rng.next_u64() as u32);
                (key, random_value(rng, height))
            });
            let room = treap.len() < profile.most;

            let operation = if seeding { 0 } else { below(rng, 10) };
            let made = match (operation, present, absent) {
                // Put a ticket the version does not hold.
                (0..=2, _, Some((key, value))) if room => {
                    tally.inserted += 1;
                    Some((treap.put(key, value), reference.put(key, value)))
                }
                // The same through the insert that refuses a key
                // already there, which is `Has` and then `Put`.
                (3 | 4, _, Some((key, value))) if room => {
                    tally.inserted += 1;
                    assert!(!reference.has(&key), "{context}");
                    let put = treap.put_new(key, value);
                    Some((
                        put.unwrap_or_else(|| panic!("{context}: refused an absent key")),
                        reference.put(key, value),
                    ))
                }
                // Put a ticket the version holds: the value is
                // replaced, at whatever height it carries, and the
                // node keeps its priority.  The insert that refuses a
                // key already there refuses it.
                (5, Some(key), _) => {
                    tally.replaced += 1;
                    tally.refused += 1;
                    // One time in four the value is the one the ticket
                    // holds already: the node and its ancestors are
                    // rebuilt all the same (immutable.go:154-184).
                    let value = match below(rng, 4) {
                        0 => {
                            tally.replaced_alike += 1;
                            reference.value(&key).expect("present")
                        }
                        _ => {
                            let height = rng.next_u64() as u32 % 200;
                            random_value(rng, height)
                        }
                    };
                    assert!(reference.has(&key), "{context}");
                    assert!(
                        treap.put_new(key, value).is_none(),
                        "{context}: inserted a key already there"
                    );
                    Some((treap.put(key, value), reference.put(key, value)))
                }
                // Delete a ticket the version holds.
                (6, Some(key), _) => {
                    tally.removed += 1;
                    Some((treap.delete(&key), reference.delete(&key)))
                }
                // The same through the removal that returns the value,
                // which is `Get`, `Has` and then `Delete`.
                (7, Some(key), _) => {
                    tally.removed += 1;
                    let (value, taken) = treap
                        .take(&key)
                        .unwrap_or_else(|| panic!("{context}: the key is there"));
                    assert_eq!(Some(value), reference.value(&key), "{context}");
                    assert!(reference.has(&key), "{context}");
                    Some((taken, reference.delete(&key)))
                }
                // Delete a ticket the version does not hold: the
                // version comes back as it is.
                (8, _, Some((key, _))) => {
                    tally.missing += 1;
                    assert!(reference.value(&key).is_none(), "{context}");
                    assert!(treap.take(&key).is_none(), "{context}");
                    Some((treap.delete(&key), reference.delete(&key)))
                }
                // Look tickets up.
                (_, present, absent) => {
                    for key in present.into_iter().chain(absent.map(|(key, _)| key)) {
                        tally.looked_up += 1;
                        assert_eq!(treap.has(&key), reference.has(&key), "{context}");
                        assert_eq!(treap.value(&key), reference.value(&key), "{context}");
                    }
                    None
                }
            };

            // The version the step made is not among the live ones yet;
            // the one it was made from, whose nodes it shares, still is.
            let made = made.map(|(treap, reference)| Version::new(treap, reference));
            assert_versions_match(versions.iter().chain(&made), &context);
            if let Some(made) = made {
                assert_indexes_match(&made, &context);
                tally.largest = tally.largest.max(made.shape.len());
                tally.tallest = tally.tallest.max(tallest_path(&made.shape));
                versions.push(made);
                if seeding {
                    versions.swap_remove(0);
                } else if versions.len() > LIVE_VERSIONS {
                    // Any of them goes, the newest included.
                    versions.swap_remove(below(rng, versions.len()));
                }
            }
            // What the holder of each older version sees.
            for version in &versions {
                if !version.shape.is_empty() {
                    let index = below(rng, version.shape.len());
                    assert_eq!(
                        version.treap.get_by_index(index),
                        version.reference.get_by_index(index),
                        "{context}: index {index}"
                    );
                }
            }
        }
    }

    /// Every put, delete and lookup leaves the treap as the
    /// implementation it replaced leaves it: the same nodes in the same
    /// shape, the same nodes copied and the same nodes shared with the
    /// versions still alive, and the same ticket at every index.
    #[test]
    fn every_operation_builds_what_the_reference_builds() {
        let mut rng = SplitMix64::from_entropy("ticket treap against its reference");
        for profile in &PROFILES {
            let mut tally = Tally::default();
            run_profile(profile, &mut rng, &mut tally);
            // Each kind of operation ran, on treaps of some size.
            assert!(
                tally.inserted >= 300
                    && tally.replaced >= 50
                    && tally.replaced_alike >= 5
                    && tally.removed >= 100
                    && tally.refused >= 50
                    && tally.missing >= 50
                    && tally.looked_up >= 50
                    && tally.largest >= 50,
                "{}: {tally:?}",
                profile.name
            );
            // A spine is a path longer than a stack holds in place.
            assert!(
                !profile.spine || tally.tallest > NODE_STACK_INLINE + NODE_STACK_INLINE / 2,
                "{}: {tally:?}",
                profile.name
            );
        }
    }

    /// The treap and the reference holding the counters given at the
    /// heights given, inserted in the order of the counters.
    fn version_of_counters(
        counters: core::ops::RangeInclusive<u32>,
        height: fn(u32) -> u32,
    ) -> Version {
        let mut treap = Immutable::new();
        let mut reference = reference::Immutable::new();
        for counter in counters {
            let value = Value::new(height(counter));
            treap = treap.put(counter_key(counter), value);
            reference = reference.put(counter_key(counter), value);
        }
        Version::new(treap, reference)
    }

    /// A path longer than the stack holds in place is recorded whole:
    /// every put and delete at the far end of a spine of 200 nodes
    /// builds what the reference builds.
    #[test]
    fn a_path_longer_than_the_stack_holds_in_place_is_rebuilt_whole() {
        const COUNT: u32 = 200;
        assert!(COUNT as usize > 2 * NODE_STACK_INLINE);
        // The counters from 1 at heights from 1, with the counter at
        // the end of the spine and the one that goes below it.
        struct Spine {
            name: &'static str,
            height: fn(u32) -> u32,
            deepest: u32,
            beyond: u32,
        }
        let spines = [
            Spine {
                name: "to the right",
                height: |counter| counter,
                deepest: COUNT,
                beyond: COUNT + 1,
            },
            Spine {
                name: "to the left",
                height: |counter| COUNT + 1 - counter,
                deepest: 1,
                beyond: 0,
            },
        ];
        for Spine {
            name,
            height,
            deepest,
            beyond,
        } in spines
        {
            let spine = version_of_counters(1..=COUNT, height);
            assert_eq!(
                tallest_path(&spine.shape),
                COUNT as usize,
                "one spine {name}"
            );
            let deepest = counter_key(deepest);
            assert_eq!(
                spine.shape.last().expect("nodes").key,
                deepest,
                "the end of the spine {name}"
            );
            let (treap, reference) = (&spine.treap, &spine.reference);

            let value = Value {
                revoked: true,
                ..Value::new(3)
            };
            let replaced = Version::new(treap.put(deepest, value), reference.put(deepest, value));
            // The value the node holds already, put again: the node
            // and the path above it are rebuilt all the same
            // (immutable.go:154-184).
            let held = reference.value(&deepest).expect("present");
            let rewritten = Version::new(treap.put(deepest, held), reference.put(deepest, held));
            let deleted = Version::new(treap.delete(&deepest), reference.delete(&deepest));
            let (taken_value, taken) = treap.take(&deepest).expect("present");
            assert_eq!(Some(taken_value), reference.value(&deepest));
            let taken = Version::new(taken, reference.delete(&deepest));
            // A ticket that goes below the deepest node and stays
            // there, and one low enough to climb the whole spine.
            let beyond = counter_key(beyond);
            let mut made = alloc::vec![replaced, rewritten, deleted, taken];
            for value in [Value::new(COUNT + 5), Value::new(0)] {
                let put = Version::new(treap.put(beyond, value), reference.put(beyond, value));
                // Climbing, it ends above the spine it went down.
                assert_eq!(put.shape[0].key == beyond, value.height == 0, "{name}");
                assert_eq!(tallest_path(&put.shape), COUNT as usize + 1, "{name}");
                made.push(put);
                made.push(Version::new(
                    treap.put_new(beyond, value).expect("absent"),
                    reference.put(beyond, value),
                ));
            }
            made.push(spine);
            assert_versions_match(&made, name);
            for version in &made {
                assert_indexes_match(version, name);
            }
        }
    }

    /// A cascade longer than the stack holds in place is folded back
    /// whole: removing the root from between two spines of a hundred
    /// nodes, each leading back towards it, builds what the reference
    /// builds.
    #[test]
    fn a_cascade_longer_than_the_stack_holds_in_place_is_folded_whole() {
        const COUNT: u32 = 200;
        const ROOT: u32 = COUNT / 2;
        let between = version_of_counters(0..=COUNT, |counter| match counter.abs_diff(ROOT) {
            0 => 0,
            away => COUNT - away,
        });
        let root = &between.shape[0];
        assert_eq!(root.key, counter_key(ROOT));
        // Every other node is on one of the two spines the cascade
        // walks: the left subtree runs down to the right, the right
        // subtree down to the left.
        let on_a_spine = between.shape[1..]
            .iter()
            .filter(|node| {
                if compare_bytewise(&node.key, &root.key) == Ordering::Less {
                    !node.has_left
                } else {
                    !node.has_right
                }
            })
            .count();
        assert_eq!(on_a_spine, COUNT as usize);
        assert!(on_a_spine > 2 * NODE_STACK_INLINE);

        let (treap, reference) = (&between.treap, &between.reference);
        let deleted = Version::new(treap.delete(&root.key), reference.delete(&root.key));
        let (value, taken) = treap.take(&root.key).expect("present");
        assert_eq!(Some(value), reference.value(&root.key));
        let taken = Version::new(taken, reference.delete(&root.key));
        let made = [between, deleted, taken];
        assert_versions_match(&made, "the root removed");
        for version in &made {
            assert_indexes_match(version, "the root removed");
        }
    }
}
