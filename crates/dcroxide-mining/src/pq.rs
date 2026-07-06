// SPDX-License-Identifier: ISC

//! The transaction priority queue (dcrd `txpriorityqueue.go`),
//! including a faithful port of Go's `container/heap` sift
//! operations so pop order matches dcrd exactly, including among
//! equal elements.

use alloc::rc::Rc;
use alloc::vec::Vec;

use dcroxide_stake::TxType;

use crate::types::TxDesc;

/// A transaction along with the information needed to prioritize it
/// (dcrd `txPrioItem`).
#[derive(Clone, Debug)]
pub struct TxPrioItem {
    /// The transaction descriptor.
    pub tx_desc: Rc<TxDesc>,
    /// The transaction type.
    pub tx_type: TxType,
    /// Whether the transaction is an automatic revocation.
    pub auto_revocation: bool,
    /// The transaction fee in atoms.
    pub fee: i64,
    /// The input-age based priority.
    pub priority: f64,
    /// The fee in atoms per kilobyte.
    pub fee_per_kb: f64,
}

/// The stake priority used to sort stake transactions by importance
/// (dcrd `stakePriority`): votes (3) over automatic revocations (2)
/// over tickets (1) over regular transactions and revocations (0).
pub type StakePriority = i32;

/// The stake priority for a transaction type (dcrd
/// `txStakePriority`).
pub fn tx_stake_priority(tx_type: TxType, auto_revocation: bool) -> StakePriority {
    match () {
        _ if tx_type == TxType::SSGen => 3,
        _ if tx_type == TxType::SSRtx && auto_revocation => 2,
        _ if tx_type == TxType::SStx => 1,
        _ => 0,
    }
}

/// Compare the stake priority of two items: 1 when i > j, 0 when
/// equal, -1 when i < j (dcrd `compareStakePriority`).
pub fn compare_stake_priority(i: &TxPrioItem, j: &TxPrioItem) -> i32 {
    let i_prio = tx_stake_priority(i.tx_type, i.auto_revocation);
    let j_prio = tx_stake_priority(j.tx_type, j.auto_revocation);
    if i_prio > j_prio {
        return 1;
    }
    if i_prio < j_prio {
        return -1;
    }
    0
}

/// Sort by stake priority, then fees per kilobyte, then transaction
/// priority (dcrd `txPQByStakeAndFee`).
pub fn tx_pq_by_stake_and_fee(pq: &TxPriorityQueue, i: usize, j: usize) -> bool {
    let cmp = compare_stake_priority(&pq.items[i], &pq.items[j]);
    if cmp == 1 {
        return true;
    }
    if cmp == -1 {
        return false;
    }

    // Using > so that pop gives the highest fee item as opposed to
    // the lowest.  Sort by fee first, then priority.
    if pq.items[i].fee_per_kb == pq.items[j].fee_per_kb {
        return pq.items[i].priority > pq.items[j].priority;
    }

    pq.items[i].fee_per_kb > pq.items[j].fee_per_kb
}

/// The compare function type for the queue (dcrd
/// `txPriorityQueueLessFunc`).
pub type TxPriorityQueueLessFunc = fn(&TxPriorityQueue, usize, usize) -> bool;

/// A priority queue of prioritized transactions with an arbitrary
/// compare function (dcrd `txPriorityQueue` over Go's
/// `container/heap`).
pub struct TxPriorityQueue {
    less_func: TxPriorityQueueLessFunc,
    /// The heap-ordered items.
    pub items: Vec<TxPrioItem>,
}

impl TxPriorityQueue {
    /// A new priority queue reserving the given space, ordered by the
    /// provided compare function (dcrd `newTxPriorityQueue`).
    pub fn new(reserve: usize, less_func: TxPriorityQueueLessFunc) -> TxPriorityQueue {
        TxPriorityQueue {
            less_func,
            items: Vec::with_capacity(reserve),
        }
    }

    /// The number of items in the queue (dcrd `Len`).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn less(&self, i: usize, j: usize) -> bool {
        (self.less_func)(self, i, j)
    }

    /// Go's `container/heap` sift-up.
    fn up(&mut self, mut j: usize) {
        while j > 0 {
            let i = (j - 1) / 2; // parent
            if i == j || !self.less(j, i) {
                break;
            }
            self.items.swap(i, j);
            j = i;
        }
    }

    /// Go's `container/heap` sift-down.
    fn down(&mut self, i0: usize, n: usize) -> bool {
        let mut i = i0;
        loop {
            let j1 = 2 * i + 1;
            if j1 >= n {
                break;
            }
            let mut j = j1; // left child
            let j2 = j1 + 1;
            if j2 < n && self.less(j2, j1) {
                j = j2; // right child
            }
            if !self.less(j, i) {
                break;
            }
            self.items.swap(i, j);
            i = j;
        }
        i > i0
    }

    /// Change the compare function and re-establish the heap ordering
    /// (dcrd `SetLessFunc`, which invokes `heap.Init`).
    pub fn set_less_func(&mut self, less_func: TxPriorityQueueLessFunc) {
        self.less_func = less_func;
        // heap.Init.
        let n = self.items.len();
        for i in (0..n / 2).rev() {
            self.down(i, n);
        }
    }

    /// Push an item onto the queue (Go `heap.Push`).
    pub fn push(&mut self, item: TxPrioItem) {
        self.items.push(item);
        self.up(self.items.len() - 1);
    }

    /// Pop the highest priority item from the queue (Go `heap.Pop`).
    pub fn pop(&mut self) -> Option<TxPrioItem> {
        if self.items.is_empty() {
            return None;
        }
        let n = self.items.len() - 1;
        self.items.swap(0, n);
        self.down(0, n);
        self.items.pop()
    }
}
