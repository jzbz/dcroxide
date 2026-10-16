// SPDX-License-Identifier: ISC
//! `is_majority_version` answers what dcrd's `isMajorityVersion`
//! answers (`internal/blockchain/chain.go:558-572`) while looking at no
//! more blocks than dcrd does, and at fewer once the required number is
//! out of reach.
//!
//! dcrd's loop is transcribed statement for statement below and run
//! over the same block versions, together with the plain count the rule
//! describes: of the blocks in the window, at least the required number
//! meet the minimum version.  The port is asked through a list-backed
//! view and through the block index view, which walks parent links.

// Test-harness arithmetic over bounded heights and counts.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};

use dcroxide_blockchain::blockindex::{NodeId, NodeStore};
use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::stakever::{VersionChainView, VersionNode, is_majority_version};
use dcroxide_chaincfg::{Params, mainnet_params};
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::BlockHeader;

/// dcrd's `isMajorityVersion` over the block versions from the start
/// node back to the first block: the answer, and how many blocks the
/// loop looked at.
fn dcrd_is_majority_version(
    versions_newest_first: &[i32],
    min_ver: i32,
    num_to_check: u64,
    num_required: u64,
) -> (bool, u64) {
    let mut num_found = 0u64;
    let mut iter_node = 0usize;
    let mut i = 0u64;
    while i < num_to_check && num_found < num_required && iter_node < versions_newest_first.len() {
        // This node has a version that is at least the minimum version.
        if versions_newest_first[iter_node] >= min_ver {
            num_found += 1;
        }

        iter_node += 1;
        i += 1;
    }
    (num_found >= num_required, i)
}

/// The rule without any walk: whether at least the required number of
/// the blocks in the window meet the minimum version.
fn counted(
    versions_newest_first: &[i32],
    min_ver: i32,
    num_to_check: u64,
    num_required: u64,
) -> bool {
    let window = usize::try_from(num_to_check)
        .unwrap_or(usize::MAX)
        .min(versions_newest_first.len());
    let met = versions_newest_first[..window]
        .iter()
        .filter(|version| **version >= min_ver)
        .count();
    met as u64 >= num_required
}

/// A branch held as a list of block versions by height, served through
/// the trait's height-by-height default walk, counting the blocks a
/// walk looks at.
struct Listed<'a> {
    versions: &'a [i32],
    visited: Cell<u64>,
}

impl VersionChainView for Listed<'_> {
    fn node(&self, height: i64) -> Option<VersionNode> {
        let version = *self.versions.get(usize::try_from(height).ok()?)?;
        self.visited.set(self.visited.get() + 1);
        Some(VersionNode {
            height,
            block_version: version,
            ..VersionNode::default()
        })
    }
}

/// The block index view of a branch, counting the blocks a walk looks
/// at.
struct Counted<'a> {
    view: NodeBranchView<'a>,
    visited: Cell<u64>,
}

impl VersionChainView for Counted<'_> {
    fn node(&self, height: i64) -> Option<VersionNode> {
        VersionChainView::node(&self.view, height)
    }

    fn walk_back(&self, height: i64, visit: &mut dyn FnMut(&VersionNode) -> bool) {
        self.view.walk_back(height, &mut |node| {
            self.visited.set(self.visited.get() + 1);
            visit(node)
        });
    }
}

/// A branch of blocks with the given versions, the first at height
/// zero, as a list and as block index nodes.
struct Branch {
    versions: Vec<i32>,
    store: NodeStore,
    tip: NodeId,
    /// The network parameters, whose window each check sets.
    params: RefCell<Params>,
}

impl Branch {
    fn new(versions: Vec<i32>) -> Branch {
        let mut store = NodeStore::new();
        let mut parent: Option<NodeId> = None;
        for (height, version) in versions.iter().enumerate() {
            let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
            header.height = height as u32;
            header.version = *version;
            if let Some(parent) = parent {
                header.prev_block = store.node(parent).hash;
            }
            parent = Some(store.new_node(&header, parent));
        }
        Branch {
            versions,
            store,
            tip: parent.expect("at least one block"),
            params: RefCell::new(mainnet_params()),
        }
    }

    /// The block versions from the start back to the first block.
    fn newest_first(&self, start: i64) -> Vec<i32> {
        self.versions[..=start as usize]
            .iter()
            .rev()
            .copied()
            .collect()
    }

    /// Ask the port through both views and hold each answer against
    /// dcrd's loop and the plain count; returns the answer and how many
    /// blocks the block index view's walk looked at.
    fn check(
        &self,
        start: i64,
        min_ver: i32,
        num_to_check: u64,
        num_required: u64,
        what: &str,
    ) -> (bool, u64) {
        self.params.borrow_mut().block_upgrade_num_to_check = num_to_check;
        let params = &*self.params.borrow();
        let newest_first = self.newest_first(start);
        let (want, dcrd_visited) =
            dcrd_is_majority_version(&newest_first, min_ver, num_to_check, num_required);
        assert_eq!(
            want,
            counted(&newest_first, min_ver, num_to_check, num_required),
            "{what}: dcrd's loop against the plain count"
        );

        let listed = Listed {
            versions: &self.versions,
            visited: Cell::new(0),
        };
        assert_eq!(
            is_majority_version(&listed, min_ver, Some(start), num_required, params),
            want,
            "{what}: by height"
        );

        // The view's tip is the newest block, so a start below it walks
        // a branch that goes on above the start.
        let indexed = Counted {
            view: NodeBranchView {
                store: &self.store,
                tip: self.tip,
            },
            visited: Cell::new(0),
        };
        assert_eq!(
            is_majority_version(&indexed, min_ver, Some(start), num_required, params),
            want,
            "{what}: by parent links"
        );
        assert_eq!(
            listed.visited.get(),
            indexed.visited.get(),
            "{what}: blocks looked at through each view"
        );
        assert!(
            indexed.visited.get() <= dcrd_visited,
            "{what}: looked at {} blocks where dcrd looks at {dcrd_visited}",
            indexed.visited.get()
        );
        (want, indexed.visited.get())
    }
}

/// The main network's two walks over a branch longer than the window:
/// the old block version check needs 950 of 1,000 and the stake version
/// enforcement 750 of 1,000 (`validate.rs`, dcrd `validate.go:1060` and
/// `:1525`).
#[test]
fn the_main_network_walks_stop_where_the_answer_is_settled() {
    let params = mainnet_params();
    let (to_check, reject, enforce) = (
        params.block_upgrade_num_to_check,
        params.block_reject_num_required,
        params.block_enforce_num_required,
    );
    assert_eq!((to_check, reject, enforce), (1000, 950, 750));

    // No block meets the minimum: the 51st miss puts 950 out of reach,
    // and the 251st puts 750 out of reach.
    let old = Branch::new(vec![3i32; 1500]);
    let tip = 1499;
    assert_eq!(
        old.check(tip, 4, to_check, reject, "none of 950"),
        (false, 51)
    );
    assert_eq!(
        old.check(tip, 4, to_check, enforce, "none of 750"),
        (false, 251)
    );

    // Every block meets the minimum: the walks stop at the required
    // number, as dcrd's do.
    assert_eq!(
        old.check(tip, 3, to_check, reject, "all of 950"),
        (true, 950)
    );
    assert_eq!(
        old.check(tip, 3, to_check, enforce, "all of 750"),
        (true, 750)
    );

    // Exactly 950 of the newest 1,000 meet it, the 50 that do not being
    // the newest: every block of the window is looked at.  With one
    // more miss at the far end of the window the answer flips on the
    // last block looked at.
    let mut versions = vec![4i32; 1500];
    for version in versions.iter_mut().rev().take(50) {
        *version = 3;
    }
    assert_eq!(
        Branch::new(versions.clone()).check(tip, 4, to_check, reject, "exactly 950"),
        (true, 1000)
    );
    versions[500] = 3;
    assert_eq!(
        Branch::new(versions).check(tip, 4, to_check, reject, "one short of 950"),
        (false, 1000)
    );
}

/// The edges of the window and of the branch, with a window of 100.
#[test]
fn the_edges_of_the_window_and_of_the_branch() {
    // A branch of 60 blocks, shorter than the window, all meeting the
    // minimum: 60 can be reached and 61 cannot, though the bound of the
    // window alone would still allow it, so the walk runs to the first
    // block.
    let short = Branch::new(vec![5i32; 60]);
    assert_eq!(
        short.check(59, 5, 100, 60, "all of a short branch"),
        (true, 60)
    );
    assert_eq!(
        short.check(59, 5, 100, 61, "more than a short branch"),
        (false, 60)
    );
    assert_eq!(
        short.check(59, 5, 100, 75, "past the first block"),
        (false, 60)
    );

    // A start below the tip whose window runs past the first block.
    assert_eq!(
        short.check(9, 5, 100, 10, "ten from the first block"),
        (true, 10)
    );
    assert_eq!(
        short.check(9, 5, 100, 11, "eleven from the first block"),
        (false, 10)
    );
    assert_eq!(
        short.check(0, 5, 100, 1, "the first block alone"),
        (true, 1)
    );

    // Nothing required is always met, and more than the window holds
    // never is: neither looks at a block.
    assert_eq!(short.check(59, 5, 100, 0, "nothing required"), (true, 0));
    assert_eq!(
        short.check(59, 5, 100, 101, "more than the window"),
        (false, 0)
    );
    assert_eq!(
        short.check(59, 5, 0, 0, "an empty window, nothing required"),
        (true, 0)
    );
    assert_eq!(short.check(59, 5, 0, 1, "an empty window"), (false, 0));

    // A whole window required: the first miss settles it.
    let mut versions = vec![5i32; 300];
    versions[296] = 4;
    let one_miss = Branch::new(versions);
    assert_eq!(
        one_miss.check(299, 5, 100, 100, "all of the window"),
        (false, 4)
    );
    assert_eq!(one_miss.check(299, 5, 100, 99, "all but one"), (true, 100));

    // No start at all, as for the block after no block.
    let mut params = mainnet_params();
    params.block_upgrade_num_to_check = 100;
    let listed = Listed {
        versions: &short.versions,
        visited: Cell::new(0),
    };
    assert!(!is_majority_version(&listed, 5, None, 1, &params));
    assert!(is_majority_version(&listed, 5, None, 0, &params));
    assert_eq!(listed.visited.get(), 0);
}

/// Random version sequences, windows, required numbers and starts,
/// with the share of blocks that meet the minimum drawn near the
/// required share as often as not, so that both answers turn up close
/// to the threshold.
#[test]
fn random_sequences_match_dcrds_walk() {
    let mut rng = SplitMix64::from_entropy("majority version differential");
    let (mut met, mut unmet, mut shorter) = (0u32, 0u32, 0u32);

    for round in 0..400 {
        let len = 1 + rng.below(260) as usize;
        let num_to_check = rng.below(130);
        let num_required = rng.below(num_to_check + 12);

        // The chance in 1,000 that a block meets the minimum version.
        let share = if rng.below(2) == 0 && num_to_check > 0 {
            (num_required * 1000 / num_to_check).min(1000)
        } else {
            rng.below(1001)
        };
        let branch = Branch::new(
            (0..len)
                .map(|_| if rng.below(1000) < share { 7 } else { 6 })
                .collect(),
        );

        for _ in 0..12 {
            let start = match rng.below(4) {
                0 => len as i64 - 1,
                _ => rng.below(len as u64) as i64,
            };
            // Mostly the version the sequence divides on, sometimes one
            // every block meets or none does.
            let min_ver = match rng.below(8) {
                0 => 6,
                1 => 8,
                _ => 7,
            };
            let what = format!(
                "round {round}: {len} blocks, start {start}, minimum {min_ver}, \
                 {num_required} of {num_to_check}"
            );
            let (_, dcrd_visited) = dcrd_is_majority_version(
                &branch.newest_first(start),
                min_ver,
                num_to_check,
                num_required,
            );
            let (got, visited) = branch.check(start, min_ver, num_to_check, num_required, &what);
            if got {
                met += 1;
                // A met majority is found on the same block as dcrd's.
                assert_eq!(visited, dcrd_visited, "{what}");
            } else {
                unmet += 1;
            }
            shorter += u32::from(visited < dcrd_visited);
        }
    }

    // Both answers are reached often, and so is the shorter walk.
    assert!(met > 300, "{met} majorities met");
    assert!(unmet > 300, "{unmet} majorities not met");
    assert!(shorter > 300, "{shorter} walks shorter than dcrd's");
}
