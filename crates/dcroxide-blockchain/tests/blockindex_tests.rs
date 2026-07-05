// SPDX-License-Identifier: ISC
//! dcrd's own block index and chain view test battery
//! (blockindex_test.go and chainview_test.go at release-v2.1.5) ported
//! over the arena-based [`NodeStore`]/[`BlockIndex`]/[`NodeChainView`]:
//! header reconstruction, past median times, chain tip tracking, the
//! ancestor skip list, ancestor relationships, best candidate
//! comparison, view containment/next/fork/locators, tip switching, and
//! empty-view behavior.

// Test-harness arithmetic over bounded lengths; the fake-node helper
// mirrors dcrd's newFakeNode signature.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

use core::str::FromStr;

use dcroxide_blockchain::blockindex::{
    BlockIndex, BlockStatus, NodeId, NodeStore, compare_hashes_as_uint256_le,
};
use dcroxide_blockchain::chainview_nodes::{BlockLocator, NodeChainView};
use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::BlockHeader;

/// A deterministic stand-in for dcrd's use of rand for fake nonces.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn zero_header() -> BlockHeader {
    BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0
}

/// Create a fake node like dcrd's `newFakeNode`: a header with the
/// given fields, marked stored + validated and fully linked when the
/// parent is.
fn new_fake_node(
    store: &mut NodeStore,
    index: &mut BlockIndex,
    parent: Option<NodeId>,
    block_version: i32,
    stake_version: u32,
    bits: u32,
    timestamp: i64,
    nonce: u32,
) -> NodeId {
    let (prev_block, height) = match parent {
        Some(p) => {
            let n = index_node_fields(store, p);
            (n.0, (n.1 + 1) as u32)
        }
        None => (Hash([0u8; 32]), 0),
    };
    let mut header = zero_header();
    header.version = block_version;
    header.prev_block = prev_block;
    header.vote_bits = 0x01;
    header.bits = bits;
    header.height = height;
    header.timestamp = timestamp as u32;
    header.nonce = nonce;
    header.stake_version = stake_version;
    let id = store.new_node(&header, parent);
    let parent_linked = parent.is_none_or(|p| store.node(p).is_fully_linked);
    {
        let n = store.node_mut(id);
        n.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
        n.is_fully_linked = parent_linked;
    }
    let _ = index;
    id
}

fn index_node_fields(store: &NodeStore, id: NodeId) -> (Hash, i64) {
    let n = store.node(id);
    (n.hash, n.height)
}

/// dcrd `chainedFakeNodes`: a chain of fake nodes each one second
/// apart starting from the parent's timestamp (or a fixed base).
fn chained_fake_nodes(
    store: &mut NodeStore,
    index: &mut BlockIndex,
    parent: Option<NodeId>,
    num_nodes: usize,
    rng: &mut Lcg,
) -> Vec<NodeId> {
    let mut nodes = Vec::with_capacity(num_nodes);
    let mut tip = parent;
    let mut block_time = match tip {
        Some(t) => store.node(t).timestamp,
        None => 1_500_000_000,
    };
    for _ in 0..num_nodes {
        block_time += 1;
        let nonce = rng.next() as u32;
        let node = new_fake_node(store, index, tip, 1, 1, 0, block_time, nonce);
        tip = Some(node);
        nodes.push(node);
    }
    nodes
}

fn branch_tip(nodes: &[NodeId]) -> NodeId {
    *nodes.last().expect("non-empty branch")
}

/// dcrd `TestBlockNodeHeader`: the node must reconstruct the exact
/// header it was created from, including the previous block hash.
#[test]
fn block_node_header() {
    let mut store = NodeStore::new();
    let mut header = zero_header();
    header.version = 6;
    header.vote_bits = 0x2f;
    header.final_state = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    header.voters = 5;
    header.fresh_stake = 4;
    header.revocations = 3;
    header.pool_size = 10101;
    header.bits = 0x1d00ffff;
    header.sbits = 12345678;
    header.height = 0;
    header.size = 393216;
    header.timestamp = 1518101194;
    header.nonce = 0xdeadbeef;
    header.extra_data = [0x17; 32];
    header.stake_version = 7;
    let genesis = store.new_node(&header, None);
    assert_eq!(store.header(genesis), header, "genesis header round trip");

    let mut child = header;
    child.prev_block = store.node(genesis).hash;
    child.height = 1;
    child.nonce = 1;
    let child_id = store.new_node(&child, Some(genesis));
    assert_eq!(store.header(child_id), child, "child header round trip");
}

/// dcrd `TestCalcPastMedianTime` over a genesis timestamp of
/// 2018-01-01 00:00:00 UTC followed by the test timestamps.
#[test]
fn calc_past_median_time() {
    let tests: &[(&str, &[i64], i64)] = &[
        ("one block", &[1517188771], 1517188771),
        (
            "two blocks, in order",
            &[1517188771, 1517188831],
            1517188771,
        ),
        (
            "three blocks, in order",
            &[1517188771, 1517188831, 1517188891],
            1517188831,
        ),
        (
            "three blocks, out of order",
            &[1517188771, 1517188891, 1517188831],
            1517188831,
        ),
        (
            "four blocks, in order",
            &[1517188771, 1517188831, 1517188891, 1517188951],
            1517188831,
        ),
        (
            "four blocks, out of order",
            &[1517188831, 1517188771, 1517188951, 1517188891],
            1517188831,
        ),
        (
            "eleven blocks, in order",
            &[
                1517188771, 1517188831, 1517188891, 1517188951, 1517189011, 1517189071, 1517189131,
                1517189191, 1517189251, 1517189311, 1517189371,
            ],
            1517189071,
        ),
        (
            "eleven blocks, out of order",
            &[
                1517188831, 1517188771, 1517188891, 1517189011, 1517188951, 1517189071, 1517189131,
                1517189191, 1517189251, 1517189371, 1517189311,
            ],
            1517189071,
        ),
        (
            "fifteen blocks, in order",
            &[
                1517188771, 1517188831, 1517188891, 1517188951, 1517189011, 1517189071, 1517189131,
                1517189191, 1517189251, 1517189311, 1517189371, 1517189431, 1517189491, 1517189551,
                1517189611,
            ],
            1517189311,
        ),
        (
            "fifteen blocks, out of order",
            &[
                1517188771, 1517188891, 1517188831, 1517189011, 1517188951, 1517189131, 1517189071,
                1517189251, 1517189191, 1517189371, 1517189311, 1517189491, 1517189431, 1517189611,
                1517189551,
            ],
            1517189311,
        ),
    ];

    for (name, timestamps, expected) in tests {
        let mut store = NodeStore::new();
        let mut index = BlockIndex::new();
        // The genesis timestamp corresponds to 2018-01-01 00:00:00 UTC.
        let mut node = new_fake_node(&mut store, &mut index, None, 1, 0, 0, 1514764800, 0);
        for (i, &timestamp) in timestamps.iter().enumerate() {
            node = new_fake_node(
                &mut store,
                &mut index,
                Some(node),
                0,
                0,
                0,
                timestamp,
                i as u32 + 1,
            );
        }
        assert_eq!(
            store.calc_past_median_time(node),
            *expected,
            "{name}: mismatched timestamps"
        );
    }
}

/// dcrd `TestChainTips`: seven branches with one duplicate-extended
/// tip excluded.
#[test]
fn chain_tips() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x746970);
    let genesis = new_fake_node(&mut store, &mut index, None, 1, 0, 0, 1514764800, 0);
    index.add_node(&store, genesis);

    let mut branches: Vec<Vec<NodeId>> = Vec::new();
    branches.push(chained_fake_nodes(
        &mut store,
        &mut index,
        Some(genesis),
        4,
        &mut rng,
    ));
    let b1 = chained_fake_nodes(&mut store, &mut index, Some(branches[0][0]), 25, &mut rng);
    branches.push(b1);
    let b2 = chained_fake_nodes(&mut store, &mut index, Some(branches[1][0]), 3, &mut rng);
    branches.push(b2);
    let b3 = chained_fake_nodes(&mut store, &mut index, Some(branches[0][0]), 25, &mut rng);
    branches.push(b3);
    let b4 = chained_fake_nodes(&mut store, &mut index, Some(genesis), 1, &mut rng);
    branches.push(b4);
    let b5 = chained_fake_nodes(&mut store, &mut index, Some(genesis), 1, &mut rng);
    branches.push(b5);
    let b6 = chained_fake_nodes(&mut store, &mut index, Some(branches[4][0]), 1, &mut rng);
    branches.push(b6);
    for branch in &branches {
        for &node in branch {
            index.add_node(&store, node);
        }
    }

    // Branch 4's tip was extended by branch 6 and is not a tip.
    let mut expected: Vec<NodeId> = branches
        .iter()
        .map(|b| branch_tip(b))
        .filter(|&t| t != branch_tip(&branches[4]))
        .collect();
    expected.sort_unstable();

    let mut tips: Vec<NodeId> = Vec::new();
    index
        .for_each_chain_tip::<()>(|tip| {
            tips.push(tip);
            Ok(())
        })
        .unwrap();
    tips.sort_unstable();
    assert_eq!(tips, expected, "chain tips mismatch");
}

/// dcrd `TestAncestorSkipList` over a 250,000 node chain with 2,500
/// random probes.
#[test]
fn ancestor_skip_list() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x736b6970);
    let mut nodes = Vec::with_capacity(250_000);
    let mut parent = None;
    for i in 0..250_000u32 {
        let node = new_fake_node(&mut store, &mut index, parent, 1, 1, 0, 1_500_000_000, i);
        nodes.push(node);
        parent = Some(node);
    }

    // Every node's skip pointer must point at the exact node at the
    // calculated skip height below it.
    for (i, &node) in nodes.iter().enumerate().skip(1) {
        let skip = store.node(node).skip_to_ancestor.expect("skip pointer");
        let skip_height = store.node(skip).height;
        assert!(
            skip_height < i as i64,
            "skip height {skip_height} not below {i}"
        );
        assert_eq!(skip, nodes[skip_height as usize], "wrong skip node at {i}");
    }

    let tip = branch_tip(&nodes);
    for _ in 0..2_500 {
        let start_height = rng.below(nodes.len() as u64 - 1) as i64;
        let start_node = nodes[start_height as usize];
        assert_eq!(store.ancestor(tip, start_height), Some(start_node));
        assert_eq!(store.ancestor(start_node, 0), Some(nodes[0]));
        let end_height = rng.below(start_height as u64 + 1) as i64;
        assert_eq!(
            store.ancestor(start_node, end_height),
            Some(nodes[end_height as usize])
        );
    }
}

/// dcrd `TestIsAncestorOf` over six branches.
#[test]
fn is_ancestor_of() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x616e63);
    let genesis = new_fake_node(&mut store, &mut index, None, 1, 0, 0, 1514764800, 0);
    let b0 = chained_fake_nodes(&mut store, &mut index, Some(genesis), 4, &mut rng);
    let b1 = chained_fake_nodes(&mut store, &mut index, Some(b0[0]), 8, &mut rng);
    let b2 = chained_fake_nodes(&mut store, &mut index, Some(b1[0]), 3, &mut rng);
    let b3 = chained_fake_nodes(&mut store, &mut index, Some(b0[0]), 8, &mut rng);
    let b4 = chained_fake_nodes(&mut store, &mut index, Some(genesis), 1, &mut rng);
    let b5 = chained_fake_nodes(&mut store, &mut index, Some(genesis), 1, &mut rng);

    let tests: &[(&str, NodeId, NodeId, bool)] = &[
        (
            "node is ancestor of itself",
            branch_tip(&b0),
            branch_tip(&b0),
            true,
        ),
        (
            "different branch tips at same height",
            branch_tip(&b1),
            branch_tip(&b3),
            false,
        ),
        (
            "different branch tips at different heights",
            branch_tip(&b1),
            branch_tip(&b2),
            false,
        ),
        (
            "genesis is ancestor of all blocks (via branch 4)",
            genesis,
            branch_tip(&b4),
            true,
        ),
        (
            "genesis is ancestor of all blocks (via branch 5)",
            genesis,
            branch_tip(&b5),
            true,
        ),
        (
            "descendants are not ancestors (via branch 1)",
            branch_tip(&b1),
            b1[2],
            false,
        ),
        ("branch 1 ancestor", b1[2], branch_tip(&b1), true),
        (
            "branch 3 node not ancestor of a branch 1 node (smaller height)",
            b3[0],
            branch_tip(&b1),
            false,
        ),
        (
            "branch 2 node not ancestor of a branch 1 node (greater height)",
            branch_tip(&b2),
            b1[0],
            false,
        ),
    ];
    for (name, n, n2, want) in tests {
        assert_eq!(store.is_ancestor_of(*n, *n2), *want, "{name}");
    }
}

/// dcrd `TestBetterCandidate`: the full comparison table over work,
/// data availability, received order, and the hash tiebreaker.
#[test]
fn better_candidate() {
    let lower_hash =
        Hash::from_str("000000000000c41019872ff7db8fd2e9bfa05f42d3f8fee8e895e8c1e5b8dcba")
            .expect("hash");
    let higher_hash =
        Hash::from_str("000000000000d41019872ff7db8fd2e9bfa05f42d3f8fee8e895e8c1e5b8dcba")
            .expect("hash");
    let zero_hash = Hash([0u8; 32]);
    let stored = BlockStatus::DATA_STORED;
    let none = BlockStatus::NONE;

    // (name, (hash, work, status, order) a, ... b, want_cmp, want_better)
    type Case<'a> = (
        &'a str,
        (Hash, u64, BlockStatus, u32),
        (Hash, u64, BlockStatus, u32),
        i32,
        bool,
    );
    let tests: &[Case] = &[
        (
            "exactly equal, both data",
            (zero_hash, 2, stored, 0),
            (zero_hash, 2, stored, 0),
            0,
            false,
        ),
        (
            "exactly equal, no data",
            (zero_hash, 2, none, 0),
            (zero_hash, 2, none, 0),
            0,
            false,
        ),
        (
            "a has more cumulative work, same order, higher hash, b has data",
            (higher_hash, 4, none, 0),
            (lower_hash, 2, stored, 0),
            1,
            true,
        ),
        (
            "a has less cumulative work, same order, lower hash, a has data",
            (lower_hash, 2, stored, 0),
            (higher_hash, 4, none, 0),
            -1,
            false,
        ),
        (
            "a has same cumulative work, same order, lower hash, b has data",
            (lower_hash, 2, none, 0),
            (higher_hash, 2, stored, 0),
            -1,
            false,
        ),
        (
            "a has same cumulative work, same order, higher hash, a has data",
            (higher_hash, 2, stored, 0),
            (lower_hash, 2, none, 0),
            1,
            true,
        ),
        (
            "a has same cumulative work, higher order, lower hash, both data",
            (lower_hash, 2, stored, 1),
            (higher_hash, 2, stored, 0),
            -1,
            false,
        ),
        (
            "a has same cumulative work, lower order, lower hash, both data",
            (lower_hash, 2, stored, 1),
            (higher_hash, 2, stored, 2),
            -1,
            true,
        ),
        (
            "a has same cumulative work, same order, lower hash, no data",
            (lower_hash, 2, none, 0),
            (higher_hash, 2, none, 0),
            -1,
            true,
        ),
        (
            "a has same cumulative work, same order, lower hash, both data",
            (lower_hash, 2, stored, 0),
            (higher_hash, 2, stored, 0),
            -1,
            true,
        ),
        (
            "a has same cumulative work, same order, higher hash, both data",
            (higher_hash, 2, stored, 0),
            (lower_hash, 2, stored, 0),
            1,
            false,
        ),
    ];

    for (name, a, b, want_cmp, want_better) in tests {
        let mut store = NodeStore::new();
        let na = store.new_node(&zero_header(), None);
        let nb = {
            let mut h = zero_header();
            h.nonce = 1;
            store.new_node(&h, None)
        };
        for (id, fields) in [(na, a), (nb, b)] {
            let n = store.node_mut(id);
            n.hash = fields.0;
            n.work_sum = Uint256::from(fields.1);
            n.status = fields.2;
            n.received_order_id = fields.3;
        }
        assert_eq!(
            compare_hashes_as_uint256_le(&store.node(na).hash, &store.node(nb).hash),
            *want_cmp,
            "{name}: cmp"
        );
        assert_eq!(
            store.better_candidate(na, nb),
            *want_better,
            "{name}: better"
        );
    }
}

fn locator_hashes(store: &NodeStore, nodes: &[NodeId], indexes: &[usize]) -> BlockLocator {
    indexes.iter().map(|&i| store.node(nodes[i]).hash).collect()
}

/// dcrd `TestChainView`: three-branch containment, forks, next,
/// equality, and locator layouts.
#[test]
fn chain_view() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x76696577);
    let b0 = chained_fake_nodes(&mut store, &mut index, None, 5, &mut rng);
    let b1 = chained_fake_nodes(&mut store, &mut index, Some(b0[1]), 25, &mut rng);
    let b2 = chained_fake_nodes(&mut store, &mut index, Some(b1[0]), 3, &mut rng);

    struct Test<'a> {
        name: &'a str,
        view: NodeChainView,
        genesis: NodeId,
        tip: NodeId,
        side: NodeChainView,
        side_tip: NodeId,
        fork: NodeId,
        contains: Vec<NodeId>,
        no_contains: Vec<NodeId>,
        equal: NodeChainView,
        unequal: NodeChainView,
        locator: BlockLocator,
    }

    let tests = [
        Test {
            name: "chain0-chain1",
            view: NodeChainView::new(&store, Some(branch_tip(&b0))),
            genesis: b0[0],
            tip: branch_tip(&b0),
            side: NodeChainView::new(&store, Some(branch_tip(&b1))),
            side_tip: branch_tip(&b1),
            fork: b0[1],
            contains: b0.clone(),
            no_contains: b1.clone(),
            equal: NodeChainView::new(&store, Some(branch_tip(&b0))),
            unequal: NodeChainView::new(&store, Some(branch_tip(&b1))),
            locator: locator_hashes(&store, &b0, &[4, 3, 2, 1, 0]),
        },
        Test {
            name: "chain1-chain2",
            view: NodeChainView::new(&store, Some(branch_tip(&b1))),
            genesis: b0[0],
            tip: branch_tip(&b1),
            side: NodeChainView::new(&store, Some(branch_tip(&b2))),
            side_tip: branch_tip(&b2),
            fork: b1[0],
            contains: b1.clone(),
            no_contains: b2.clone(),
            equal: NodeChainView::new(&store, Some(branch_tip(&b1))),
            unequal: NodeChainView::new(&store, Some(branch_tip(&b2))),
            locator: {
                let mut l = locator_hashes(
                    &store,
                    &b1,
                    &[24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 11, 7],
                );
                l.extend(locator_hashes(&store, &b0, &[1, 0]));
                l
            },
        },
        Test {
            name: "chain2-chain0",
            view: NodeChainView::new(&store, Some(branch_tip(&b2))),
            genesis: b0[0],
            tip: branch_tip(&b2),
            side: NodeChainView::new(&store, Some(branch_tip(&b0))),
            side_tip: branch_tip(&b0),
            fork: b0[1],
            contains: b2.clone(),
            no_contains: b0[2..].to_vec(),
            equal: NodeChainView::new(&store, Some(branch_tip(&b2))),
            unequal: NodeChainView::new(&store, Some(branch_tip(&b0))),
            locator: {
                let mut l = locator_hashes(&store, &b2, &[2, 1, 0]);
                l.extend(locator_hashes(&store, &b1, &[0]));
                l.extend(locator_hashes(&store, &b0, &[1, 0]));
                l
            },
        },
    ];

    for test in &tests {
        let name = test.name;
        assert_eq!(
            test.view.height(),
            store.node(test.tip).height,
            "{name}: height"
        );
        assert_eq!(
            test.side.height(),
            store.node(test.side_tip).height,
            "{name}: side height"
        );
        assert_eq!(test.view.genesis(), Some(test.genesis), "{name}: genesis");
        assert_eq!(
            test.side.genesis(),
            Some(test.genesis),
            "{name}: side genesis"
        );
        assert_eq!(test.view.tip(), Some(test.tip), "{name}: tip");
        assert_eq!(test.side.tip(), Some(test.side_tip), "{name}: side tip");

        assert_eq!(
            test.view.find_fork(&store, test.side.tip().unwrap()),
            Some(test.fork),
            "{name}: fork (view, side)"
        );
        assert_eq!(
            test.side.find_fork(&store, test.view.tip().unwrap()),
            Some(test.fork),
            "{name}: fork (side, view)"
        );
        assert_eq!(
            test.view.find_fork(&store, test.view.tip().unwrap()),
            test.view.tip(),
            "{name}: fork (view, tip)"
        );

        for &node in &test.contains {
            assert!(
                test.view.contains(&store, node),
                "{name}: expected containment"
            );
        }
        for &node in &test.no_contains {
            assert!(
                !test.view.contains(&store, node),
                "{name}: unexpected containment"
            );
        }
        assert!(
            test.view.equals(&test.equal),
            "{name}: unexpected unequal views"
        );
        assert!(
            !test.view.equals(&test.unequal),
            "{name}: unexpected equal views"
        );

        for (i, &node) in test.contains.iter().enumerate() {
            let expected = test.contains.get(i + 1).copied();
            assert_eq!(test.view.next(&store, node), expected, "{name}: next");
        }
        for &node in &test.no_contains {
            assert_eq!(
                test.view.next(&store, node),
                None,
                "{name}: next not in view"
            );
        }
        for &want in &test.contains {
            assert_eq!(
                test.view.node_by_height(store.node(want).height),
                Some(want),
                "{name}: node by height"
            );
        }
        assert_eq!(
            test.view.block_locator(&store, test.view.tip()),
            test.locator,
            "{name}: locator"
        );
    }
}

/// dcrd `TestChainViewForkCorners`: unrelated chains have no fork
/// point.
#[test]
fn chain_view_fork_corners() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x666f726b);
    let branch = chained_fake_nodes(&mut store, &mut index, None, 5, &mut rng);
    let unrelated = chained_fake_nodes(&mut store, &mut index, None, 7, &mut rng);
    let view1 = NodeChainView::new(&store, Some(branch_tip(&branch)));
    let view2 = NodeChainView::new(&store, Some(branch_tip(&unrelated)));
    for &node in &branch {
        assert_eq!(view2.find_fork(&store, node), None, "unexpected fork");
    }
    for &node in &unrelated {
        assert_eq!(view1.find_fork(&store, node), None, "unexpected fork");
    }
}

/// dcrd `TestChainViewSetTip`: growing, shrinking, and switching tips.
#[test]
fn chain_view_set_tip() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x736574);
    let b0 = chained_fake_nodes(&mut store, &mut index, None, 5, &mut rng);
    let b1 = chained_fake_nodes(&mut store, &mut index, Some(b0[1]), 25, &mut rng);

    let cases: &[(&str, Option<NodeId>, Vec<(Option<NodeId>, Vec<NodeId>)>)] = &[
        (
            "increasing",
            None,
            vec![
                (Some(branch_tip(&b0)), b0.clone()),
                (Some(branch_tip(&b1)), b1.clone()),
            ],
        ),
        (
            "decreasing",
            Some(branch_tip(&b1)),
            vec![(Some(branch_tip(&b0)), b0.clone()), (None, Vec::new())],
        ),
        (
            "small-large-small",
            Some(branch_tip(&b0)),
            vec![
                (Some(branch_tip(&b1)), b1.clone()),
                (Some(branch_tip(&b0)), b0.clone()),
            ],
        ),
        (
            "large-small-large",
            Some(branch_tip(&b1)),
            vec![
                (Some(branch_tip(&b0)), b0.clone()),
                (Some(branch_tip(&b1)), b1.clone()),
            ],
        ),
    ];

    for (name, initial, steps) in cases {
        let mut view = NodeChainView::new(&store, *initial);
        for (tip, contains) in steps {
            view.set_tip(&store, *tip);
            assert_eq!(view.tip(), *tip, "{name}: tip");
            for &node in contains {
                assert!(view.contains(&store, node), "{name}: expected containment");
            }
        }
    }
}

/// dcrd `TestChainViewNil`: behavior of an uninitialized view.
#[test]
fn chain_view_nil() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x6e696c);
    let view = NodeChainView::new(&store, None);
    assert!(
        view.equals(&NodeChainView::new(&store, None)),
        "nil views unequal"
    );
    assert_eq!(view.genesis(), None, "genesis");
    assert_eq!(view.tip(), None, "tip");
    assert_eq!(view.height(), -1, "height");
    assert_eq!(view.node_by_height(10), None, "node by height");
    let fake = chained_fake_nodes(&mut store, &mut index, None, 1, &mut rng)[0];
    assert!(!view.contains(&store, fake), "contains");
    assert_eq!(view.find_fork(&store, fake), None, "fork");
    assert_eq!(
        view.block_locator(&store, None),
        BlockLocator::new(),
        "locator"
    );
}

/// Supplementary coverage (dcrd exercises these paths through its
/// chain integration tests): marking a block as failed must propagate
/// an invalid-ancestor status to every descendant, drop them from the
/// best chain candidates, and reselect the best header; accepting
/// block data must link waiting children in order.
#[test]
fn invalidation_and_linking() {
    let mut store = NodeStore::new();
    let mut index = BlockIndex::new();
    let mut rng = Lcg(0x696e76);
    // Real difficulty bits so cumulative work grows with height and
    // chain selection is work-driven like production chains.
    const BITS: u32 = 0x207fffff;
    let genesis = new_fake_node(&mut store, &mut index, None, 1, 0, BITS, 1514764800, 0);
    index.add_node(&store, genesis);
    let grow =
        |store: &mut NodeStore, index: &mut BlockIndex, from: NodeId, n: usize, rng: &mut Lcg| {
            let mut nodes = Vec::new();
            let mut tip = from;
            for _ in 0..n {
                let ts = store.node(tip).timestamp + 1;
                let node =
                    new_fake_node(store, index, Some(tip), 1, 1, BITS, ts, rng.next() as u32);
                index.add_node(store, node);
                nodes.push(node);
                tip = node;
            }
            nodes
        };
    let main = grow(&mut store, &mut index, genesis, 6, &mut rng);
    let side = grow(&mut store, &mut index, main[1], 3, &mut rng);

    // Invalidate main[2]: main[3..] become invalid ancestors, the side
    // branch (forking at main[1]) is untouched.
    index.mark_block_failed_validation(&mut store, main[2]);
    assert!(
        store.node(main[2]).status.known_validate_failed(),
        "failed flag"
    );
    for &n in &main[3..] {
        assert!(
            store.node(n).status.known_invalid_ancestor(),
            "descendant invalid ancestor"
        );
        assert!(
            !store.node(n).status.has_validated(),
            "descendant validated unset"
        );
    }
    for &n in &side {
        assert!(
            !store.node(n).status.known_invalid(),
            "side branch untouched"
        );
    }
    // The best header must now be on the side branch, which has the
    // most cumulative work among the still-valid tips.
    assert_eq!(
        index.best_header(),
        Some(branch_tip(&side)),
        "best header reselected"
    );
    assert_eq!(
        index.best_invalid(),
        Some(branch_tip(&main)),
        "best invalid"
    );

    // Data linking: a parent without data holds back its child until
    // the parent's data is accepted, at which point both link in
    // order and become candidates against the given tip.
    let tip = branch_tip(&side);
    let p = new_fake_node(
        &mut store,
        &mut index,
        Some(tip),
        1,
        1,
        BITS,
        1514767000,
        900,
    );
    let c = new_fake_node(&mut store, &mut index, Some(p), 1, 1, BITS, 1514767001, 901);
    store.node_mut(p).is_fully_linked = false;
    store.node_mut(c).is_fully_linked = false;
    index.add_node(&store, p);
    index.add_node(&store, c);

    // The child's parent cannot be validated yet, so the child is
    // queued rather than linked.
    store.node_mut(p).status = BlockStatus::NONE;
    let linked = index.accept_block_data(&mut store, c, tip);
    assert!(linked.is_empty(), "child linked before parent data");

    // Accepting the parent's data links the parent and the waiting
    // child in order.
    store.node_mut(p).status = BlockStatus::DATA_STORED;
    store.node_mut(c).status = BlockStatus::DATA_STORED;
    let linked = index.accept_block_data(&mut store, p, tip);
    assert_eq!(linked, [p, c], "parent then child linked");
    assert!(store.node(p).is_fully_linked && store.node(c).is_fully_linked);
    assert!(
        store.node(p).received_order_id < store.node(c).received_order_id,
        "received order assigned in link order"
    );
    assert_eq!(
        index.find_best_chain_candidate(&store),
        Some(c),
        "highest-work candidate wins"
    );
}
