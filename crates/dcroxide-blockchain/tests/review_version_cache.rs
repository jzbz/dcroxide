// SPDX-License-Identifier: ISC
//! The stake version and threshold state memoization keys.
//!
//! dcrd keys `calcStakeVersionCache` by the voter version node
//! `calcVoterVersion` settles on, so every block of a stake version
//! interval shares one entry and the 950-block `isMajorityVersion(3, ..)`
//! walk runs once per interval.  The port keyed it by the argument node,
//! which missed for every new block and grew one entry per block.  dcrd's
//! `nextThresholdState` also caches the defined state at the boundary
//! whose median time precedes the deployment's start, which the port
//! skipped, so every query before an agenda's start recomputed a median.
//! These tests pin both keys against a counting view, and that the cached
//! results match the uncached path.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use dcroxide_blockchain::stakever::{VersionChainView, VersionNode, calc_stake_version};
use dcroxide_blockchain::thresholdstate::{
    ThresholdState, ThresholdStateTuple, VoteChainView, VoteNode, next_threshold_state,
};
use dcroxide_chaincfg::{ConsensusDeployment, Params, simnet_params};

const T0: i64 = 1_600_000_000;

/// Threshold cache rows keyed by deployment version, vote id and
/// boundary hash.
type ThresholdCache = BTreeMap<(u32, String, [u8; 32]), ThresholdStateTuple>;

/// A synthetic branch with dcrd-shaped memoization caches (when
/// `caching`) and counters for the node lookups and descending walks.
struct Synth {
    nodes: Vec<VoteNode>,
    caching: bool,
    vote_node_calls: Cell<usize>,
    walk_calls: Cell<usize>,
    voter_interval: RefCell<BTreeMap<[u8; 32], Option<u32>>>,
    stake_majority: RefCell<BTreeMap<(u32, [u8; 32]), bool>>,
    prior_stake_version: RefCell<BTreeMap<[u8; 32], Option<u32>>>,
    stake_version: RefCell<BTreeMap<[u8; 32], u32>>,
    threshold: RefCell<ThresholdCache>,
}

impl Synth {
    fn new(nodes: Vec<VoteNode>, caching: bool) -> Synth {
        Synth {
            nodes,
            caching,
            vote_node_calls: Cell::new(0),
            walk_calls: Cell::new(0),
            voter_interval: RefCell::default(),
            stake_majority: RefCell::default(),
            prior_stake_version: RefCell::default(),
            stake_version: RefCell::default(),
            threshold: RefCell::default(),
        }
    }

    fn get(&self, height: i64) -> Option<&VoteNode> {
        self.nodes.get(usize::try_from(height).ok()?)
    }

    fn hash(height: i64) -> [u8; 32] {
        let mut hash = [0xa5u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        hash
    }
}

impl VersionChainView for Synth {
    fn node(&self, height: i64) -> Option<VersionNode> {
        self.get(height).map(|n| n.node.clone())
    }

    fn walk_back(&self, height: i64, visit: &mut dyn FnMut(&VersionNode) -> bool) {
        self.walk_calls.set(self.walk_calls.get() + 1);
        let mut h = height;
        while let Some(node) = self.get(h) {
            if !visit(&node.node) || h == 0 {
                break;
            }
            h -= 1;
        }
    }

    fn cache_hash(&self, height: i64) -> Option<[u8; 32]> {
        (self.caching && self.get(height).is_some()).then(|| Synth::hash(height))
    }

    fn voter_version_interval_cached(&self, hash: [u8; 32]) -> Option<Option<u32>> {
        self.voter_interval.borrow().get(&hash).copied()
    }

    fn cache_voter_version_interval(&self, hash: [u8; 32], version: Option<u32>) {
        self.voter_interval.borrow_mut().insert(hash, version);
    }

    fn stake_majority_cached(&self, min_ver: u32, hash: [u8; 32]) -> Option<bool> {
        self.stake_majority.borrow().get(&(min_ver, hash)).copied()
    }

    fn cache_stake_majority(&self, min_ver: u32, hash: [u8; 32], majority: bool) {
        self.stake_majority
            .borrow_mut()
            .insert((min_ver, hash), majority);
    }

    fn prior_stake_version_cached(&self, hash: [u8; 32]) -> Option<Option<u32>> {
        self.prior_stake_version.borrow().get(&hash).copied()
    }

    fn cache_prior_stake_version(&self, hash: [u8; 32], version: Option<u32>) {
        self.prior_stake_version.borrow_mut().insert(hash, version);
    }

    fn stake_version_cached(&self, hash: [u8; 32]) -> Option<u32> {
        self.stake_version.borrow().get(&hash).copied()
    }

    fn cache_stake_version(&self, hash: [u8; 32], version: u32) {
        self.stake_version.borrow_mut().insert(hash, version);
    }
}

impl VoteChainView for Synth {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        self.vote_node_calls.set(self.vote_node_calls.get() + 1);
        self.get(height).cloned()
    }

    fn threshold_state_cached(
        &self,
        deployment_version: u32,
        vote_id: &str,
        hash: [u8; 32],
    ) -> Option<ThresholdStateTuple> {
        self.threshold
            .borrow()
            .get(&(deployment_version, vote_id.to_string(), hash))
            .cloned()
    }

    fn cache_threshold_state(
        &self,
        deployment_version: u32,
        vote_id: &str,
        hash: [u8; 32],
        state: ThresholdStateTuple,
    ) {
        self.threshold
            .borrow_mut()
            .insert((deployment_version, vote_id.to_string(), hash), state);
    }
}

/// Simnet's first deployment, unforced, starting at `start_time`.
fn deployment(params: &Params, start_time: u64) -> (u32, ConsensusDeployment) {
    let (version, deployments) = &params.deployments[0];
    let mut deployment = deployments[0].clone();
    deployment.forced_choice_id = "";
    deployment.start_time = start_time;
    deployment.expire_time = u64::MAX;
    (*version, deployment)
}

/// A chain of `len` blocks whose headers and votes move to the
/// deployment version (voting yes) from `upgrade_height`, with the
/// header stake versions following one interval behind.
fn build_chain(
    params: &Params,
    len: i64,
    upgrade_height: i64,
    version: u32,
    yes_bits: u16,
) -> Vec<VoteNode> {
    let svi = params.stake_version_interval;
    (0..len)
        .map(|height| {
            let upgraded = height >= upgrade_height;
            let votes: Vec<(u32, u16)> = if height >= params.stake_validation_height {
                let vote_version = if upgraded { version } else { version - 1 };
                (0..5).map(|_| (vote_version, yes_bits)).collect()
            } else {
                Vec::new()
            };
            VoteNode {
                node: VersionNode {
                    height,
                    timestamp: T0 + height * 300 + (height * 37) % 250,
                    block_version: if upgraded { version as i32 } else { 3 },
                    stake_version: if height >= upgrade_height + svi {
                        version
                    } else {
                        0
                    },
                    vote_versions: votes.iter().map(|v| v.0).collect(),
                },
                votes,
            }
        })
        .collect()
}

fn yes_bits(deployment: &ConsensusDeployment) -> u16 {
    deployment
        .vote
        .choices
        .iter()
        .find(|c| !c.is_abstain && !c.is_no)
        .expect("a yes choice")
        .bits
}

/// Every block of a stake version interval shares the cached stake
/// version, so the header version majority walk runs once per interval
/// and the cache grows by one entry per interval.
#[test]
fn stake_version_is_memoized_per_interval() {
    let params = simnet_params();
    let (version, dep) = deployment(&params, 0);
    let nodes = build_chain(&params, 1200, 300, version, yes_bits(&dep));
    let view = Synth::new(nodes.clone(), true);

    // simnet: SVH 144 and SVI 112, so heights 256 through 367 all
    // follow the voter version interval ending at 255.
    let first = calc_stake_version(&view, 300, &params);
    let walks = view.walk_calls.get();
    assert!(walks > 0, "the first call walks the header versions");
    for prev in [301, 320, 366] {
        assert_eq!(calc_stake_version(&view, prev, &params), first);
    }
    assert_eq!(
        view.walk_calls.get(),
        walks,
        "blocks of the same interval re-walked the header versions"
    );
    assert_eq!(view.stake_version.borrow().len(), 1);
    assert!(view.stake_version.borrow().contains_key(&Synth::hash(255)));

    // The memoized results match the uncached path across intervals,
    // whichever order the heights are asked in.
    let plain = Synth::new(nodes, false);
    let heights: Vec<i64> = (0..1199).collect();
    for prev in heights.iter().chain(heights.iter().rev()) {
        assert_eq!(
            calc_stake_version(&view, *prev, &params),
            calc_stake_version(&plain, *prev, &params),
            "prev {prev}"
        );
    }
    assert!(view.stake_version.borrow().len() <= 1199 / 112 + 1);
}

/// A deployment whose start time is still ahead caches its defined
/// state at the boundary like dcrd, so a repeated query is a cache hit
/// with no median time recomputation or node probe.
#[test]
fn defined_state_before_start_is_memoized() {
    let params = simnet_params();
    let (version, dep) = deployment(&params, u64::MAX);
    let nodes = build_chain(&params, 1200, 300, version, yes_bits(&dep));
    let view = Synth::new(nodes, true);

    let prev = 1100;
    let want = next_threshold_state(&view, Some(prev), version, &dep, &params);
    assert_eq!(want.state, ThresholdState::Defined);
    assert_eq!(
        view.threshold.borrow().len(),
        1,
        "the defined boundary state was not cached"
    );

    view.walk_calls.set(0);
    view.vote_node_calls.set(0);
    for prev in [1100, 1101, 1099] {
        assert_eq!(
            next_threshold_state(&view, Some(prev), version, &dep, &params),
            want
        );
    }
    assert_eq!(
        view.walk_calls.get(),
        0,
        "a cached query recomputed a median"
    );
    assert_eq!(
        view.vote_node_calls.get(),
        0,
        "a cached query probed a node"
    );
}

/// The memoized threshold states (including the cached defined states
/// before the start time and below the stake validation height) match
/// the uncached path through a full defined, started, locked in and
/// active progression.
#[test]
fn memoized_threshold_states_match_uncached() {
    let params = simnet_params();
    let start = (T0 + 700 * 300) as u64;
    let (version, dep) = deployment(&params, start);
    let nodes = build_chain(&params, 2600, 300, version, yes_bits(&dep));
    let view = Synth::new(nodes.clone(), true);
    let plain = Synth::new(nodes, false);

    let mut seen = Vec::new();
    for prev in (0..2599).step_by(7).chain((0..2599).rev().step_by(13)) {
        let got = next_threshold_state(&view, Some(prev), version, &dep, &params);
        assert_eq!(
            got,
            next_threshold_state(&plain, Some(prev), version, &dep, &params),
            "prev {prev}"
        );
        if !seen.contains(&got.state) {
            seen.push(got.state);
        }
    }
    for state in [
        ThresholdState::Defined,
        ThresholdState::Started,
        ThresholdState::LockedIn,
        ThresholdState::Active,
    ] {
        assert!(seen.contains(&state), "{state:?} never reached");
    }
}
