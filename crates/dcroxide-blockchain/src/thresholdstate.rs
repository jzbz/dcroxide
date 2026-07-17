// SPDX-License-Identifier: ISC
//! The agenda voting threshold state machine (dcrd
//! internal/blockchain `thresholdstate.go`).
//!
//! The chain walk is abstracted behind [`VoteChainView`]; the stake
//! version and median time prerequisites come from [`crate::stakever`].
//! dcrd memoizes interval-boundary states in a per-deployment cache
//! keyed by block hash; on a single-branch view the boundary heights
//! are unique, so this port recomputes from the deployment start each
//! call, which is result-identical.

use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chaincfg::{Choice, ConsensusDeployment, Params};

use crate::stakever::{
    VersionChainView, VersionNode, calc_past_median_time, calc_stake_version, calc_want_height,
    is_majority_version,
};

/// The threshold states an agenda moves through (dcrd
/// `ThresholdState`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThresholdState {
    /// The first state each deployment starts in.
    Defined,
    /// The voting window has begun.
    Started,
    /// The vote reached its activation threshold.
    LockedIn,
    /// The deployment is active.
    Active,
    /// The deployment expired or was voted down.
    Failed,
}

impl ThresholdState {
    /// dcrd's name for this state.
    pub fn go_name(self) -> &'static str {
        match self {
            ThresholdState::Defined => "ThresholdDefined",
            ThresholdState::Started => "ThresholdStarted",
            ThresholdState::LockedIn => "ThresholdLockedIn",
            ThresholdState::Active => "ThresholdActive",
            ThresholdState::Failed => "ThresholdFailed",
        }
    }
}

/// A threshold state along with the winning choice, when one exists
/// (dcrd `ThresholdStateTuple`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdStateTuple {
    /// The current state.
    pub state: ThresholdState,
    /// The choice that locked in or failed the agenda, when decided.
    pub choice: Option<Choice>,
}

fn tuple(state: ThresholdState, choice: Option<Choice>) -> ThresholdStateTuple {
    ThresholdStateTuple { state, choice }
}

/// A node carrying the full vote data the state machine tallies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VoteNode {
    /// The version-independent node data.
    pub node: VersionNode,
    /// The (vote version, vote bits) pairs carried by the block votes;
    /// must be consistent with `node.vote_versions`.
    pub votes: Vec<(u32, u16)>,
}

/// A height-indexed view of the branch providing full vote data.  A
/// vote view is also a [`VersionChainView`] — the version data is a
/// projection of the vote data — which lets the stake version
/// calculations and their memoization hooks run over the same view.
///
/// The `threshold_state_*` methods expose dcrd's per-deployment
/// `thresholdStateCache`, keyed by the interval-boundary block hash;
/// the defaults disable caching exactly like the stake version
/// hooks.
pub trait VoteChainView: VersionChainView {
    /// The node at the given height along this branch.
    fn vote_node(&self, height: i64) -> Option<VoteNode>;

    /// A cached threshold state for the deployment at the
    /// interval-boundary node with the hash.
    fn threshold_state_cached(
        &self,
        _deployment_version: u32,
        _vote_id: &str,
        _hash: [u8; 32],
    ) -> Option<ThresholdStateTuple> {
        None
    }

    /// Record the threshold state for the deployment at the
    /// interval-boundary node with the hash.
    fn cache_threshold_state(
        &self,
        _deployment_version: u32,
        _vote_id: &str,
        _hash: [u8; 32],
        _state: ThresholdStateTuple,
    ) {
    }
}

/// The highest deployment version defined by the network (dcrd
/// `currentDeploymentVersion`); zero when there are none.
pub fn current_deployment_version(params: &Params) -> u32 {
    params
        .deployments
        .iter()
        .map(|(version, _)| *version)
        .max()
        .unwrap_or(0)
}

/// The lowest deployment version greater than the given one (dcrd
/// `nextDeploymentVersion`); zero when there is none.
pub fn next_deployment_version(params: &Params, version: u32) -> u32 {
    params
        .deployments
        .iter()
        .map(|(v, _)| *v)
        .filter(|v| *v > version)
        .min()
        .unwrap_or(0)
}

/// The next threshold state for the deployment at the block AFTER the
/// given previous node (dcrd `nextThresholdState`).
pub fn next_threshold_state(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    deployment_version: u32,
    deployment: &ConsensusDeployment,
    params: &Params,
) -> ThresholdStateTuple {
    // The threshold state for the window that contains the genesis
    // block is defined by definition.
    let rule_change_interval = i64::from(params.rule_change_activation_interval);
    let confirmation_window = rule_change_interval;
    let svh = params.stake_validation_height;
    let Some(prev_height) = prev_height else {
        return tuple(ThresholdState::Defined, None);
    };
    if prev_height + 1 < svh + confirmation_window {
        return tuple(ThresholdState::Defined, None);
    }

    // Get the ancestor that is the last block of the previous
    // confirmation window.
    let want_height = calc_want_height(svh, rule_change_interval, prev_height + 1);

    // Collect the confirmation-window boundary nodes back to the
    // point the deployment's begin time is no longer met OR a cached
    // boundary state is found (dcrd walks until a cache hit and
    // seeds the forward replay from it).
    let begin_time = deployment.start_time;
    let vote_id = deployment.vote.id;
    let mut needed_heights = Vec::new();
    let mut walk_height = Some(want_height);
    let mut seed_state: Option<ThresholdStateTuple> = None;
    while let Some(h) = walk_height {
        if view.vote_node(h).is_none() {
            break;
        }
        if let Some(hash) = view.cache_hash(h)
            && let Some(cached) = view.threshold_state_cached(deployment_version, vote_id, hash)
        {
            seed_state = Some(cached);
            break;
        }
        let median_time = calc_past_median_time(view, h);
        if (median_time as u64) < begin_time {
            break;
        }
        needed_heights.push(h);
        let next = h - confirmation_window;
        walk_height = if next >= 0 { Some(next) } else { None };
    }

    // The starting state is defined (dcrd seeds its cache with Defined
    // at the node whose median time is before the begin time) unless a
    // cached boundary supplied it.
    let mut state = seed_state.unwrap_or_else(|| tuple(ThresholdState::Defined, None));

    // Replay the state transitions forward through the collected
    // boundary nodes.
    let end_time = deployment.expire_time;
    for &h in needed_heights.iter().rev() {
        match state.state {
            ThresholdState::Defined => {
                // Ensure we are at the minimal require height (Go's
                // `break` here exits the switch arm, not the loop, so
                // the walk continues with the state left defined).
                if h < svh {
                    continue;
                }

                // The deployment expired.
                let median_time = calc_past_median_time(view, h) as u64;
                if median_time >= end_time {
                    state.state = ThresholdState::Failed;
                } else if calc_stake_version(view, h, params) < deployment_version {
                    // Make sure we are on the correct stake version.
                } else if !is_majority_version(
                    view,
                    deployment_version as i32,
                    Some(h),
                    params.block_reject_num_required,
                    params,
                ) {
                    // The dependency not being met means the state stays
                    // defined.
                } else if median_time >= begin_time {
                    // The begin time has been reached: start voting.
                    state.state = ThresholdState::Started;
                }
            }
            ThresholdState::Started => {
                // The deployment expired.
                let median_time = calc_past_median_time(view, h) as u64;
                if median_time >= end_time {
                    state.state = ThresholdState::Failed;
                } else {
                    // Tally the votes over the confirmation window.
                    let vote = &deployment.vote;
                    let choice_idx_shift = vote.mask.trailing_zeros();
                    let mut total_non_abstain_votes: u32 = 0;
                    let mut choice_counts = vec![0u32; vote.choices.len()];
                    let mut count_height = h;
                    for _ in 0..confirmation_window {
                        let Some(count_node) = view.vote_node(count_height) else {
                            break;
                        };
                        for (version, bits) in &count_node.votes {
                            if *version != deployment_version {
                                continue;
                            }
                            let choice_idx = usize::from((bits & vote.mask) >> choice_idx_shift);
                            if choice_idx > vote.choices.len() - 1 {
                                continue;
                            }
                            choice_counts[choice_idx] += 1;
                            if !vote.choices[choice_idx].is_abstain {
                                total_non_abstain_votes += 1;
                            }
                        }
                        if count_height == 0 {
                            break;
                        }
                        count_height -= 1;
                    }

                    if total_non_abstain_votes >= params.rule_change_activation_quorum {
                        let threshold = total_non_abstain_votes
                            * params.rule_change_activation_multiplier
                            / params.rule_change_activation_divisor;
                        for (choice_idx, choice) in vote.choices.iter().enumerate() {
                            if choice.is_abstain || choice_counts[choice_idx] < threshold {
                                continue;
                            }
                            if choice.is_no {
                                state.state = ThresholdState::Failed;
                            } else {
                                state.state = ThresholdState::LockedIn;
                            }
                            state.choice = Some(choice.clone());
                            break;
                        }
                    }
                }
            }
            ThresholdState::LockedIn => {
                // The new rule becomes active when its previous state
                // was locked in.
                state.state = ThresholdState::Active;
            }
            // Nothing to do for the terminal states.
            ThresholdState::Active | ThresholdState::Failed => {}
        }

        // Record the boundary's state (dcrd updates the deployment
        // cache as it ascends).
        if let Some(hash) = view.cache_hash(h) {
            view.cache_threshold_state(deployment_version, vote_id, hash, state.clone());
        }
    }

    state
}

/// The threshold state for the deployment for the block AFTER the given
/// node, honoring test networks' forced choices (dcrd
/// `deploymentState`).
pub fn deployment_state(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    deployment_version: u32,
    deployment: &ConsensusDeployment,
    params: &Params,
) -> ThresholdStateTuple {
    // Networks may force an outcome for an agenda (used on test
    // networks for already-decided agendas); dcrd resolves this into a
    // forced state at chain construction.
    if !deployment.forced_choice_id.is_empty() {
        let choice = deployment
            .vote
            .choices
            .iter()
            .find(|c| c.id == deployment.forced_choice_id)
            .cloned();
        let state = match &choice {
            Some(c) if c.is_no => ThresholdState::Failed,
            Some(_) => ThresholdState::Active,
            // A forced choice id that does not exist is a chaincfg data
            // error; dcrd validates this at startup and the ported
            // chaincfg sanity tests do the same.
            None => unreachable!("forced choice id must exist in the vote choices"),
        };
        return tuple(state, choice);
    }

    next_threshold_state(view, prev_height, deployment_version, deployment, params)
}

/// Compacted vote counts for a deployment over the current rule change
/// activation interval (dcrd `VoteCounts`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VoteCounts {
    /// The total number of votes with the deployment's version.
    pub total: u32,
    /// The number of votes that abstained, including invalid choices.
    pub total_abstain: u32,
    /// Per-choice vote counts in the deployment's choice order.
    pub vote_choices: Vec<u32>,
}

/// The height at which the deployment last changed state as of the
/// node at the given height, or `None` when the state has never
/// changed (dcrd `stateLastChanged`).
pub fn state_last_changed(
    view: &impl VoteChainView,
    node_height: i64,
    deployment_version: u32,
    deployment: &ConsensusDeployment,
    params: &Params,
) -> Option<i64> {
    // No state changes are possible if the chain is not yet past stake
    // validation height and had a full interval to change.
    let confirmation_interval = i64::from(params.rule_change_activation_interval);
    let svh = params.stake_validation_height;
    if node_height < svh + confirmation_interval {
        return None;
    }

    // Determine the current state.  Notice that nextThresholdState
    // always calculates the state for the block after the provided
    // one, so use the parent to get the state for the requested block.
    let cur_state = next_threshold_state(
        view,
        Some(node_height - 1),
        deployment_version,
        deployment,
        params,
    );

    // Determine the first block of the current confirmation interval
    // in order to determine the block at which the state possibly
    // changed.  Since the state can only change at an interval
    // boundary, loop backwards one interval at a time to determine
    // when (and if) the state changed.
    let final_node_height = calc_want_height(svh, confirmation_interval, node_height);
    let mut walk_height = final_node_height + 1;
    let mut prior_state_change_height = walk_height;
    while walk_height >= 1 {
        // As previously mentioned, nextThresholdState always
        // calculates the state for the block after the provided one,
        // so use the parent to get the state of the block itself.
        let state = next_threshold_state(
            view,
            Some(walk_height - 1),
            deployment_version,
            deployment,
            params,
        );
        if state.state != cur_state.state {
            return Some(prior_state_change_height);
        }

        // Get the ancestor that is the first block of the previous
        // confirmation interval.
        prior_state_change_height = walk_height;
        walk_height -= confirmation_interval;
    }

    None
}
