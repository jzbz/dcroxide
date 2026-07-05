// SPDX-License-Identifier: ISC
//! Agenda activation helpers and the algorithm selectors they drive
//! (dcrd internal/blockchain `thresholdstate.go` is-active helpers plus
//! the `calcNextRequiredDifficulty`/`calcNextRequiredStakeDifficulty`
//! selectors from `difficulty.go`).

use dcroxide_chaincfg::{ConsensusDeployment, Params};

use crate::difficulty::{
    ChainView, DiffNode, calc_next_blake3_diff_from_anchor, calc_next_blake256_diff,
    calc_next_required_stake_difficulty_v1, calc_next_required_stake_difficulty_v2,
};
use crate::stakever::calc_want_height;
use crate::thresholdstate::{ThresholdState, VoteChainView, deployment_state};

/// The vote ID for the DCP0001 stake difficulty algorithm change.
pub const VOTE_ID_SDIFF_ALGORITHM: &str = "sdiffalgorithm";
/// The vote ID for the DCP0002/DCP0003 LN features agenda.
pub const VOTE_ID_LN_FEATURES: &str = "lnfeatures";
/// The vote ID for the DCP0005 header commitments agenda.
pub const VOTE_ID_HEADER_COMMITMENTS: &str = "headercommitments";
/// The vote ID for the DCP0006 decentralized treasury agenda.
pub const VOTE_ID_TREASURY: &str = "treasury";
/// The vote ID for the DCP0007 revert treasury policy agenda.
pub const VOTE_ID_REVERT_TREASURY_POLICY: &str = "reverttreasurypolicy";
/// The vote ID for the DCP0008 explicit version upgrades agenda.
pub const VOTE_ID_EXPLICIT_VERSION_UPGRADES: &str = "explicitverupgrades";
/// The vote ID for the DCP0009 automatic ticket revocations agenda.
pub const VOTE_ID_AUTO_REVOCATIONS: &str = "autorevocations";
/// The vote ID for the DCP0010 subsidy split change agenda.
pub const VOTE_ID_CHANGE_SUBSIDY_SPLIT: &str = "changesubsidysplit";
/// The vote ID for the DCP0011 BLAKE3 proof of work agenda.
pub const VOTE_ID_BLAKE3_POW: &str = "blake3pow";
/// The vote ID for the DCP0012 subsidy split change agenda.
pub const VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2: &str = "changesubsidysplitr2";

/// Locate the deployment with the given vote ID along with its version
/// (the lookup dcrd performs once in `extractDeployments`).
pub fn find_deployment<'a>(
    params: &'a Params,
    vote_id: &str,
) -> Option<(u32, &'a ConsensusDeployment)> {
    for (version, deployments) in &params.deployments {
        for deployment in deployments {
            if deployment.vote.id == vote_id {
                return Some((*version, deployment));
            }
        }
    }
    None
}

/// Whether the agenda with the given vote ID is active for the block
/// AFTER the given node (the shared body of dcrd's `is*AgendaActive`
/// helpers).  Errors when the network does not define the deployment
/// (dcrd `ErrUnknownDeploymentID`).
pub fn is_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    vote_id: &str,
    params: &Params,
) -> Result<bool, UnknownDeployment> {
    let (version, deployment) = find_deployment(params, vote_id).ok_or(UnknownDeployment)?;
    let state = deployment_state(view, prev_height, version, deployment, params);
    Ok(state.state == ThresholdState::Active)
}

/// Whether the DCP0011 BLAKE3 proof of work agenda is active for the
/// block AFTER the given node (dcrd `isBlake3PowAgendaActive`).
pub fn is_blake3_pow_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, UnknownDeployment> {
    is_agenda_active(view, prev_height, VOTE_ID_BLAKE3_POW, params)
}

/// Whether the DCP0005 header commitments agenda is active for the
/// block AFTER the given node (dcrd
/// `isHeaderCommitmentsAgendaActive`).
pub fn is_header_commitments_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, UnknownDeployment> {
    is_agenda_active(view, prev_height, VOTE_ID_HEADER_COMMITMENTS, params)
}

/// The network does not define the requested deployment (dcrd
/// `ErrUnknownDeploymentID`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnknownDeployment;

/// Whether the DCP0006 treasury agenda is active for the block AFTER
/// the given node (dcrd `isTreasuryAgendaActive`); the genesis block
/// special-cases to inactive.
pub fn is_treasury_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, UnknownDeployment> {
    if prev_height == Some(0) {
        return Ok(false);
    }
    is_agenda_active(view, prev_height, VOTE_ID_TREASURY, params)
}

/// Whether the DCP0011 BLAKE3 proof of work agenda has a forced-active
/// state on this network (dcrd `isBlake3PowAgendaForcedActive`).
pub fn is_blake3_pow_agenda_forced_active(params: &Params) -> bool {
    let Some((_, deployment)) = find_deployment(params, VOTE_ID_BLAKE3_POW) else {
        return false;
    };
    if deployment.forced_choice_id.is_empty() {
        return false;
    }
    deployment
        .vote
        .choices
        .iter()
        .find(|c| c.id == deployment.forced_choice_id)
        .is_some_and(|c| !c.is_no)
}

/// A view that provides both the difficulty node data and the full
/// vote data the agenda checks need.
pub trait FullChainView: ChainView + VoteChainView {}
impl<T: ChainView + VoteChainView> FullChainView for T {}

/// The anchor block for BLAKE3 difficulty calculations: the final block
/// of the interval just before the agenda activated (dcrd
/// `blake3WorkDiffAnchor`, sans dcrd's cached-anchor fast path).
fn blake3_work_diff_anchor(
    view: &impl FullChainView,
    prev_height: i64,
    params: &Params,
) -> Option<DiffNode> {
    let rcai = i64::from(params.rule_change_activation_interval);
    let svh = params.stake_validation_height;

    // Determine the final node of the previous rule change interval.
    let final_node_height = calc_want_height(svh, rcai, prev_height + 1);
    let mut candidate_height = final_node_height;
    let mut anchor = None;
    while candidate_height >= 0 {
        let Some(candidate) = ChainView::node(view, candidate_height) else {
            break;
        };
        if candidate.height == 0 {
            break;
        }
        let is_active =
            is_agenda_active(view, Some(candidate.height - 1), VOTE_ID_BLAKE3_POW, params)
                .expect("known good agenda state lookup");
        if !is_active {
            anchor = Some(candidate);
            break;
        }
        candidate_height -= rcai;
    }
    anchor
}

/// Calculate the required BLAKE3 difficulty for the block AFTER the
/// given node (dcrd `calcNextBlake3Diff`).
pub(crate) fn calc_next_blake3_diff(
    view: &impl FullChainView,
    prev_node: &DiffNode,
    params: &Params,
) -> u32 {
    // When the agenda is always active, the anchor is the first block
    // of the chain.
    if is_blake3_pow_agenda_forced_active(params) {
        if prev_node.height == 0 {
            return params.work_diff_v2_blake3_start_bits;
        }
        let anchor = ChainView::node(view, 1).expect("height 1 exists below tip");
        return calc_next_blake3_diff_from_anchor(prev_node, &anchor, params);
    }

    let anchor = blake3_work_diff_anchor(view, prev_node.height, params)
        .expect("anchor exists once the agenda is active");
    calc_next_blake3_diff_from_anchor(prev_node, &anchor, params)
}

/// Calculate the required proof of work difficulty for the block AFTER
/// the given node, selecting the algorithm by the BLAKE3 agenda state
/// (dcrd `calcNextRequiredDifficulty`).
pub fn calc_next_required_difficulty(
    view: &impl FullChainView,
    prev_node: &DiffNode,
    new_block_time_unix: i64,
    params: &Params,
) -> Result<u32, UnknownDeployment> {
    let is_active = is_agenda_active(view, Some(prev_node.height), VOTE_ID_BLAKE3_POW, params)?;
    if is_active {
        return Ok(calc_next_blake3_diff(view, prev_node, params));
    }
    Ok(calc_next_blake256_diff(
        view,
        prev_node,
        new_block_time_unix,
        params,
    ))
}

/// Calculate the required stake difficulty for the block AFTER the
/// given node, selecting the algorithm by the DCP0001 agenda state
/// (dcrd `calcNextRequiredStakeDifficulty`); networks without the
/// deployment always use the new algorithm.
pub fn calc_next_required_stake_difficulty(
    view: &impl FullChainView,
    cur_node: Option<&DiffNode>,
    params: &Params,
) -> i64 {
    let Some((version, deployment)) = find_deployment(params, VOTE_ID_SDIFF_ALGORITHM) else {
        return calc_next_required_stake_difficulty_v2(view, cur_node, params);
    };
    let state = deployment_state(
        view,
        cur_node.map(|n| n.height),
        version,
        deployment,
        params,
    );
    if state.state == ThresholdState::Active {
        return calc_next_required_stake_difficulty_v2(view, cur_node, params);
    }
    calc_next_required_stake_difficulty_v1(view, cur_node, params)
}
