// SPDX-License-Identifier: ISC
//! Consensus rule change agendas and the selectors they drive (dcrd
//! internal/blockchain `agendas.go`, plus the `maxBlockSize` selector
//! from `chain.go` and the `calcNextRequiredDifficulty`,
//! `calcNextRequiredStakeDifficulty` and `estimateNextStakeDifficulty`
//! selectors from `difficulty.go`).
//!
//! dcrd separates an agenda -- a consensus rule whose status can change
//! along the chain -- from the deployment whose vote may decide it.
//! `makeAgendas` builds one agenda per deployment in the chain
//! parameters, attaches the hard-coded historical activations of the
//! main and version 3 test networks, and adds a default for every
//! required agenda the network defines no deployment for.  dcrd builds
//! that map once in `New`; this port holds no chain parameters in its
//! chain, so it resolves the one agenda a query needs with
//! [`lookup_agenda`], which shares every per-agenda step with
//! [`make_agendas`].  [`make_agendas`] itself runs, with its full
//! validation, when a chain is constructed (`Chain::new`,
//! `Chain::open`), as dcrd's `New` runs it.
//!
//! The one piece of agenda state that is not a pure function of the
//! parameters, the activation anchor dcrd caches on each agenda, lives
//! per chain in the block index store and is reached through the
//! [`VoteChainView`] anchor hooks.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use dcroxide_chaincfg::{ConsensusDeployment, Params, Vote};
use dcroxide_chainhash::Hash;
use dcroxide_wire::CurrencyNet;

use crate::difficulty::{
    ChainView, DiffNode, calc_next_blake3_diff_from_anchor, calc_next_blake256_diff,
    calc_next_required_stake_difficulty_v1, calc_next_required_stake_difficulty_v2,
    estimate_next_stake_difficulty_v1, estimate_next_stake_difficulty_v2,
};
use crate::ruleerror::{RuleError, RuleErrorKind, rule_error};
use crate::stakever::calc_want_height;
use crate::thresholdstate::{
    ThresholdState, ThresholdStateTuple, VoteChainView, agenda_state, new_threshold_state,
};

// The agenda vote IDs come from chaincfg's canonical definitions (dcrd's
// blockchain uses `chaincfg.VoteID*` the same way); they are re-exported
// here so the consensus lookups and the agenda tables share one copy.
pub use dcroxide_chaincfg::{
    VOTE_ID_AUTO_REVOCATIONS, VOTE_ID_BLAKE3_POW, VOTE_ID_CHANGE_SUBSIDY_SPLIT,
    VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2, VOTE_ID_EXPLICIT_VERSION_UPGRADES, VOTE_ID_FIX_LN_SEQ_LOCKS,
    VOTE_ID_HEADER_COMMITMENTS, VOTE_ID_LN_FEATURES, VOTE_ID_LN_SUPPORT, VOTE_ID_MAX_BLOCK_SIZE,
    VOTE_ID_MAX_TREASURY_SPEND, VOTE_ID_REVERT_TREASURY_POLICY, VOTE_ID_SDIFF_ALGORITHM,
    VOTE_ID_TREASURY,
};

/// The IDs of every agenda that influences consensus behavior, in the
/// order dcrd lists them (dcrd `requiredAgendaIDs`, `agendas.go:35-49`).
///
/// A required agenda the network defines no deployment for gets a
/// default agenda: always inactive on the main network and active, with
/// an empty choice, on every other network.  That lets the simulation
/// network and newer test networks apply the newer rules without a vote
/// or a forced choice in their parameters.
pub const REQUIRED_AGENDA_IDS: [&str; 13] = [
    VOTE_ID_MAX_BLOCK_SIZE,
    VOTE_ID_SDIFF_ALGORITHM,
    VOTE_ID_LN_FEATURES,
    VOTE_ID_FIX_LN_SEQ_LOCKS,
    VOTE_ID_HEADER_COMMITMENTS,
    VOTE_ID_TREASURY,
    VOTE_ID_REVERT_TREASURY_POLICY,
    VOTE_ID_EXPLICIT_VERSION_UPGRADES,
    VOTE_ID_AUTO_REVOCATIONS,
    VOTE_ID_CHANGE_SUBSIDY_SPLIT,
    VOTE_ID_BLAKE3_POW,
    VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
    VOTE_ID_MAX_TREASURY_SPEND,
];

/// A hard-coded historical agenda activation (dcrd
/// `historicalActivationState`, `agendas.go:378-390`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HistoricalActivationState {
    /// The height of the parent of the historical block at which the
    /// agenda activated.
    pub anchor_height: i64,
    /// The hash of that parent, in internal byte order.
    pub anchor_hash: Hash,
    /// The ID of the winning choice.
    pub choice_id: &'static str,
}

/// One network's historical agenda activations, keyed by agenda ID
/// (dcrd `historicalAgenda`).
pub type HistoricalAgendas = &'static [(&'static str, HistoricalActivationState)];

// The historical agenda activations of the main network and the version
// 3 test network, copied from dcrd `makeHistoricalAgendas`
// (`agendas.go:66-188`).  Each anchor is the parent of the block at
// which the agenda activated, not the activation block a DCP names:
// every descendant of the parent is validated under the new rules,
// including side chain blocks at the activation height.  The hashes
// are in internal byte order; `historical_agenda_tables_match_dcrd`
// pins them against dcrd's display-order literals.
const MAINNET_HISTORICAL_AGENDAS: HistoricalAgendas = &[
    (
        VOTE_ID_SDIFF_ALGORITHM,
        HistoricalActivationState {
            anchor_height: 149247,
            anchor_hash: Hash([
                0x75, 0x9f, 0x9c, 0xe5, 0x00, 0x60, 0xf4, 0x24, 0x27, 0x20, 0xbb, 0xac, 0x48, 0xb2,
                0xe9, 0xf4, 0x52, 0xb3, 0x0b, 0xc2, 0x6b, 0x05, 0x2d, 0x58, 0x39, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_LN_SUPPORT,
        HistoricalActivationState {
            anchor_height: 149247,
            anchor_hash: Hash([
                0x75, 0x9f, 0x9c, 0xe5, 0x00, 0x60, 0xf4, 0x24, 0x27, 0x20, 0xbb, 0xac, 0x48, 0xb2,
                0xe9, 0xf4, 0x52, 0xb3, 0x0b, 0xc2, 0x6b, 0x05, 0x2d, 0x58, 0x39, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_LN_FEATURES,
        HistoricalActivationState {
            anchor_height: 189567,
            anchor_hash: Hash([
                0xae, 0x00, 0x23, 0xaf, 0xd3, 0x65, 0xd8, 0xcb, 0x84, 0xc8, 0x80, 0x3f, 0x06, 0x6d,
                0xd1, 0x1c, 0x8e, 0x12, 0x49, 0x06, 0xef, 0xe4, 0xeb, 0xa2, 0x5c, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_FIX_LN_SEQ_LOCKS,
        HistoricalActivationState {
            anchor_height: 342783,
            anchor_hash: Hash([
                0x1c, 0x40, 0xd7, 0x05, 0x7a, 0x2a, 0x04, 0x93, 0xa4, 0x3d, 0xef, 0x13, 0x1c, 0xee,
                0x73, 0x8e, 0xbb, 0xe9, 0x7a, 0x3c, 0xb6, 0x53, 0xc0, 0x17, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_HEADER_COMMITMENTS,
        HistoricalActivationState {
            anchor_height: 431487,
            anchor_hash: Hash([
                0x26, 0x3c, 0x5c, 0xa9, 0xb4, 0x44, 0xfb, 0x15, 0xc6, 0xee, 0x09, 0xab, 0xd4, 0xfa,
                0x84, 0xc4, 0xeb, 0xd4, 0x04, 0x57, 0x79, 0x8f, 0x5b, 0x22, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_TREASURY,
        HistoricalActivationState {
            anchor_height: 552447,
            anchor_hash: Hash([
                0xcb, 0x9a, 0xdb, 0xaa, 0x78, 0x1a, 0xd4, 0x85, 0xbf, 0xff, 0xdb, 0x34, 0x85, 0xa2,
                0x77, 0x98, 0x2a, 0x63, 0x0f, 0x45, 0x7c, 0xe5, 0xd3, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_REVERT_TREASURY_POLICY,
        HistoricalActivationState {
            anchor_height: 657279,
            anchor_hash: Hash([
                0xaa, 0xfc, 0x22, 0xf8, 0x6a, 0x77, 0x59, 0xf2, 0x0b, 0xa0, 0xdd, 0xcb, 0x89, 0xd8,
                0x2f, 0x9a, 0xd3, 0xda, 0x90, 0xbb, 0x8b, 0xda, 0x69, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        HistoricalActivationState {
            anchor_height: 657279,
            anchor_hash: Hash([
                0xaa, 0xfc, 0x22, 0xf8, 0x6a, 0x77, 0x59, 0xf2, 0x0b, 0xa0, 0xdd, 0xcb, 0x89, 0xd8,
                0x2f, 0x9a, 0xd3, 0xda, 0x90, 0xbb, 0x8b, 0xda, 0x69, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_AUTO_REVOCATIONS,
        HistoricalActivationState {
            anchor_height: 657279,
            anchor_hash: Hash([
                0xaa, 0xfc, 0x22, 0xf8, 0x6a, 0x77, 0x59, 0xf2, 0x0b, 0xa0, 0xdd, 0xcb, 0x89, 0xd8,
                0x2f, 0x9a, 0xd3, 0xda, 0x90, 0xbb, 0x8b, 0xda, 0x69, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        HistoricalActivationState {
            anchor_height: 657279,
            anchor_hash: Hash([
                0xaa, 0xfc, 0x22, 0xf8, 0x6a, 0x77, 0x59, 0xf2, 0x0b, 0xa0, 0xdd, 0xcb, 0x89, 0xd8,
                0x2f, 0x9a, 0xd3, 0xda, 0x90, 0xbb, 0x8b, 0xda, 0x69, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_BLAKE3_POW,
        HistoricalActivationState {
            anchor_height: 794367,
            anchor_hash: Hash([
                0xf0, 0x4e, 0x76, 0x5c, 0x99, 0x4d, 0x86, 0x0e, 0x77, 0xaf, 0xcd, 0x25, 0xea, 0x47,
                0x04, 0x96, 0x5e, 0xd0, 0x09, 0x74, 0xc6, 0xd8, 0x93, 0xc2, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        HistoricalActivationState {
            anchor_height: 794367,
            anchor_hash: Hash([
                0xf0, 0x4e, 0x76, 0x5c, 0x99, 0x4d, 0x86, 0x0e, 0x77, 0xaf, 0xcd, 0x25, 0xea, 0x47,
                0x04, 0x96, 0x5e, 0xd0, 0x09, 0x74, 0xc6, 0xd8, 0x93, 0xc2, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_MAX_TREASURY_SPEND,
        HistoricalActivationState {
            anchor_height: 1052415,
            anchor_hash: Hash([
                0xea, 0xfa, 0x5d, 0x56, 0x9e, 0x5d, 0x02, 0x55, 0x8f, 0x21, 0x08, 0x91, 0x4e, 0x6e,
                0x7e, 0xbc, 0xcd, 0x8f, 0x66, 0xd0, 0x70, 0x24, 0xd4, 0xfb, 0x01, 0x2a, 0x53, 0xfd,
                0xdc, 0x84, 0x1b, 0xbc,
            ]),
            choice_id: "yes",
        },
    ),
];

const TESTNET3_HISTORICAL_AGENDAS: HistoricalAgendas = &[
    (
        VOTE_ID_FIX_LN_SEQ_LOCKS,
        HistoricalActivationState {
            anchor_height: 136847,
            anchor_hash: Hash([
                0x75, 0xf4, 0x64, 0xfa, 0xb7, 0x0c, 0xa4, 0x20, 0x6f, 0xf7, 0x68, 0xb9, 0xec, 0x0b,
                0xfd, 0xe0, 0x0a, 0x91, 0x41, 0x96, 0xe3, 0x1e, 0xb1, 0x37, 0xe0, 0x2d, 0x23, 0x04,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_HEADER_COMMITMENTS,
        HistoricalActivationState {
            anchor_height: 323327,
            anchor_hash: Hash([
                0x6a, 0xb2, 0xa6, 0x13, 0x75, 0x4c, 0x0f, 0x11, 0x89, 0xa5, 0x42, 0x44, 0x71, 0x8c,
                0x5a, 0xc3, 0xc4, 0x94, 0x4c, 0x8b, 0x24, 0xea, 0xbf, 0x7d, 0x6f, 0x14, 0xf7, 0x38,
                0x24, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_TREASURY,
        HistoricalActivationState {
            anchor_height: 560207,
            anchor_hash: Hash([
                0x23, 0xec, 0xc1, 0xc8, 0x5a, 0x59, 0xfe, 0x15, 0x92, 0xed, 0x2a, 0xd2, 0x97, 0xe6,
                0x2d, 0x1c, 0x43, 0x2a, 0xa9, 0xd7, 0x9d, 0xae, 0xc0, 0xb5, 0xb4, 0xef, 0x6c, 0x5b,
                0x4f, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_REVERT_TREASURY_POLICY,
        HistoricalActivationState {
            anchor_height: 867647,
            anchor_hash: Hash([
                0x7b, 0x05, 0x4b, 0x85, 0x62, 0xed, 0x0c, 0xc4, 0xa8, 0xf2, 0xcb, 0x3a, 0x9d, 0x34,
                0x8f, 0xf1, 0xc1, 0x18, 0xa3, 0xce, 0xae, 0x61, 0xea, 0x86, 0x48, 0x13, 0xaf, 0x36,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        HistoricalActivationState {
            anchor_height: 867647,
            anchor_hash: Hash([
                0x7b, 0x05, 0x4b, 0x85, 0x62, 0xed, 0x0c, 0xc4, 0xa8, 0xf2, 0xcb, 0x3a, 0x9d, 0x34,
                0x8f, 0xf1, 0xc1, 0x18, 0xa3, 0xce, 0xae, 0x61, 0xea, 0x86, 0x48, 0x13, 0xaf, 0x36,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_AUTO_REVOCATIONS,
        HistoricalActivationState {
            anchor_height: 867647,
            anchor_hash: Hash([
                0x7b, 0x05, 0x4b, 0x85, 0x62, 0xed, 0x0c, 0xc4, 0xa8, 0xf2, 0xcb, 0x3a, 0x9d, 0x34,
                0x8f, 0xf1, 0xc1, 0x18, 0xa3, 0xce, 0xae, 0x61, 0xea, 0x86, 0x48, 0x13, 0xaf, 0x36,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        HistoricalActivationState {
            anchor_height: 877727,
            anchor_hash: Hash([
                0xac, 0xad, 0xc2, 0xd8, 0x51, 0xf0, 0x96, 0x32, 0xd8, 0xc0, 0x09, 0x3d, 0x5a, 0x82,
                0x4c, 0x85, 0x2c, 0xc0, 0xb2, 0x98, 0x78, 0xa6, 0xd8, 0x8c, 0x52, 0xe9, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_BLAKE3_POW,
        HistoricalActivationState {
            anchor_height: 1170047,
            anchor_hash: Hash([
                0x27, 0xd7, 0xae, 0x5c, 0x98, 0x72, 0xa8, 0x79, 0xb9, 0xa9, 0xda, 0x0b, 0x63, 0x91,
                0x51, 0x21, 0xd7, 0x41, 0xe4, 0xce, 0xe3, 0xa9, 0x6f, 0xae, 0xa6, 0xea, 0xbf, 0x96,
                0xb3, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        HistoricalActivationState {
            anchor_height: 1170047,
            anchor_hash: Hash([
                0x27, 0xd7, 0xae, 0x5c, 0x98, 0x72, 0xa8, 0x79, 0xb9, 0xa9, 0xda, 0x0b, 0x63, 0x91,
                0x51, 0x21, 0xd7, 0x41, 0xe4, 0xce, 0xe3, 0xa9, 0x6f, 0xae, 0xa6, 0xea, 0xbf, 0x96,
                0xb3, 0x00, 0x00, 0x00,
            ]),
            choice_id: "yes",
        },
    ),
    (
        VOTE_ID_MAX_TREASURY_SPEND,
        HistoricalActivationState {
            anchor_height: 1805087,
            anchor_hash: Hash([
                0x8d, 0x24, 0xed, 0x3d, 0x78, 0xf7, 0xac, 0x33, 0x9e, 0x08, 0x15, 0xb4, 0x90, 0x68,
                0xbc, 0x89, 0xbe, 0xd6, 0x0e, 0x8c, 0x4f, 0xad, 0x27, 0x2b, 0xd6, 0xae, 0xba, 0x40,
                0x6c, 0x5c, 0xe2, 0xf3,
            ]),
            choice_id: "yes",
        },
    ),
];

/// The historical agenda activations for the given network: the main
/// and version 3 test networks have them, and every other network has
/// none (dcrd `makeHistoricalAgendas()[net]`).
pub fn historical_agendas(net: CurrencyNet) -> HistoricalAgendas {
    match net {
        CurrencyNet::MAIN_NET => MAINNET_HISTORICAL_AGENDAS,
        CurrencyNet::TEST_NET3 => TESTNET3_HISTORICAL_AGENDAS,
        _ => &[],
    }
}

/// The historical activation the table holds for the agenda, if any.
fn historical_entry<'t>(
    historical: &'t [(&'static str, HistoricalActivationState)],
    agenda_id: &str,
) -> Option<&'t HistoricalActivationState> {
    historical
        .iter()
        .find(|(id, _)| *id == agenda_id)
        .map(|(_, state)| state)
}

/// The vote bit approving the parent block's regular transaction tree
/// (dcrd `dcrutil.BlockValid`), which no agenda mask may use.
const BLOCK_VALID: u16 = 0x0001;

/// Whether the network is the main network (dcrd `isMainNet`).
fn is_main_net(params: &Params) -> bool {
    params.net == CurrencyNet::MAIN_NET
}

/// dcrd's `ErrUnknownAgendaID` for an agenda ID the network does not
/// define (`agendas.go:695-698`, `:719-722`).
pub fn unknown_agenda_error(agenda_id: &str) -> RuleError {
    rule_error(
        RuleErrorKind::UnknownAgendaID,
        format!("agenda ID {agenda_id} does not exist"),
    )
}

/// Ensure the vote choices conform to the semantics the vote tallying
/// and state determination logic requires (dcrd
/// `validateDeploymentChoices`, `agendas.go:210-327`).
pub fn validate_deployment_choices(vote: &Vote) -> Result<(), RuleError> {
    // Ensure the mask is not zero.
    if vote.mask == 0 {
        return Err(rule_error(
            RuleErrorKind::DeploymentBadMask,
            format!("deployment ID {} mask is zero", vote.id),
        ));
    }

    // Ensure the mask does not use the bit reserved to specify whether
    // or not the voters approve the regular transaction tree of the
    // parent block.
    if vote.mask & BLOCK_VALID != 0 {
        return Err(rule_error(
            RuleErrorKind::DeploymentBadMask,
            format!(
                "deployment ID {} mask {:#06x} uses reserved bit 0",
                vote.id, vote.mask
            ),
        ));
    }

    // Count the number of consecutive 1 bits set in the mask.
    let mut consec_ones: u32 = 0;
    let mut v = vote.mask;
    while v != 0 {
        v &= v.wrapping_shl(1);
        consec_ones = consec_ones.wrapping_add(1);
    }

    // Ensure the mask only consists of consecutive bits.
    let mask_population_count = vote.mask.count_ones();
    if consec_ones != mask_population_count {
        return Err(rule_error(
            RuleErrorKind::DeploymentBadMask,
            format!(
                "deployment ID {} mask {:#06x} does not have consecutive bits",
                vote.id, vote.mask
            ),
        ));
    }

    // Ensure there are not more choices than the mask bits can
    // represent.
    let num_choices = vote.choices.len();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the population count of a u16 mask is at most 16, so the shift is in range"
    )]
    let max_choices = 1usize << mask_population_count;
    if num_choices > max_choices {
        return Err(rule_error(
            RuleErrorKind::DeploymentTooManyChoices,
            format!(
                "deployment ID {} has {num_choices} choices for mask {:#06x} which can only \
                 represent {max_choices} choices",
                vote.id, vote.mask
            ),
        ));
    }

    let mut num_abstain: usize = 0;
    let mut num_no: usize = 0;
    let mut dups: BTreeMap<String, usize> = BTreeMap::new();
    for (choice_idx, choice) in vote.choices.iter().enumerate() {
        // Ensure the id is not empty.
        if choice.id.is_empty() {
            return Err(rule_error(
                RuleErrorKind::DeploymentMissingChoiceID,
                format!(
                    "deployment ID {} choice index {choice_idx} does not have an ID",
                    vote.id
                ),
            ));
        }

        // Ensure that the choice bits are not zero for all choices
        // except the abstain choice.
        if choice.bits == 0 && !choice.is_abstain {
            return Err(rule_error(
                RuleErrorKind::DeploymentBadChoiceBits,
                format!(
                    "deployment ID {} choice ID {} (index {choice_idx}) vote bits are zero for \
                     choice that is not marked abstain",
                    vote.id, choice.id
                ),
            ));
        }

        // Ensure the bits for the choice are a subset of the mask.
        if vote.mask & choice.bits != choice.bits {
            return Err(rule_error(
                RuleErrorKind::DeploymentBadChoiceBits,
                format!(
                    "deployment ID {} choice ID {} (index {choice_idx}) vote bits {:#06x} are not \
                     covered by the mask {:04x}",
                    vote.id, choice.id, choice.bits, vote.mask
                ),
            ));
        }

        // Ensure only one of the choice type identification flags are
        // set.
        if choice.is_abstain && choice.is_no {
            return Err(rule_error(
                RuleErrorKind::DeploymentNonExclusiveFlags,
                format!(
                    "deployment ID {} choice ID {} (index {choice_idx}) has both the abstain and \
                     no choice flags set",
                    vote.id, choice.id
                ),
            ));
        }

        // Count flags.
        if choice.is_abstain {
            num_abstain = num_abstain.wrapping_add(1);
        }
        if choice.is_no {
            num_no = num_no.wrapping_add(1);
        }

        // Ensure there are not any duplicates.
        let id = choice.id.to_lowercase();
        if let Some(orig_choice_idx) = dups.get(&id) {
            return Err(rule_error(
                RuleErrorKind::DeploymentDuplicateChoice,
                format!(
                    "deployment ID {} choice ID {} at index {choice_idx} already exists for the \
                     choice at index {orig_choice_idx}",
                    vote.id, choice.id
                ),
            ));
        }
        dups.insert(id, choice_idx);
    }

    // Ensure there is one and only one of each choice type
    // identification flag set.
    if num_abstain == 0 {
        return Err(rule_error(
            RuleErrorKind::DeploymentMissingAbstain,
            format!("deployment ID {} does not have an abstain choice", vote.id),
        ));
    }
    if num_abstain > 1 {
        return Err(rule_error(
            RuleErrorKind::DeploymentTooManyAbstain,
            format!("deployment ID {} has more than one abstain choice", vote.id),
        ));
    }
    if num_no == 0 {
        return Err(rule_error(
            RuleErrorKind::DeploymentMissingNo,
            format!("deployment ID {} does not have a no choice", vote.id),
        ));
    }
    if num_no > 1 {
        return Err(rule_error(
            RuleErrorKind::DeploymentTooManyNo,
            format!("deployment ID {} has more than one no choice", vote.id),
        ));
    }

    Ok(())
}

/// The threshold state and choice a deployment's forced choice fixes,
/// `None` when it has no forced choice, or an error when the choice
/// does not exist or is the abstain choice (dcrd
/// `determineForcedThresholdState`, `agendas.go:333-374`).
pub fn determine_forced_threshold_state(
    deployment: &ConsensusDeployment,
) -> Result<Option<ThresholdStateTuple>, RuleError> {
    // Nothing to extract when there is no forced choice.
    let forced_choice_id = deployment.forced_choice_id;
    if forced_choice_id.is_empty() {
        return Ok(None);
    }
    let deployment_id = deployment.vote.id;

    // Attempt to find the choice with the ID that matches the forced
    // choice and ensure it exists.
    let Some(forced_choice) = deployment
        .vote
        .choices
        .iter()
        .find(|c| c.id == forced_choice_id)
    else {
        return Err(rule_error(
            RuleErrorKind::UnknownDeploymentChoice,
            format!(
                "deployment ID {deployment_id} forced choice {forced_choice_id:?} does not \
                 exist in the chain parameters"
            ),
        ));
    };

    // The forced choice must not be the abstain choice because it must
    // resolve to either an active or failed state.
    if forced_choice.is_abstain {
        return Err(rule_error(
            RuleErrorKind::DeploymentChoiceAbstain,
            format!(
                "deployment ID {deployment_id} forced choice {forced_choice_id:?} is of type \
                 abstain which is not a valid forced choice"
            ),
        ));
    }

    let state = if forced_choice.is_no {
        ThresholdState::Failed
    } else {
        ThresholdState::Active
    };
    Ok(Some(new_threshold_state(state, forced_choice_id)))
}

/// A consensus rule change agenda (dcrd `consensusAgenda`,
/// `agendas.go:401-435`), less the cached activation anchor, which the
/// port keeps per chain behind the [`VoteChainView`] anchor hooks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConsensusAgenda<'a> {
    /// The state to use instead of determining one by other means: set
    /// when the deployment has a forced choice, or for a required
    /// agenda the network defines no deployment for.
    pub forced_state: Option<ThresholdStateTuple>,
    /// The hard-coded historical activation, set only when the table
    /// for the network has one, the agenda has no forced state, and the
    /// winning choice is not the no choice.
    pub historical_state: Option<HistoricalActivationState>,
    /// The deployment version and parameters, set only for an agenda
    /// that comes from a deployment and has no forced state.
    pub deployment: Option<(u32, &'a ConsensusDeployment)>,
}

/// The agenda for a deployment, before any historical activation is
/// attached: the forced state from its forced choice, and otherwise the
/// deployment itself (the per-deployment body of dcrd `makeAgendas`,
/// `agendas.go:481-507`).  Forced choices are refused on the main
/// network.
fn deployment_agenda<'a>(
    params: &Params,
    version: u32,
    deployment: &'a ConsensusDeployment,
) -> Result<ConsensusAgenda<'a>, RuleError> {
    // Determine the forced threshold state when the deployment has a
    // forced choice specified.
    let forced_state = determine_forced_threshold_state(deployment)?;

    // Prevent forced choices on the main network.
    if is_main_net(params) && forced_state.is_some() {
        return Err(rule_error(
            RuleErrorKind::ForcedMainNetChoice,
            format!(
                "deployment ID {} has a forced choice for the main network",
                deployment.vote.id
            ),
        ));
    }

    Ok(ConsensusAgenda {
        forced_state,
        historical_state: None,
        deployment: forced_state.is_none().then_some((version, deployment)),
    })
}

/// Resolve a historical activation's winning choice against the
/// deployment's vote choices (dcrd `makeAgendas`, `agendas.go:537-569`):
/// an unknown or abstain winner is an error, and a no winner leaves the
/// agenda without a historical activation.
fn resolve_historical_choice(
    agenda_id: &str,
    entry: &HistoricalActivationState,
    deployment: &ConsensusDeployment,
) -> Result<Option<HistoricalActivationState>, RuleError> {
    let Some(winning_choice) = deployment
        .vote
        .choices
        .iter()
        .find(|c| c.id == entry.choice_id)
    else {
        return Err(rule_error(
            RuleErrorKind::UnknownDeploymentChoice,
            format!(
                "deployment ID {agenda_id} has a historical state with unknown winning choice \
                 {:?}",
                entry.choice_id
            ),
        ));
    };
    if winning_choice.is_abstain {
        return Err(rule_error(
            RuleErrorKind::DeploymentChoiceAbstain,
            format!(
                "deployment ID {agenda_id} historical state choice {:?} is of invalid type \
                 abstain",
                entry.choice_id
            ),
        ));
    }

    // Only changes that passed are historical activations.
    if winning_choice.is_no {
        return Ok(None);
    }

    Ok(Some(HistoricalActivationState {
        anchor_height: entry.anchor_height,
        anchor_hash: entry.anchor_hash,
        choice_id: winning_choice.id,
    }))
}

/// The historical activation the table attaches to the deployment's
/// agenda when it has no forced state, resolved as
/// [`make_agendas`] resolves it; `Ok(None)` when the table has no entry
/// for it or the winner is the no choice.
pub(crate) fn resolve_historical_state(
    historical: &[(&'static str, HistoricalActivationState)],
    deployment: &ConsensusDeployment,
) -> Result<Option<HistoricalActivationState>, RuleError> {
    let agenda_id = deployment.vote.id;
    match historical_entry(historical, agenda_id) {
        Some(entry) => resolve_historical_choice(agenda_id, entry, deployment),
        None => Ok(None),
    }
}

/// Attach a historical activation to an existing agenda (the body of
/// dcrd `makeAgendas`' historical loop, `agendas.go:523-570`).
fn attach_historical(
    agenda: &mut ConsensusAgenda<'_>,
    agenda_id: &str,
    entry: &HistoricalActivationState,
) -> Result<(), RuleError> {
    if agenda.forced_state.is_some() {
        return Err(rule_error(
            RuleErrorKind::HistoricalForcedChoice,
            format!(
                "agenda ID {agenda_id} has both a forced choice and a historical state configured"
            ),
        ));
    }
    let (_, deployment) = agenda
        .deployment
        .expect("an agenda without a forced state has a deployment");
    agenda.historical_state = resolve_historical_choice(agenda_id, entry, deployment)?;
    Ok(())
}

/// The error for a historical activation of an agenda no deployment
/// defines (dcrd `makeAgendas`, `agendas.go:526-529`).  The historical
/// loop runs before the required defaults exist, so this holds for a
/// required agenda too.
fn unknown_historical_agenda_error(agenda_id: &str) -> RuleError {
    rule_error(
        RuleErrorKind::UnknownAgendaID,
        format!("agenda ID {agenda_id} for historical consensus change does not exist"),
    )
}

/// The default agenda for a required agenda the network defines no
/// deployment for: forced inactive on the main network and active, with
/// an empty choice, on every other network (dcrd `makeAgendas`,
/// `agendas.go:575-589`).
fn default_agenda<'a>(params: &Params) -> ConsensusAgenda<'a> {
    let forced_state = if is_main_net(params) {
        new_threshold_state(ThresholdState::Defined, "")
    } else {
        new_threshold_state(ThresholdState::Active, "")
    };
    ConsensusAgenda {
        forced_state: Some(forced_state),
        historical_state: None,
        deployment: None,
    }
}

/// The consensus rule change agendas for the chain parameters with the
/// given historical activations, keyed by agenda ID, after validating
/// every deployment (dcrd `makeAgendas`, `agendas.go:449-592`).
///
/// The map holds an agenda for every deployment and every required
/// agenda.  The checks refuse duplicate deployment IDs, masks that
/// overlap within a deployment version, malformed vote choices,
/// unusable forced choices, forced choices on the main network, and
/// historical activations of unknown or forced agendas or with an
/// unknown or abstain winner.
pub fn make_agendas<'a>(
    params: &'a Params,
    historical: &[(&'static str, HistoricalActivationState)],
) -> Result<BTreeMap<&'static str, ConsensusAgenda<'a>>, RuleError> {
    // Create an agenda for each deployment specified in the chain
    // params.
    let mut agendas: BTreeMap<&'static str, ConsensusAgenda<'a>> = BTreeMap::new();
    for (version, deployments) in &params.deployments {
        let mut used_mask_bits: u16 = 0;
        for deployment in deployments {
            let id = deployment.vote.id;
            if agendas.contains_key(id) {
                return Err(rule_error(
                    RuleErrorKind::DuplicateDeployment,
                    format!("deployment ID {id} exists in more than one deployment"),
                ));
            }

            // Ensure the masks in all deployments for the same version
            // do not have any shared bits.
            let vote = &deployment.vote;
            if vote.mask & used_mask_bits != 0 {
                return Err(rule_error(
                    RuleErrorKind::DeploymentBadMask,
                    format!(
                        "deployment ID {} mask {:#06x} uses bits that are already used by other \
                         votes in the deployment (used bits {used_mask_bits:#06x})",
                        vote.id, vote.mask
                    ),
                ));
            }
            used_mask_bits |= vote.mask;

            // Ensure the deployment choices conform to the semantics
            // expected by the vote tallying threshold state logic.
            validate_deployment_choices(vote)?;

            agendas.insert(id, deployment_agenda(params, *version, deployment)?);
        }
    }

    // Add the historical consensus change details.  This currently
    // requires an associated deployment, since the state change and
    // vote queries depend on one.
    for (id, entry) in historical {
        let Some(agenda) = agendas.get_mut(id) else {
            return Err(unknown_historical_agenda_error(id));
        };
        attach_historical(agenda, id, entry)?;
    }

    // Create a default agenda for each required agenda that has no
    // associated deployment.
    for id in REQUIRED_AGENDA_IDS {
        agendas.entry(id).or_insert_with(|| default_agenda(params));
    }

    Ok(agendas)
}

/// Locate the deployment with the given vote ID along with its version
/// (the deployment `makeAgendas` builds the ID's agenda from).
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

/// The agenda with the given ID exactly as [`make_agendas`] builds it
/// for the parameters and historical activations, or dcrd's
/// `ErrUnknownAgendaID` when the network has no such agenda (dcrd's
/// `b.agendas[agendaID]` lookup).
///
/// The per-agenda steps are the ones [`make_agendas`] runs, in its
/// order.  The checks that span deployments or only validate a vote's
/// shape (duplicate IDs, overlapping masks, malformed choices) are left
/// to [`make_agendas`], which chain construction runs.
pub fn lookup_agenda<'a>(
    params: &'a Params,
    historical: &[(&'static str, HistoricalActivationState)],
    agenda_id: &str,
) -> Result<ConsensusAgenda<'a>, RuleError> {
    let entry = historical_entry(historical, agenda_id);
    let Some((version, deployment)) = find_deployment(params, agenda_id) else {
        if entry.is_some() {
            return Err(unknown_historical_agenda_error(agenda_id));
        }
        if REQUIRED_AGENDA_IDS.contains(&agenda_id) {
            return Ok(default_agenda(params));
        }
        return Err(unknown_agenda_error(agenda_id));
    };
    let mut agenda = deployment_agenda(params, version, deployment)?;
    if let Some(entry) = entry {
        attach_historical(&mut agenda, agenda_id, entry)?;
    }
    Ok(agenda)
}

/// Whether a positional agenda query result is valid and, when it is,
/// whether the agenda is active (dcrd `agendaActiveInfo`,
/// `agendas.go:596-599`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AgendaActiveInfo {
    /// Whether the result could be determined.
    pub is_valid: bool,
    /// Whether the agenda is active; only meaningful when valid.
    pub is_active: bool,
}

/// Whether the agenda is active for the block AFTER the given node,
/// using only information that depends on the block's position in the
/// chain and the headers of its ancestors -- never their block data,
/// and never the agenda's deployment (dcrd `isAgendaActivePositional`,
/// `agendas.go:620-679`).
///
/// The result is valid when the agenda is forced, when the parent of
/// its activation block is a historical fact, or when its activation
/// was discovered while tallying votes on a full-context path.  A
/// historical anchor that resolves along this branch is cached as the
/// agenda's activation anchor.
pub fn is_agenda_active_positional(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    agenda_id: &str,
    agenda: &ConsensusAgenda<'_>,
) -> AgendaActiveInfo {
    // Agendas are never active for the genesis block.
    let Some(prev_height) = prev_height else {
        return AgendaActiveInfo {
            is_valid: true,
            is_active: false,
        };
    };

    // Forced states are independent of chain position and take
    // precedence.
    if let Some(state) = agenda.forced_state {
        return AgendaActiveInfo {
            is_valid: true,
            is_active: state.state == ThresholdState::Active,
        };
    }

    // The agenda is definitively inactive when the activation height is
    // a known historical fact and the queried block is before the
    // anchor.  The anchor is the parent of the activation block and the
    // queried block is one above the given parent, so the comparison is
    // exclusive.
    let historical = agenda.historical_state;
    if let Some(hs) = historical
        && prev_height < hs.anchor_height
    {
        return AgendaActiveInfo {
            is_valid: true,
            is_active: false,
        };
    }

    // Use the previously cached anchor when it exists and is an
    // ancestor of the queried block (which includes the anchor itself).
    if view.active_anchor_cached(agenda_id, prev_height).is_some() {
        return AgendaActiveInfo {
            is_valid: true,
            is_active: true,
        };
    }

    // Attempt to resolve a known historical activation anchor through
    // the ancestry of the queried block itself.  Unrelated side chains
    // are handled because the anchor is only cached when its hash
    // matches, and only used when it is an ancestor.
    if let Some(hs) = historical
        && prev_height >= hs.anchor_height
        && view.ancestor_hash(hs.anchor_height) == Some(hs.anchor_hash.0)
    {
        view.cache_active_anchor(agenda_id, hs.anchor_height, hs.choice_id);
        return AgendaActiveInfo {
            is_valid: true,
            is_active: true,
        };
    }

    AgendaActiveInfo::default()
}

/// [`is_agenda_active_positional`] for the agenda with the given ID,
/// or dcrd's `ErrUnknownAgendaID` when the network has no such agenda
/// (dcrd `isAgendaActivePositionalByID`, `agendas.go:693-702`).
pub fn is_agenda_active_positional_by_id(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    agenda_id: &str,
    params: &Params,
) -> Result<AgendaActiveInfo, RuleError> {
    let agenda = lookup_agenda(params, view.historical_agendas(params.net), agenda_id)?;
    Ok(is_agenda_active_positional(
        view,
        prev_height,
        agenda_id,
        &agenda,
    ))
}

/// Whether the agenda with the given ID is active for the block AFTER
/// the given node (dcrd `isAgendaActive`, `agendas.go:717-745`), the
/// shared body of every single-choice agenda query.
///
/// The agenda is looked up first, so an unknown ID is dcrd's
/// `ErrUnknownAgendaID` even for the genesis block.  Agendas are never
/// active for the genesis block (`None`), forced or not.  Otherwise the
/// positional query answers when it can, and the vote tally answers
/// the rest.  Only the state is examined, never the choice, which
/// assumes the agenda has a single passing choice.
pub fn is_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    agenda_id: &str,
    params: &Params,
) -> Result<bool, RuleError> {
    let agenda = lookup_agenda(params, view.historical_agendas(params.net), agenda_id)?;

    // Agendas are never active for the genesis block.
    if prev_height.is_none() {
        return Ok(false);
    }

    // Attempt the faster positional path first: forced agendas, cached
    // anchors and hard-coded historical activations.
    let info = is_agenda_active_positional(view, prev_height, agenda_id, &agenda);
    if info.is_valid {
        return Ok(info.is_active);
    }

    // Determine the status by tallying votes.
    let state = agenda_state(view, prev_height, agenda_id, &agenda, params);
    Ok(state.state == ThresholdState::Active)
}

/// Whether the max block size agenda, whose vote only took place on an
/// earlier version of the test network, is active for the block AFTER
/// the given node (dcrd `isMaxBlockSizeAgendaActive`,
/// `agendas.go:804-807`).
pub fn is_max_block_size_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_MAX_BLOCK_SIZE, params)
}

/// Whether the DCP0001 stake difficulty algorithm agenda is active for
/// the block AFTER the given node (dcrd `isSDiffAlgoAgendaActive`,
/// `agendas.go:819-822`).
pub fn is_sdiff_algo_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_SDIFF_ALGORITHM, params)
}

/// Whether the DCP0002/DCP0003 LN features agenda is active for the
/// block AFTER the given node (dcrd `isLNFeaturesAgendaActive`).
pub fn is_ln_features_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_LN_FEATURES, params)
}

/// Whether the DCP0005 header commitments agenda is active for the
/// block AFTER the given node (dcrd
/// `isHeaderCommitmentsAgendaActive`).
pub fn is_header_commitments_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_HEADER_COMMITMENTS, params)
}

/// Whether the DCP0006 treasury agenda is active for the block AFTER
/// the given node (dcrd `isTreasuryAgendaActive`,
/// `agendas.go:882-890`).  The genesis block and block 1 are special
/// and always inactive, ahead of the agenda lookup.
pub fn is_treasury_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    // Ignore block 0 and 1 because they are special.
    if matches!(prev_height, None | Some(0)) {
        return Ok(false);
    }
    is_agenda_active(view, prev_height, VOTE_ID_TREASURY, params)
}

/// Whether the DCP0007 revert treasury expenditure policy agenda is
/// active for the block AFTER the given node (dcrd
/// `isRevertTreasuryPolicyActive`).
pub fn is_revert_treasury_policy_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_REVERT_TREASURY_POLICY, params)
}

/// Whether the DCP0008 explicit version upgrades agenda is active for
/// the block AFTER the given node (dcrd
/// `isExplicitVerUpgradesAgendaActive`).
pub fn is_explicit_ver_upgrades_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_EXPLICIT_VERSION_UPGRADES, params)
}

/// Whether the DCP0009 automatic ticket revocations agenda is active
/// for the block AFTER the given node (dcrd
/// `isAutoRevocationsAgendaActive`).
pub fn is_auto_revocations_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_AUTO_REVOCATIONS, params)
}

/// Whether the DCP0010 subsidy split agenda is active for the block
/// AFTER the given node (dcrd `isSubsidySplitAgendaActive`).
pub fn is_subsidy_split_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_CHANGE_SUBSIDY_SPLIT, params)
}

/// Whether the DCP0011 BLAKE3 proof of work agenda is active for the
/// block AFTER the given node (dcrd `isBlake3PowAgendaActive`).
pub fn is_blake3_pow_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_BLAKE3_POW, params)
}

/// Whether the DCP0012 subsidy split round 2 agenda is active for the
/// block AFTER the given node (dcrd `isSubsidySplitR2AgendaActive`).
pub fn is_subsidy_split_r2_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2, params)
}

/// Whether the DCP0013 maximum treasury spend agenda is active for the
/// block AFTER the given node (dcrd `isMaxTreasurySpendAgendaActive`).
pub fn is_max_treasury_spend_agenda_active(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<bool, RuleError> {
    is_agenda_active(view, prev_height, VOTE_ID_MAX_TREASURY_SPEND, params)
}

/// Whether the DCP0011 BLAKE3 proof of work agenda is forced active on
/// this network, by a forced choice or as a required agenda's default
/// (dcrd `isBlake3PowAgendaForcedActive`, `agendas.go:1002-1011`).
pub fn is_blake3_pow_agenda_forced_active(params: &Params) -> bool {
    // A forced state does not depend on the historical activations.
    lookup_agenda(params, &[], VOTE_ID_BLAKE3_POW)
        .ok()
        .and_then(|agenda| agenda.forced_state)
        .is_some_and(|state| state.state == ThresholdState::Active)
}

/// The maximum allowed block size for the block AFTER the given node
/// (dcrd `maxBlockSize`, `chain.go:1615-1638`).
///
/// The larger size applies only when the max block size agenda is
/// active and the parameters actually define a second size: agendas a
/// network defines no deployment for are active by default off the main
/// network, and the version 3 test network lists a single size.
pub fn max_block_size(
    view: &impl VoteChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<i64, RuleError> {
    let is_active = is_max_block_size_agenda_active(view, prev_height, params)?;
    let max_sizes = &params.maximum_block_sizes;
    if is_active && max_sizes.len() > 1 {
        return Ok(max_sizes[1] as i64);
    }
    Ok(max_sizes[0] as i64)
}

/// A view that provides both the difficulty node data and the full
/// vote data the agenda checks need.
pub trait FullChainView: ChainView + VoteChainView {}
impl<T: ChainView + VoteChainView> FullChainView for T {}

/// The anchor block for BLAKE3 difficulty calculations: the final block
/// of the interval just before the agenda activated (dcrd
/// `blake3WorkDiffAnchor`).  The anchor found is recorded as the
/// view's confirmed anchor, which the positional difficulty check
/// then enforces.
fn blake3_work_diff_anchor(
    view: &impl FullChainView,
    prev_height: i64,
    params: &Params,
) -> Option<DiffNode> {
    // Use the previously cached anchor when it exists and is actually
    // an ancestor of the passed node.
    if let Some(anchor_height) = view.blake3_anchor_cached(prev_height) {
        return ChainView::node(view, anchor_height);
    }

    let rcai = i64::from(params.rule_change_activation_interval);
    let svh = params.stake_validation_height;

    // Determine the final node of the previous rule change interval.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "prev_height is a block height (a u32 header height widened to i64)"
    )]
    let final_node_height = calc_want_height(svh, rcai, prev_height + 1);
    let mut candidate_height = final_node_height;
    let mut anchor = None;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "candidate.height >= 1 since height 0 breaks above, and candidate_height >= 0 \
                  by the loop condition, less the u32 rcai"
    )]
    while candidate_height >= 0 {
        let Some(candidate) = ChainView::node(view, candidate_height) else {
            break;
        };
        if candidate.height == 0 {
            break;
        }
        let is_active = is_blake3_pow_agenda_active(view, Some(candidate.height - 1), params)
            .expect("known good agenda state lookup");
        if !is_active {
            anchor = Some(candidate);
            break;
        }
        candidate_height -= rcai;
    }

    // Update the cached anchor to the discovered one since it is
    // highly likely the next call will involve a descendant of this
    // anchor as opposed to some other anchor on an entirely unrelated
    // side chain.
    if let Some(anchor) = &anchor {
        view.cache_blake3_anchor(anchor.height);
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
) -> Result<u32, RuleError> {
    let is_active = is_blake3_pow_agenda_active(view, Some(prev_node.height), params)?;
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
/// (dcrd `calcNextRequiredStakeDifficulty`, `difficulty.go:860-871`).
pub fn calc_next_required_stake_difficulty(
    view: &impl FullChainView,
    cur_node: Option<&DiffNode>,
    params: &Params,
) -> Result<i64, RuleError> {
    // Choose the stake difficulty algorithm based on the result of the
    // vote for the stake difficulty algorithm agenda.
    if is_sdiff_algo_agenda_active(view, cur_node.map(|n| n.height), params)? {
        return Ok(calc_next_required_stake_difficulty_v2(
            view, cur_node, params,
        ));
    }
    Ok(calc_next_required_stake_difficulty_v1(
        view, cur_node, params,
    ))
}

/// Estimate the next stake difficulty by pretending the given number
/// of tickets will be purchased in the remainder of the interval, or
/// the maximum possible number when the flag is set, selecting the
/// algorithm based on the DCP0001 agenda state (dcrd
/// `estimateNextStakeDifficulty`, `difficulty.go:1335-1347`).  The
/// error is the message of dcrd's error.
pub fn estimate_next_stake_difficulty(
    view: &impl FullChainView,
    cur_node: Option<&DiffNode>,
    new_tickets: i64,
    use_max_tickets: bool,
    params: &Params,
) -> Result<i64, String> {
    // Choose the stake difficulty algorithm based on the result of the
    // vote for the stake difficulty algorithm agenda.
    let is_active = is_sdiff_algo_agenda_active(view, cur_node.map(|n| n.height), params)
        .map_err(|e| e.description)?;
    if is_active {
        return estimate_next_stake_difficulty_v2(
            view,
            cur_node,
            new_tickets,
            use_max_tickets,
            params,
        );
    }
    estimate_next_stake_difficulty_v1(view, cur_node, new_tickets, use_max_tickets, params)
}
