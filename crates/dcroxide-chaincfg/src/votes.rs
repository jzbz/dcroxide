// SPDX-License-Identifier: ISC
//! Canonical consensus agenda vote definitions.
//!
//! dcrd repeats each `Vote` literal verbatim in every per-network params
//! file; the definitions are identical across networks (only the deployment
//! schedule around them — version key, start/expire times, forced choice —
//! differs). The constructors here are that single canonical copy, pinned
//! against dcrd by the per-network dump differential.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Choice, Vote};

/// Vote ID for the max block size increase agenda (dcrd
/// `VoteIDMaxBlockSize`).
pub const VOTE_ID_MAX_BLOCK_SIZE: &str = "maxblocksize";
/// Vote ID for the DCP0001 stake difficulty algorithm agenda.
pub const VOTE_ID_SDIFF_ALGORITHM: &str = "sdiffalgorithm";
/// Vote ID for the LN support development agenda (mainnet only).
pub const VOTE_ID_LN_SUPPORT: &str = "lnsupport";
/// Vote ID for the DCP0002/DCP0003 LN features agenda.
pub const VOTE_ID_LN_FEATURES: &str = "lnfeatures";
/// Vote ID for the DCP0004 sequence lock fix agenda.
pub const VOTE_ID_FIX_LN_SEQ_LOCKS: &str = "fixlnseqlocks";
/// Vote ID for the DCP0005 header commitments agenda.
pub const VOTE_ID_HEADER_COMMITMENTS: &str = "headercommitments";
/// Vote ID for the DCP0006 decentralized treasury agenda.
pub const VOTE_ID_TREASURY: &str = "treasury";
/// Vote ID for the DCP0007 treasury policy revert agenda.
pub const VOTE_ID_REVERT_TREASURY_POLICY: &str = "reverttreasurypolicy";
/// Vote ID for the DCP0008 explicit version upgrades agenda.
pub const VOTE_ID_EXPLICIT_VERSION_UPGRADES: &str = "explicitverupgrades";
/// Vote ID for the DCP0009 automatic ticket revocations agenda.
pub const VOTE_ID_AUTO_REVOCATIONS: &str = "autorevocations";
/// Vote ID for the DCP0010 subsidy split change agenda.
pub const VOTE_ID_CHANGE_SUBSIDY_SPLIT: &str = "changesubsidysplit";
/// Vote ID for the DCP0011 BLAKE3 proof of work agenda.
pub const VOTE_ID_BLAKE3_POW: &str = "blake3pow";
/// Vote ID for the DCP0012 subsidy split round 2 agenda.
pub const VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2: &str = "changesubsidysplitr2";
/// Vote ID for the DCP0013 max treasury expenditure agenda.
pub const VOTE_ID_MAX_TREASURY_SPEND: &str = "maxtreasuryspend";

/// The recurring three-choice layout: abstain (bits 0), hard no, yes.
fn choices(
    abstain_description: &'static str,
    no_description: &'static str,
    no_bits: u16,
    yes_description: &'static str,
    yes_bits: u16,
) -> Vec<Choice> {
    vec![
        Choice {
            id: "abstain",
            description: abstain_description,
            bits: 0x0000,
            is_abstain: true,
            is_no: false,
        },
        Choice {
            id: "no",
            description: no_description,
            bits: no_bits,
            is_abstain: false,
            is_no: true,
        },
        Choice {
            id: "yes",
            description: yes_description,
            bits: yes_bits,
            is_abstain: false,
            is_no: false,
        },
    ]
}

pub(crate) fn max_block_size_vote() -> Vote {
    Vote {
        id: VOTE_ID_MAX_BLOCK_SIZE,
        description: "Change maximum allowed block size from 1MiB to 1.25MB",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "reject changing max allowed block size",
            0x0002,
            "accept changing max allowed block size",
            0x0004,
        ),
    }
}

pub(crate) fn sdiff_algorithm_vote() -> Vote {
    Vote {
        id: VOTE_ID_SDIFF_ALGORITHM,
        description: "Change stake difficulty algorithm as defined in DCP0001",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing algorithm",
            0x0002,
            "change to the new algorithm",
            0x0004,
        ),
    }
}

pub(crate) fn ln_support_vote() -> Vote {
    Vote {
        id: VOTE_ID_LN_SUPPORT,
        description: "Request developers begin work on Lightning Network (LN) integration",
        mask: 0x0018,
        choices: choices(
            "abstain from voting",
            "no, do not work on integrating LN support",
            0x0008,
            "yes, begin work on integrating LN support",
            0x0010,
        ),
    }
}

pub(crate) fn ln_features_vote() -> Vote {
    Vote {
        id: VOTE_ID_LN_FEATURES,
        description: "Enable features defined in DCP0002 and DCP0003 necessary to support \
                      Lightning Network (LN)",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn fix_ln_seq_locks_vote() -> Vote {
    Vote {
        id: VOTE_ID_FIX_LN_SEQ_LOCKS,
        description: "Modify sequence lock handling as defined in DCP0004",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn header_commitments_vote() -> Vote {
    Vote {
        id: VOTE_ID_HEADER_COMMITMENTS,
        description: "Enable header commitments as defined in DCP0005",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn treasury_vote() -> Vote {
    Vote {
        id: VOTE_ID_TREASURY,
        description: "Enable decentralized Treasury opcodes as defined in DCP0006",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn revert_treasury_policy_vote() -> Vote {
    Vote {
        id: VOTE_ID_REVERT_TREASURY_POLICY,
        description: "Change maximum treasury expenditure policy as defined in DCP0007",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn explicit_version_upgrades_vote() -> Vote {
    Vote {
        id: VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        description: "Enable explicit version upgrades as defined in DCP0008",
        mask: 0x0018,
        choices: choices(
            "abstain from voting",
            "keep the existing consensus rules",
            0x0008,
            "change to the new consensus rules",
            0x0010,
        ),
    }
}

pub(crate) fn auto_revocations_vote() -> Vote {
    Vote {
        id: VOTE_ID_AUTO_REVOCATIONS,
        description: "Enable automatic ticket revocations as defined in DCP0009",
        mask: 0x0060,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0020,
            "change to the new consensus rules",
            0x0040,
        ),
    }
}

pub(crate) fn change_subsidy_split_vote() -> Vote {
    Vote {
        id: VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        description: "Change block reward subsidy split to 10/80/10 as defined in DCP0010",
        mask: 0x0180,
        choices: choices(
            "abstain from voting",
            "keep the existing consensus rules",
            0x0080,
            "change to the new consensus rules",
            0x0100,
        ),
    }
}

pub(crate) fn blake3_pow_vote() -> Vote {
    Vote {
        id: VOTE_ID_BLAKE3_POW,
        description: "Change proof of work hashing algorithm to BLAKE3 as defined in DCP0011",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}

pub(crate) fn change_subsidy_split_r2_vote() -> Vote {
    Vote {
        id: VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        description: "Change block reward subsidy split to 1/89/10 as defined in DCP0012",
        mask: 0x0060,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0020,
            "change to the new consensus rules",
            0x0040,
        ),
    }
}

pub(crate) fn max_treasury_spend_vote() -> Vote {
    Vote {
        id: VOTE_ID_MAX_TREASURY_SPEND,
        description: "Change maximum treasury expenditure policy as defined in DCP0013",
        mask: 0x0006,
        choices: choices(
            "abstain voting for change",
            "keep the existing consensus rules",
            0x0002,
            "change to the new consensus rules",
            0x0004,
        ),
    }
}
