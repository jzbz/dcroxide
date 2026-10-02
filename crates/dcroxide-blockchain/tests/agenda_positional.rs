// SPDX-License-Identifier: ISC
//! dcrd's positional agenda query, activation anchors and historical
//! activations (`internal/blockchain/agendas.go` and
//! `thresholdstate.go` at `6f6cf21b`).
//!
//! Ports `TestIsAgendaActivePositional` (`agendas_test.go:357-512`) over
//! the block index store, and pins the rest of the behaviour the series
//! introduced: the tally caching the first LockedIn to Active boundary
//! it computes as the agenda's anchor (on every path that computes it),
//! never for an agenda with a historical activation; the historical
//! activations deciding agenda queries on the main network without a
//! tally; and agendas never being active for the genesis block.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str::FromStr;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::agendas::{
    AgendaActiveInfo, ConsensusAgenda, HistoricalActivationState, VOTE_ID_BLAKE3_POW,
    VOTE_ID_LN_FEATURES, VOTE_ID_SDIFF_ALGORITHM, VOTE_ID_TREASURY,
    calc_next_required_stake_difficulty, find_deployment, is_agenda_active,
    is_agenda_active_positional, is_treasury_agenda_active,
};
use dcroxide_blockchain::blockindex::{BlockStatus, NodeId, NodeStore};
use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::difficulty::{ChainView, DiffNode};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::stakever::{VersionChainView, VersionNode};
use dcroxide_blockchain::thresholdstate::{
    ThresholdState, ThresholdStateTuple, VoteChainView, VoteNode, new_threshold_state,
    next_threshold_state,
};
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_wire::{BlockHeader, CurrencyNet};

const VALID: AgendaActiveInfo = AgendaActiveInfo {
    is_valid: true,
    is_active: true,
};
const INACTIVE: AgendaActiveInfo = AgendaActiveInfo {
    is_valid: true,
    is_active: false,
};
const UNKNOWN: AgendaActiveInfo = AgendaActiveInfo {
    is_valid: false,
    is_active: false,
};

/// Append `count` chained nodes after `parent`, each distinct by its
/// nonce tag, returning them in height order (dcrd
/// `chainedFakeNodes`).
fn chained_nodes(store: &mut NodeStore, parent: NodeId, count: u32, tag: u32) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let mut parent = parent;
    for _ in 0..count {
        let prev = store.node(parent);
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.prev_block = prev.hash;
        header.height = prev.height as u32 + 1;
        header.timestamp = header.height;
        header.nonce = tag;
        let id = store.new_node(&header, Some(parent));
        ids.push(id);
        parent = id;
    }
    ids
}

/// dcrd `TestIsAgendaActivePositional`: the genesis block, forced
/// states, and historical states before, exactly at, and after the
/// anchor, with side chains that do and do not descend from it.  The
/// cases run in order: the exact-anchor case caches the anchor the
/// later cases use.
///
/// ```text
/// genesis -> 1 -> 2 -> ... -> 9 -> 10  -> 11  -> 12  -> 13
///                              |      \-> 11a -> 12a
///                              \-> 10b -> 11b -> 12b
/// ```
#[test]
fn is_agenda_active_positional_cases() {
    let mut store = NodeStore::new();
    let genesis_header = regnet_params().genesis_block.header;
    let genesis = store.new_node(&genesis_header, None);
    let branch0 = chained_nodes(&mut store, genesis, 13, 0);
    let branch1 = chained_nodes(&mut store, branch0[9], 2, 1);
    let branch2 = chained_nodes(&mut store, branch0[8], 3, 2);

    // Anchors are kept per agenda ID, so each agenda value below gets
    // its own ID, as each of dcrd's agenda values carries its own
    // anchor.
    let historical_anchor = branch0[9];
    let with_historical_state = ConsensusAgenda {
        forced_state: None,
        historical_state: Some(HistoricalActivationState {
            anchor_height: store.node(historical_anchor).height,
            anchor_hash: store.node(historical_anchor).hash,
            choice_id: "yes",
        }),
        deployment: None,
    };
    let with_historical_state_wrong_hash = ConsensusAgenda {
        historical_state: Some(HistoricalActivationState {
            anchor_height: store.node(historical_anchor).height,
            anchor_hash: store.node(branch0[0]).hash,
            choice_id: "yes",
        }),
        ..with_historical_state
    };
    let empty = ConsensusAgenda {
        forced_state: None,
        historical_state: None,
        deployment: None,
    };
    let forced = |state, choice_id| ConsensusAgenda {
        forced_state: Some(new_threshold_state(state, choice_id)),
        ..empty
    };
    let with_forced_state_defined = forced(ThresholdState::Defined, "");
    let with_forced_state_active = forced(ThresholdState::Active, "yes");
    let with_forced_state_failed = forced(ThresholdState::Failed, "");

    // The cached anchor agenda's anchor is preset at the historical
    // anchor node.
    NodeBranchView {
        store: &store,
        tip: historical_anchor,
    }
    .cache_active_anchor("cached", 10, "yes");

    let tip0 = *branch0.last().expect("tip");
    let tip1 = *branch1.last().expect("tip");
    let tip2 = *branch2.last().expect("tip");
    let tests: [(
        &str,
        Option<NodeId>,
        &str,
        ConsensusAgenda<'_>,
        AgendaActiveInfo,
    ); 17] = [
        (
            "genesis block always inactive (with historical)",
            None,
            "historical",
            with_historical_state,
            INACTIVE,
        ),
        (
            "genesis block always inactive even when forced active",
            None,
            "forcedactive",
            with_forced_state_active,
            INACTIVE,
        ),
        (
            "forced defined",
            Some(branch0[0]),
            "forceddefined",
            with_forced_state_defined,
            INACTIVE,
        ),
        (
            "forced active",
            Some(branch0[0]),
            "forcedactive",
            with_forced_state_active,
            VALID,
        ),
        (
            "forced failed",
            Some(branch0[0]),
            "forcedfailed",
            with_forced_state_failed,
            INACTIVE,
        ),
        (
            "no historical state inconclusive (no anchor)",
            Some(tip0),
            "empty",
            empty,
            UNKNOWN,
        ),
        (
            "no historical state cached anchor main chain descendant",
            Some(tip0),
            "cached",
            empty,
            VALID,
        ),
        (
            "no historical state cached anchor inconclusive side chain",
            Some(tip2),
            "cached",
            empty,
            UNKNOWN,
        ),
        (
            "historical state with wrong hash inconclusive",
            Some(historical_anchor),
            "historicalwronghash",
            with_historical_state_wrong_hash,
            UNKNOWN,
        ),
        (
            "historical state inconclusive side chain",
            Some(tip2),
            "historical",
            with_historical_state,
            UNKNOWN,
        ),
        (
            "historical state before anchor height (no anchor)",
            Some(branch0[0]),
            "historical",
            with_historical_state,
            INACTIVE,
        ),
        (
            "historical state exact anchor height side chain (no anchor)",
            Some(branch2[0]),
            "historical",
            with_historical_state,
            UNKNOWN,
        ),
        (
            "historical state exact anchor conclusive",
            Some(historical_anchor),
            "historical",
            with_historical_state,
            VALID,
        ),
        (
            "historical state before anchor height (with anchor)",
            Some(branch0[0]),
            "historical",
            with_historical_state,
            INACTIVE,
        ),
        (
            "historical state exact anchor height side chain (with anchor)",
            Some(branch2[0]),
            "historical",
            with_historical_state,
            UNKNOWN,
        ),
        (
            "historical state main chain anchor descendant",
            Some(tip0),
            "historical",
            with_historical_state,
            VALID,
        ),
        (
            "historical state side chain anchor descendant",
            Some(tip1),
            "historical",
            with_historical_state,
            VALID,
        ),
    ];

    for (name, node, agenda_id, agenda, want) in tests {
        let tip = node.unwrap_or(genesis);
        let view = NodeBranchView { store: &store, tip };
        let prev_height = node.map(|n| store.node(n).height);
        let info = is_agenda_active_positional(&view, prev_height, agenda_id, &agenda);
        assert_eq!(info, want, "{name}");

        // Inconclusive side chains never set the anchor.
        if name == "historical state exact anchor height side chain (no anchor)" {
            assert!(!view.has_active_anchor("historical"), "{name}");
        }
    }

    // The exact anchor case cached the anchor at the historical node.
    let view = NodeBranchView {
        store: &store,
        tip: tip0,
    };
    assert_eq!(view.active_anchor_cached("historical", 10), Some("yes"));
    assert_eq!(view.active_anchor_cached("historical", 9), None);
    assert!(!view.has_active_anchor("historicalwronghash"));
}

/// The regnet header recipe dcrd's query vectors use: block version 6,
/// stake version 5, and five version 5 votes per block from stake
/// validation height on, which vote the DCP0001 agenda (version 5, mask
/// 0x6) yes from height 464 to 783 and abstain otherwise.  The agenda
/// starts at the 463 boundary, locks in at 783 and is active for every
/// block after 1103.
fn regnet_votes(height: u32) -> Vec<(u32, u16)> {
    match height {
        0..=143 => Vec::new(),
        464..=783 => vec![(5, 0x5); 5],
        _ => vec![(5, 0x1); 5],
    }
}

/// Append regnet nodes up to `to_height` after `parent`, tagged by the
/// nonce so branches differ, marking them validated with data.
fn extend_regnet(chain: &mut Chain, parent: NodeId, to_height: u32, tag: u32) -> Vec<NodeId> {
    let params = regnet_params();
    let mut ids = Vec::new();
    let mut parent = parent;
    let from = chain.store.node(parent).height as u32 + 1;
    for height in from..=to_height {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.version = 6;
        header.prev_block = chain.store.node(parent).hash;
        header.vote_bits = 0x01;
        header.bits = params.pow_limit_bits;
        header.sbits = 20000;
        header.height = height;
        header.fresh_stake = 20;
        header.timestamp = 1538524800 + height;
        header.nonce = height ^ tag;
        header.stake_version = 5;
        let id = chain.store.new_node(&header, Some(parent));
        {
            let node = chain.store.node_mut(id);
            node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
            node.is_fully_linked = true;
            node.votes = regnet_votes(height);
        }
        chain.index.add_node(&chain.store, id);
        ids.push(id);
        parent = id;
    }
    ids
}

/// A regnet chain whose main branch runs from genesis to `to_height`;
/// index `h` of the returned nodes is the node at height `h`.
fn regnet_chain(to_height: u32) -> (Chain, Vec<NodeId>) {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let genesis = chain.best_chain.tip().expect("genesis");
    let mut nodes = vec![genesis];
    nodes.extend(extend_regnet(&mut chain, genesis, to_height, 0));
    chain
        .best_chain
        .set_tip(&chain.store, nodes.last().copied());
    (chain, nodes)
}

/// The positional answer for DCP0001 after the given node.
fn sdiff_positional(chain: &Chain, node: NodeId) -> AgendaActiveInfo {
    chain
        .is_agenda_active_positional_by_id(Some(node), VOTE_ID_SDIFF_ALGORITHM, &regnet_params())
        .expect("known agenda")
}

/// A full-context tally that computes the LockedIn to Active boundary
/// caches that interval-final node as the agenda's anchor, which makes
/// the positional query definite for its descendants only.
#[test]
fn next_threshold_state_discovers_the_anchor() {
    let params = regnet_params();
    let (mut chain, main) = regnet_chain(1200);
    let side = extend_regnet(&mut chain, main[1000], 1110, 0x8000_0000);

    // Nothing is known positionally before a tally.
    assert_eq!(sdiff_positional(&chain, main[1200]), UNKNOWN);

    let tip_hash = chain.store.node(main[1200]).hash;
    assert_eq!(
        chain.next_threshold_state(&tip_hash, VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(new_threshold_state(ThresholdState::Active, "yes"))
    );

    // The anchor is the parent of the first active block.
    assert_eq!(sdiff_positional(&chain, main[1200]), VALID);
    assert_eq!(sdiff_positional(&chain, main[1103]), VALID);
    assert_eq!(sdiff_positional(&chain, main[1102]), UNKNOWN);
    assert_eq!(
        sdiff_positional(&chain, *side.last().expect("tip")),
        UNKNOWN
    );

    // The full-context query agrees, through the anchor.
    let view = NodeBranchView {
        store: &chain.store,
        tip: main[1200],
    };
    assert_eq!(
        view.active_anchor_cached(VOTE_ID_SDIFF_ALGORITHM, 1103),
        Some("yes")
    );
    assert_eq!(
        is_agenda_active(&view, Some(1200), VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(true)
    );
}

/// The state change height query (the walk behind getblockchaininfo)
/// computes the same boundary and caches the anchor too.
#[test]
fn state_last_changed_height_discovers_the_anchor() {
    let params = regnet_params();
    let (chain, main) = regnet_chain(1200);
    let tip_hash = chain.store.node(main[1200]).hash;
    assert_eq!(sdiff_positional(&chain, main[1200]), UNKNOWN);
    assert_eq!(
        chain.state_last_changed_height(&tip_hash, VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(1104)
    );
    assert_eq!(sdiff_positional(&chain, main[1200]), VALID);
}

/// Only the first anchor discovered is kept: a competing branch that
/// activates the agenda at its own boundary node later does not
/// replace it, and its descendants fall back to the tally.
#[test]
fn first_discovered_anchor_wins() {
    let params = regnet_params();
    let (mut chain, main) = regnet_chain(1200);
    let fork = extend_regnet(&mut chain, main[1102], 1110, 0x4000_0000);
    let fork_tip = *fork.last().expect("tip");

    for tip in [fork_tip, main[1200]] {
        let hash = chain.store.node(tip).hash;
        assert_eq!(
            chain.next_threshold_state(&hash, VOTE_ID_SDIFF_ALGORITHM, &params),
            Ok(new_threshold_state(ThresholdState::Active, "yes"))
        );
    }
    assert_eq!(sdiff_positional(&chain, fork_tip), VALID);
    assert_eq!(sdiff_positional(&chain, main[1200]), UNKNOWN);
}

/// The genesis block's missing parent: agendas are never active for it,
/// even when forced, but the agenda is still looked up first.
#[test]
fn agendas_are_never_active_for_the_genesis_block() {
    let simnet = simnet_params();
    let view = VecView::new(&simnet, 0, |_| Vec::new());
    for id in [
        VOTE_ID_TREASURY,
        VOTE_ID_LN_FEATURES,
        VOTE_ID_BLAKE3_POW,
        VOTE_ID_SDIFF_ALGORITHM,
    ] {
        assert_eq!(
            is_agenda_active(&view, None, id, &simnet),
            Ok(false),
            "{id}"
        );
    }
    // The genesis node itself is a parent like any other.
    assert_eq!(
        is_agenda_active(&view, Some(0), VOTE_ID_LN_FEATURES, &simnet),
        Ok(true)
    );
    assert_eq!(is_treasury_agenda_active(&view, None, &simnet), Ok(false));
    let err = is_agenda_active(&view, None, "bogusagenda", &simnet).expect_err("unknown");
    assert_eq!(err.kind, RuleErrorKind::UnknownAgendaID);
    assert_eq!(err.description, "agenda ID bogusagenda does not exist");

    // With no parent, either stake difficulty algorithm gives the
    // network minimum.
    assert_eq!(
        calc_next_required_stake_difficulty(&view, None, &simnet),
        Ok(simnet.minimum_stake_diff)
    );

    let (chain, _) = regnet_chain(2);
    let regnet = regnet_params();
    assert_eq!(
        chain.is_agenda_active_positional_by_id(None, VOTE_ID_SDIFF_ALGORITHM, &regnet),
        Ok(INACTIVE)
    );
    let err = chain
        .is_agenda_active_positional_by_id(None, "bogusagenda", &regnet)
        .expect_err("unknown");
    assert_eq!(err.kind, RuleErrorKind::UnknownAgendaID);
}

/// A height-indexed vote view with recorded anchor hooks, a replaceable
/// historical table, and optionally a fixed tally state and a known
/// ancestor hash.
struct VecView {
    tip: i64,
    votes: fn(u32) -> Vec<(u32, u16)>,
    block_version: i32,
    stake_version: u32,
    ts_base: i64,
    historical: Vec<(&'static str, HistoricalActivationState)>,
    tally: Option<ThresholdState>,
    known_hash: Option<(i64, [u8; 32])>,
    anchors: RefCell<BTreeMap<String, (i64, &'static str)>>,
}

impl VecView {
    fn new(params: &Params, tip: i64, votes: fn(u32) -> Vec<(u32, u16)>) -> VecView {
        VecView {
            tip,
            votes,
            block_version: 6,
            stake_version: 5,
            ts_base: 1538524800,
            historical: dcroxide_blockchain::agendas::historical_agendas(params.net).to_vec(),
            tally: None,
            known_hash: None,
            anchors: RefCell::new(BTreeMap::new()),
        }
    }

    fn version_node(&self, height: i64) -> Option<VersionNode> {
        (0..=self.tip).contains(&height).then(|| VersionNode {
            height,
            timestamp: self.ts_base + height,
            block_version: self.block_version,
            stake_version: self.stake_version,
            vote_versions: (self.votes)(height as u32).iter().map(|v| v.0).collect(),
        })
    }

    fn anchor(&self, agenda_id: &str) -> Option<(i64, &'static str)> {
        self.anchors.borrow().get(agenda_id).copied()
    }
}

impl ChainView for VecView {
    fn node(&self, height: i64) -> Option<DiffNode> {
        (0..=self.tip).contains(&height).then(|| DiffNode {
            height,
            timestamp: self.ts_base + height,
            bits: 0,
            sbits: 0,
            pool_size: 0,
            fresh_stake: 0,
        })
    }
}

impl VersionChainView for VecView {
    fn node(&self, height: i64) -> Option<VersionNode> {
        self.version_node(height)
    }

    fn cache_hash(&self, height: i64) -> Option<[u8; 32]> {
        // Keys only matter when a fixed tally state answers.
        self.tally?;
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Some(hash)
    }
}

impl VoteChainView for VecView {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        self.version_node(height).map(|node| VoteNode {
            votes: (self.votes)(height as u32),
            node,
        })
    }

    fn threshold_state_cached(
        &self,
        _deployment_version: u32,
        vote_id: &str,
        _hash: [u8; 32],
    ) -> Option<ThresholdStateTuple> {
        let state = self.tally?;
        (vote_id == VOTE_ID_SDIFF_ALGORITHM).then_some(new_threshold_state(
            state,
            if state == ThresholdState::Active {
                "yes"
            } else {
                ""
            },
        ))
    }

    fn historical_agendas(
        &self,
        _net: CurrencyNet,
    ) -> &[(&'static str, HistoricalActivationState)] {
        &self.historical
    }

    fn ancestor_hash(&self, height: i64) -> Option<[u8; 32]> {
        self.known_hash
            .filter(|(h, _)| *h == height && height <= self.tip)
            .map(|(_, hash)| hash)
    }

    fn active_anchor_cached(&self, agenda_id: &str, prev_height: i64) -> Option<&'static str> {
        let (height, choice_id) = self.anchor(agenda_id)?;
        (height <= prev_height && prev_height <= self.tip).then_some(choice_id)
    }

    fn has_active_anchor(&self, agenda_id: &str) -> bool {
        self.anchor(agenda_id).is_some()
    }

    fn cache_active_anchor(&self, agenda_id: &str, height: i64, choice_id: &'static str) {
        self.anchors
            .borrow_mut()
            .insert(agenda_id.to_string(), (height, choice_id));
    }
}

/// The tally itself caches the anchor at the boundary where LockedIn
/// becomes Active, with the winning choice; never for an agenda the
/// network has a historical activation for; and never over an anchor
/// already cached.
#[test]
fn tally_caches_the_anchor_once_without_history() {
    let params = regnet_params();
    let (version, deployment) =
        find_deployment(&params, VOTE_ID_SDIFF_ALGORITHM).expect("deployment");

    let view = VecView::new(&params, 1200, regnet_votes);
    assert_eq!(
        next_threshold_state(&view, Some(1102), version, deployment, &params),
        new_threshold_state(ThresholdState::LockedIn, "yes")
    );
    assert_eq!(view.anchor(VOTE_ID_SDIFF_ALGORITHM), None);
    assert_eq!(
        next_threshold_state(&view, Some(1200), version, deployment, &params),
        new_threshold_state(ThresholdState::Active, "yes")
    );
    assert_eq!(view.anchor(VOTE_ID_SDIFF_ALGORITHM), Some((1103, "yes")));

    // An agenda with a historical activation on the view's network.
    let mut historical = VecView::new(&params, 1200, regnet_votes);
    historical.historical = vec![(
        VOTE_ID_SDIFF_ALGORITHM,
        HistoricalActivationState {
            anchor_height: 1103,
            anchor_hash: Hash([9u8; 32]),
            choice_id: "yes",
        },
    )];
    assert_eq!(
        next_threshold_state(&historical, Some(1200), version, deployment, &params),
        new_threshold_state(ThresholdState::Active, "yes")
    );
    assert_eq!(historical.anchor(VOTE_ID_SDIFF_ALGORITHM), None);

    // An anchor already cached stays.
    let preset = VecView::new(&params, 1200, regnet_votes);
    preset.cache_active_anchor(VOTE_ID_SDIFF_ALGORITHM, 500, "yes");
    assert_eq!(
        next_threshold_state(&preset, Some(1200), version, deployment, &params),
        new_threshold_state(ThresholdState::Active, "yes")
    );
    assert_eq!(preset.anchor(VOTE_ID_SDIFF_ALGORITHM), Some((500, "yes")));
}

/// On the main network, an agenda query for a parent below the agenda's
/// historical anchor is definitively inactive whatever the votes say,
/// and a parent descending from the real anchor is active without a
/// tally.  Without the historical activation the tally decides.
#[test]
fn historical_activations_decide_mainnet_queries() {
    let params = mainnet_params();
    let anchor_hash =
        Hash::from_str("0000000000000139582d056bc20bb352f4e9b248acbb202724f46000e59c9f75")
            .expect("anchor hash");

    // Below the anchor, with a tally that says active.
    let mut below = VecView::new(&params, 20000, |_| Vec::new());
    below.tally = Some(ThresholdState::Active);
    assert_eq!(
        is_agenda_active(&below, Some(20000), VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(false)
    );
    below
        .historical
        .retain(|(id, _)| *id != VOTE_ID_SDIFF_ALGORITHM);
    assert_eq!(
        is_agenda_active(&below, Some(20000), VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(true)
    );

    // Above the anchor on its branch, with a tally that says defined.
    let mut above = VecView::new(&params, 150000, |_| Vec::new());
    above.tally = Some(ThresholdState::Defined);
    above.known_hash = Some((149247, anchor_hash.0));
    assert_eq!(
        is_agenda_active(&above, Some(150000), VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(true)
    );
    assert_eq!(above.anchor(VOTE_ID_SDIFF_ALGORITHM), Some((149247, "yes")));

    // Above the anchor height on a branch without the anchor block.
    let mut other = VecView::new(&params, 150000, |_| Vec::new());
    other.tally = Some(ThresholdState::Defined);
    other.known_hash = Some((149247, [1u8; 32]));
    assert_eq!(
        is_agenda_active(&other, Some(150000), VOTE_ID_SDIFF_ALGORITHM, &params),
        Ok(false)
    );
    assert_eq!(other.anchor(VOTE_ID_SDIFF_ALGORITHM), None);
}
