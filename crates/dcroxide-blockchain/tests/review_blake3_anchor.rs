// SPDX-License-Identifier: ISC
//! dcrd's two cached DCP0011 anchors (chain.go
//! `cachedBlake3WorkDiffAnchor` and
//! `cachedBlake3WorkDiffCandidateAnchor`).
//!
//! The confirmed anchor is set whenever the contextual difficulty
//! calculation resolves it (difficulty.go:314-316) and from then on
//! `checkDifficultyPositional` holds every descendant header to the
//! ASERT difficulty from it (validate.go:1115-1126), with no EMA
//! fallback.  A synced dcrd is therefore stricter at the header stage
//! than a cold one, and the vectors generated from fresh dcrd
//! processes only ever replay the cold path.  The candidate anchor is
//! tried before the candidate walk (validate.go:1188-1194).

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use core::cell::Cell;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::agendas::calc_next_required_difficulty;
use dcroxide_blockchain::blockindex::{NodeId, NodeStore};
use dcroxide_blockchain::chainview_nodes::NodeBranchView;
use dcroxide_blockchain::difficulty::{
    ChainView, DiffNode, calc_next_blake3_diff_from_anchor, calc_next_blake256_diff,
};
use dcroxide_blockchain::stakever::{VersionChainView, VersionNode};
use dcroxide_blockchain::thresholdstate::{
    ThresholdState, ThresholdStateTuple, VoteChainView, VoteNode,
};
use dcroxide_blockchain::validate::check_difficulty_positional;
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params};
use dcroxide_wire::BlockHeader;

const T0: i64 = 1_600_000_000;

/// A synthetic single branch whose BLAKE3 agenda state comes from the
/// threshold state cache hook: active for every block after
/// `active_after`, which makes that block the anchor.
struct Synth {
    tip: i64,
    spacing: i64,
    bits: u32,
    block_version: i32,
    active_after: i64,
    anchor: Cell<Option<i64>>,
    candidate: Cell<Option<i64>>,
    agenda_lookups: Cell<usize>,
    version_lookups: Cell<usize>,
}

impl Synth {
    fn new(tip: i64, spacing: i64, bits: u32, block_version: i32, active_after: i64) -> Synth {
        Synth {
            tip,
            spacing,
            bits,
            block_version,
            active_after,
            anchor: Cell::new(None),
            candidate: Cell::new(None),
            agenda_lookups: Cell::new(0),
            version_lookups: Cell::new(0),
        }
    }

    fn version_node(&self, height: i64) -> Option<VersionNode> {
        (0..=self.tip).contains(&height).then(|| VersionNode {
            height,
            timestamp: T0 + self.spacing * height,
            block_version: self.block_version,
            stake_version: 0,
            vote_versions: Vec::new(),
        })
    }

    fn header(&self, bits: u32, nonce: u32) -> BlockHeader {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.version = self.block_version;
        header.height = (self.tip + 1) as u32;
        header.timestamp = (T0 + self.spacing * (self.tip + 1)) as u32;
        header.bits = bits;
        header.nonce = nonce;
        header
    }
}

impl ChainView for Synth {
    fn node(&self, height: i64) -> Option<DiffNode> {
        (0..=self.tip).contains(&height).then(|| DiffNode {
            height,
            timestamp: T0 + self.spacing * height,
            bits: self.bits,
            sbits: 0,
            pool_size: 0,
            fresh_stake: 0,
        })
    }

    fn blake3_anchor_cached(&self, height: i64) -> Option<i64> {
        self.anchor
            .get()
            .filter(|&a| a <= height && height <= self.tip)
    }

    fn cache_blake3_anchor(&self, height: i64) {
        self.anchor.set(Some(height));
    }

    fn blake3_candidate_anchor_cached(&self, height: i64) -> Option<i64> {
        self.candidate
            .get()
            .filter(|&c| c <= height && height <= self.tip)
    }

    fn cache_blake3_candidate_anchor(&self, height: i64) {
        self.candidate.set(Some(height));
    }
}

impl VersionChainView for Synth {
    fn node(&self, height: i64) -> Option<VersionNode> {
        self.version_lookups.set(self.version_lookups.get() + 1);
        self.version_node(height)
    }

    fn cache_hash(&self, height: i64) -> Option<[u8; 32]> {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Some(hash)
    }
}

impl VoteChainView for Synth {
    fn vote_node(&self, height: i64) -> Option<VoteNode> {
        self.version_node(height).map(|node| VoteNode {
            node,
            votes: Vec::new(),
        })
    }

    fn threshold_state_cached(
        &self,
        _deployment_version: u32,
        vote_id: &str,
        hash: [u8; 32],
    ) -> Option<ThresholdStateTuple> {
        if vote_id != "blake3pow" {
            return None;
        }
        self.agenda_lookups.set(self.agenda_lookups.get() + 1);
        let height = i64::from_le_bytes(hash[..8].try_into().expect("8 bytes"));
        let state = if height >= self.active_after {
            ThresholdState::Active
        } else {
            ThresholdState::Defined
        };
        Some(ThresholdStateTuple {
            state,
            choice: None,
        })
    }
}

fn kind_and_text(
    view: &Synth,
    header: &BlockHeader,
    prev: &DiffNode,
    params: &Params,
) -> Option<(RuleErrorKind, String)> {
    check_difficulty_positional(view, header, prev, params)
        .err()
        .map(|e| (e.kind, e.description))
}

/// The two verdicts that change once the confirmed anchor is cached,
/// on mainnet after a voted activation: EMA bits are rejected, and ASERT
/// bits no longer need a BLAKE3 solution.
#[test]
fn confirmed_anchor_holds_headers_to_asert() {
    let params = mainnet_params();
    // Interval-final heights are 4095 + k*8064; the agenda became
    // active with the block after 28287, and the tip is four intervals
    // later so the anchor walk visits several candidates.
    let anchor_height = 28287;
    let view = Synth::new(60000, 300, 0x1b01ffff, 11, anchor_height);
    let prev = ChainView::node(&view, view.tip).expect("tip");
    let anchor = ChainView::node(&view, anchor_height).expect("anchor");
    let ts = i64::from(view.header(0, 0).timestamp);
    let ema = calc_next_blake256_diff(&view, &prev, ts, &params);
    let asert = calc_next_blake3_diff_from_anchor(&prev, &anchor, &params);
    assert_eq!(ema, view.bits, "EMA keeps the parent's bits off a retarget");
    assert_ne!(ema, asert);

    // Cold, like a freshly started dcrd: EMA bits pass, and ASERT bits
    // on a header not solved for BLAKE3 fall to the EMA check.
    let ema_header = view.header(ema, 0);
    let asert_header = view.header(asert, 0);
    assert_eq!(kind_and_text(&view, &ema_header, &prev, &params), None);
    assert_eq!(
        kind_and_text(&view, &asert_header, &prev, &params),
        Some((
            RuleErrorKind::UnexpectedDifficulty,
            format!(
                "block difficulty of {asert} is not the expected value of {ema} (difficulty \
                 algorithm: EMA)"
            )
        ))
    );

    // A contextual difficulty calculation resolves the anchor through
    // the agenda states and caches it.
    assert_eq!(
        calc_next_required_difficulty(&view, &prev, ts, &params),
        Ok(asert)
    );
    assert_eq!(view.anchor.get(), Some(anchor_height));
    let walked = view.agenda_lookups.get();

    // The next calculation uses the cached anchor instead of walking
    // the intervals again: only the agenda state itself is looked up.
    view.agenda_lookups.set(0);
    assert_eq!(
        calc_next_required_difficulty(&view, &prev, ts, &params),
        Ok(asert)
    );
    assert_eq!(view.agenda_lookups.get(), 1);
    assert!(walked > 1, "the cold calculation walked {walked} intervals");

    // Warm: the header must carry exactly the ASERT difficulty.
    assert_eq!(
        kind_and_text(&view, &ema_header, &prev, &params),
        Some((
            RuleErrorKind::UnexpectedDifficulty,
            format!(
                "block difficulty of {ema} is not the expected value of {asert} (difficulty \
                 algorithm: ASERT)"
            )
        ))
    );
    assert_eq!(kind_and_text(&view, &asert_header, &prev, &params), None);
}

/// A candidate anchor that matched is cached and tried first, so later
/// descendant headers skip the candidate walk.
#[test]
fn matched_candidate_anchor_is_tried_first() {
    let params = regnet_params();
    // Blocks arrive slower than the one-second target, so ASERT from
    // any candidate saturates at the regnet proof of work limit, which
    // nearly every header hash meets.
    let view = Synth::new(1500, 2, 0x1e0fffff, 11, i64::MAX);
    let prev = ChainView::node(&view, view.tip).expect("tip");
    let limit = params.pow_limit_bits;
    let solved = |nonce_start: u32| {
        (nonce_start..)
            .map(|nonce| view.header(limit, nonce))
            .find(|h| {
                dcroxide_standalone::check_proof_of_work_hash(&h.pow_hash_v2(), h.bits).is_ok()
            })
            .expect("a solved nonce")
    };

    let first = solved(0);
    assert_eq!(
        check_difficulty_positional(&view, &first, &prev, &params),
        Ok(())
    );
    // The walk starts at the final block of the previous interval
    // (143 + k*320 on regnet) and matches at once.
    assert_eq!(view.candidate.get(), Some(1423));
    assert!(view.version_lookups.get() > 0);

    view.version_lookups.set(0);
    let second = solved(first.nonce + 1);
    assert_eq!(
        check_difficulty_positional(&view, &second, &prev, &params),
        Ok(())
    );
    assert_eq!(
        view.version_lookups.get(),
        0,
        "the cached candidate matched first"
    );

    // A header that matches no candidate still falls through the walk
    // to the EMA check.
    let unmatched = view.header(0x1d00ffff, 0);
    assert_eq!(
        check_difficulty_positional(&view, &unmatched, &prev, &params).map_err(|e| e.kind),
        Err(RuleErrorKind::UnexpectedDifficulty)
    );
}

fn build_chain(store: &mut NodeStore, parent: Option<NodeId>, from: u32, to: u32) -> Vec<NodeId> {
    let mut ids = Vec::new();
    let mut parent = parent;
    for height in from..=to {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.height = height;
        header.timestamp = height;
        header.nonce = from;
        let id = store.new_node(&header, parent);
        ids.push(id);
        parent = Some(id);
    }
    ids
}

/// The block index store answers the hooks as dcrd's `IsAncestorOf`
/// checks do: the cached node counts only on the branch being asked
/// about, at or below the asked height.
#[test]
fn node_branch_view_anchor_hooks_follow_ancestry() {
    let mut store = NodeStore::new();
    let main = build_chain(&mut store, None, 0, 20);
    let fork = build_chain(&mut store, Some(main[10]), 11, 15);
    let main_view = NodeBranchView {
        store: &store,
        tip: main[20],
    };
    let fork_view = NodeBranchView {
        store: &store,
        tip: fork[4],
    };

    // Nothing is cached yet.
    assert_eq!(main_view.blake3_anchor_cached(20), None);
    assert_eq!(main_view.blake3_candidate_anchor_cached(20), None);

    // An anchor below the fork point is shared by both branches.
    main_view.cache_blake3_anchor(8);
    assert_eq!(main_view.blake3_anchor_cached(20), Some(8));
    assert_eq!(main_view.blake3_anchor_cached(8), Some(8));
    assert_eq!(main_view.blake3_anchor_cached(7), None);
    assert_eq!(main_view.blake3_anchor_cached(21), None);
    assert_eq!(fork_view.blake3_anchor_cached(15), Some(8));
    assert_eq!(main_view.blake3_candidate_anchor_cached(20), None);

    // An anchor on the main branch above the fork is not an ancestor
    // of the side branch.
    main_view.cache_blake3_anchor(12);
    assert_eq!(main_view.blake3_anchor_cached(20), Some(12));
    assert_eq!(fork_view.blake3_anchor_cached(15), None);

    // The candidate slot is separate.
    fork_view.cache_blake3_candidate_anchor(13);
    assert_eq!(fork_view.blake3_candidate_anchor_cached(15), Some(13));
    assert_eq!(main_view.blake3_candidate_anchor_cached(20), None);
    assert_eq!(main_view.blake3_anchor_cached(20), Some(12));
}
