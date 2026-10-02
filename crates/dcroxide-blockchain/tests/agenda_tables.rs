// SPDX-License-Identifier: ISC
//! dcrd's agenda construction (`internal/blockchain/agendas.go` at
//! `6f6cf21b`): the hard-coded historical activation tables, the
//! deployment validation `makeAgendas` runs when a chain is built, the
//! default required agendas, and the agenda-driven max block size
//! choice.  Ports `TestDeploymentParamsValidation`,
//! `TestHistoricalAgendaInvariants`,
//! `TestMakeAgendasDefaultRequiredAgendas` and `TestMaxBlockSizeChoice`
//! (`agendas_test.go:24-350`, `:517-603`), plus checks of the port's
//! per-query agenda lookup against `makeAgendas`.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::str::FromStr;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::agendas::{
    HistoricalActivationState, REQUIRED_AGENDA_IDS, VOTE_ID_AUTO_REVOCATIONS, VOTE_ID_BLAKE3_POW,
    VOTE_ID_CHANGE_SUBSIDY_SPLIT, VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
    VOTE_ID_EXPLICIT_VERSION_UPGRADES, VOTE_ID_FIX_LN_SEQ_LOCKS, VOTE_ID_HEADER_COMMITMENTS,
    VOTE_ID_LN_FEATURES, VOTE_ID_LN_SUPPORT, VOTE_ID_MAX_BLOCK_SIZE, VOTE_ID_MAX_TREASURY_SPEND,
    VOTE_ID_REVERT_TREASURY_POLICY, VOTE_ID_SDIFF_ALGORITHM, VOTE_ID_TREASURY, historical_agendas,
    is_blake3_pow_agenda_forced_active, lookup_agenda, make_agendas,
};
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::ChainDbError;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::thresholdstate::{ThresholdState, new_threshold_state};
use dcroxide_chaincfg::{
    Choice, ConsensusDeployment, Params, Vote, mainnet_params, regnet_params, simnet_params,
    testnet3_params,
};
use dcroxide_chainhash::Hash;
use dcroxide_wire::{BlockHeader, CurrencyNet};

/// dcrd's main network historical activations, in its source order,
/// with the hashes as the display-order literals it parses
/// (`agendas.go:68-134`).
const MAINNET_HISTORY: [(&str, i64, &str, &str); 13] = [
    (
        VOTE_ID_SDIFF_ALGORITHM,
        149247,
        "0000000000000139582d056bc20bb352f4e9b248acbb202724f46000e59c9f75",
        "yes",
    ),
    (
        VOTE_ID_LN_SUPPORT,
        149247,
        "0000000000000139582d056bc20bb352f4e9b248acbb202724f46000e59c9f75",
        "yes",
    ),
    (
        VOTE_ID_LN_FEATURES,
        189567,
        "000000000000005ca2ebe4ef0649128e1cd16d063f80c884cbd865d3af2300ae",
        "yes",
    ),
    (
        VOTE_ID_FIX_LN_SEQ_LOCKS,
        342783,
        "000000000000000017c053b63c7ae9bb8e73ee1c13ef3da493042a7a05d7401c",
        "yes",
    ),
    (
        VOTE_ID_HEADER_COMMITMENTS,
        431487,
        "0000000000000000225b8f795704d4ebc484fad4ab09eec615fb44b4a95c3c26",
        "yes",
    ),
    (
        VOTE_ID_TREASURY,
        552447,
        "000000000000000012d3e57c450f632a9877a28534dbffbf85d41a78aadb9acb",
        "yes",
    ),
    (
        VOTE_ID_REVERT_TREASURY_POLICY,
        657279,
        "00000000000000000669da8bbb90dad39a2fd889cbdda00bf259776af822fcaa",
        "yes",
    ),
    (
        VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        657279,
        "00000000000000000669da8bbb90dad39a2fd889cbdda00bf259776af822fcaa",
        "yes",
    ),
    (
        VOTE_ID_AUTO_REVOCATIONS,
        657279,
        "00000000000000000669da8bbb90dad39a2fd889cbdda00bf259776af822fcaa",
        "yes",
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        657279,
        "00000000000000000669da8bbb90dad39a2fd889cbdda00bf259776af822fcaa",
        "yes",
    ),
    (
        VOTE_ID_BLAKE3_POW,
        794367,
        "0000000000000000c293d8c67409d05e960447ea25cdaf770e864d995c764ef0",
        "yes",
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        794367,
        "0000000000000000c293d8c67409d05e960447ea25cdaf770e864d995c764ef0",
        "yes",
    ),
    (
        VOTE_ID_MAX_TREASURY_SPEND,
        1052415,
        "bc1b84dcfd532a01fbd42470d0668fcdbc7e6e4e9108218f55025d9e565dfaea",
        "yes",
    ),
];

/// dcrd's version 3 test network historical activations
/// (`agendas.go:135-186`).
const TESTNET3_HISTORY: [(&str, i64, &str, &str); 10] = [
    (
        VOTE_ID_FIX_LN_SEQ_LOCKS,
        136847,
        "0000000004232de037b11ee39641910ae0fd0becb968f76f20a40cb7fa64f475",
        "yes",
    ),
    (
        VOTE_ID_HEADER_COMMITMENTS,
        323327,
        "0000002438f7146f7dbfea248b4c94c4c35a8c714442a589110f4c7513a6b26a",
        "yes",
    ),
    (
        VOTE_ID_TREASURY,
        560207,
        "0000004f5b6cefb4b5c0ae9dd7a92a431c2de697d22aed9215fe595ac8c1ec23",
        "yes",
    ),
    (
        VOTE_ID_REVERT_TREASURY_POLICY,
        867647,
        "0000000036af134886ea61aecea318c1f18f349d3acbf2a8c40ced62854b057b",
        "yes",
    ),
    (
        VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        867647,
        "0000000036af134886ea61aecea318c1f18f349d3acbf2a8c40ced62854b057b",
        "yes",
    ),
    (
        VOTE_ID_AUTO_REVOCATIONS,
        867647,
        "0000000036af134886ea61aecea318c1f18f349d3acbf2a8c40ced62854b057b",
        "yes",
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        877727,
        "000000000000e9528cd8a67898b2c02c854c825a3d09c0d83296f051d8c2adac",
        "yes",
    ),
    (
        VOTE_ID_BLAKE3_POW,
        1170047,
        "000000b396bfeaa6ae6fa9e3cee441d7215191630bdaa9b979a872985caed727",
        "yes",
    ),
    (
        VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        1170047,
        "000000b396bfeaa6ae6fa9e3cee441d7215191630bdaa9b979a872985caed727",
        "yes",
    ),
    (
        VOTE_ID_MAX_TREASURY_SPEND,
        1805087,
        "f3e25c6c40baaed62b27ad4f8c0ed6be89bc6890b415089e33acf7783ded248d",
        "yes",
    ),
];

/// The four built-in networks.
fn all_params() -> [Params; 4] {
    [
        mainnet_params(),
        testnet3_params(),
        simnet_params(),
        regnet_params(),
    ]
}

/// The tables hold exactly dcrd's entries, in its order, with each
/// hash's internal byte order the reverse of the display literal dcrd
/// parses with `mustParseHash`.  A transposed hash would never match
/// the real chain's anchor, which on the real chain gives the same
/// answers through the vote tally, so nothing else would notice it.
#[test]
fn historical_agenda_tables_match_dcrd() {
    for (net, want) in [
        (CurrencyNet::MAIN_NET, &MAINNET_HISTORY[..]),
        (CurrencyNet::TEST_NET3, &TESTNET3_HISTORY[..]),
    ] {
        let table = historical_agendas(net);
        assert_eq!(table.len(), want.len(), "{net:?}");
        for ((id, state), (want_id, height, hash, choice)) in table.iter().zip(want) {
            assert_eq!(id, want_id, "{net:?}");
            assert_eq!(
                *state,
                HistoricalActivationState {
                    anchor_height: *height,
                    anchor_hash: Hash::from_str(hash).expect("hash literal"),
                    choice_id: choice,
                },
                "{net:?} {id}"
            );
        }
    }
    assert!(historical_agendas(simnet_params().net).is_empty());
    assert!(historical_agendas(regnet_params().net).is_empty());
}

/// Every anchor is exactly one block before a rule change activation
/// interval (dcrd `TestHistoricalAgendaInvariants`,
/// `agendas_test.go:256-280`), and each names an agenda the network
/// decides by vote rather than by a forced choice.
#[test]
fn historical_agenda_invariants() {
    for params in [mainnet_params(), testnet3_params()] {
        let rcai = i64::from(params.rule_change_activation_interval);
        let svh = params.stake_validation_height;
        for (id, agenda) in historical_agendas(params.net) {
            assert_eq!(
                (agenda.anchor_height + 1 - svh) % rcai,
                0,
                "agenda id {id} height {} is not one before a rule change activation interval",
                agenda.anchor_height
            );
            let deployment = params
                .deployments
                .iter()
                .flat_map(|(_, ds)| ds)
                .find(|d| d.vote.id == *id)
                .unwrap_or_else(|| panic!("{} has no deployment for {id}", params.name));
            assert!(deployment.forced_choice_id.is_empty(), "{id} is forced");
        }
    }
}

/// Every built-in network's parameters make agendas with its real
/// historical table: 13 required agendas everywhere plus lnsupport on
/// the main network, where every table entry attaches.
#[test]
fn built_in_networks_make_agendas() {
    for (params, want_agendas, want_historical) in [
        (mainnet_params(), 14, 13),
        (testnet3_params(), 13, 10),
        (simnet_params(), 13, 0),
        (regnet_params(), 13, 0),
    ] {
        let agendas = make_agendas(&params, historical_agendas(params.net))
            .unwrap_or_else(|e| panic!("{}: {e}", params.name));
        assert_eq!(agendas.len(), want_agendas, "{}", params.name);
        let historical = agendas
            .values()
            .filter(|a| a.historical_state.is_some())
            .count();
        assert_eq!(historical, want_historical, "{}", params.name);
        for id in REQUIRED_AGENDA_IDS {
            assert!(agendas.contains_key(id), "{}: {id}", params.name);
        }
    }

    // Only maxblocksize lacks a deployment, on the main network (where
    // the default is inactive) and the version 3 test network (where it
    // is active).
    let main = mainnet_params();
    let agendas = make_agendas(&main, historical_agendas(main.net)).expect("mainnet");
    let max_size = agendas[VOTE_ID_MAX_BLOCK_SIZE];
    assert_eq!(
        max_size.forced_state,
        Some(new_threshold_state(ThresholdState::Defined, ""))
    );
    assert!(max_size.deployment.is_none());
    let test = testnet3_params();
    let agendas = make_agendas(&test, historical_agendas(test.net)).expect("testnet3");
    let max_size = agendas[VOTE_ID_MAX_BLOCK_SIZE];
    assert_eq!(
        max_size.forced_state,
        Some(new_threshold_state(ThresholdState::Active, ""))
    );
    assert!(max_size.deployment.is_none());
}

/// The per-query lookup builds exactly the entry `makeAgendas` builds,
/// for every agenda of every network, and refuses an unknown ID with
/// dcrd's `ErrUnknownAgendaID`.
#[test]
fn lookup_agrees_with_make_agendas() {
    for params in all_params() {
        let table = historical_agendas(params.net);
        let agendas = make_agendas(&params, table).expect("valid params");
        for (id, agenda) in &agendas {
            assert_eq!(
                lookup_agenda(&params, table, id),
                Ok(*agenda),
                "{} {id}",
                params.name
            );
        }
        let err = lookup_agenda(&params, table, "bogusagenda").expect_err("unknown");
        assert_eq!(err.kind, RuleErrorKind::UnknownAgendaID);
        assert_eq!(err.description, "agenda ID bogusagenda does not exist");
    }
}

/// With no deployments and no historical data, every required agenda is
/// a default: defined on the main network and active elsewhere, both
/// with an empty choice and no deployment (dcrd
/// `TestMakeAgendasDefaultRequiredAgendas`, `agendas_test.go:283-350`).
#[test]
fn make_agendas_default_required_agendas() {
    let expected_agenda_ids = [
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
    assert_eq!(REQUIRED_AGENDA_IDS, expected_agenda_ids);

    let check = |mut params: Params, want_state: ThresholdState| {
        params.deployments.clear();
        let agendas = make_agendas(&params, &[]).expect("make agendas");
        assert_eq!(agendas.len(), expected_agenda_ids.len(), "{}", params.name);
        for id in expected_agenda_ids {
            let agenda = agendas
                .get(id)
                .unwrap_or_else(|| panic!("agenda id {id}: missing required default agenda"));
            assert_eq!(
                agenda.forced_state,
                Some(new_threshold_state(want_state, "")),
                "agenda id {id}"
            );
            assert!(agenda.deployment.is_none(), "agenda id {id}");
            assert!(agenda.historical_state.is_none(), "agenda id {id}");
            assert_eq!(
                lookup_agenda(&params, &[], id),
                Ok(*agenda),
                "agenda id {id}"
            );
        }
    };
    check(mainnet_params(), ThresholdState::Defined);
    check(regnet_params(), ThresholdState::Active);
}

fn choice(id: &'static str, bits: u16, is_abstain: bool, is_no: bool) -> Choice {
    Choice {
        id,
        description: "",
        bits,
        is_abstain,
        is_no,
    }
}

/// dcrd's mocked deployment for the validation cases: one vote with
/// abstain, no and yes choices over mask 0x6.
fn mock_deployment(
    id: &'static str,
    mask: u16,
    no_bits: u16,
    yes_bits: u16,
) -> ConsensusDeployment {
    ConsensusDeployment {
        vote: Vote {
            id,
            description: "",
            mask,
            choices: vec![
                choice("abstain", 0x0000, true, false),
                choice("no", no_bits, false, true),
                choice("yes", yes_bits, false, false),
            ],
        },
        forced_choice_id: "",
        start_time: 0,
        expire_time: i64::MAX as u64,
    }
}

/// Regnet parameters whose deployments are replaced with dcrd's mocked
/// one in version 0.
fn mock_params() -> Params {
    let mut params = regnet_params();
    params.deployments = vec![(0, vec![mock_deployment("testvote", 0x6, 0x2, 0x4)])];
    params
}

/// The first deployment of the mocked parameters.
fn first(params: &mut Params) -> &mut ConsensusDeployment {
    &mut params.deployments[0].1[0]
}

/// Malformed deployments are refused with dcrd's kinds (dcrd
/// `TestDeploymentParamsValidation`, `agendas_test.go:24-251`).
#[test]
fn deployment_params_validation() {
    type Munger = fn(&mut Params);
    let tests: [(&str, Munger, RuleErrorKind); 18] = [
        (
            "reject duplicate deployment id in the same version",
            |p| {
                let vote = p.deployments[0].1[0].clone();
                p.deployments[0].1.push(vote);
            },
            RuleErrorKind::DuplicateDeployment,
        ),
        (
            "reject duplicate deployment id in different versions",
            |p| {
                let votes = p.deployments[0].1.clone();
                p.deployments.push((1, votes));
            },
            RuleErrorKind::DuplicateDeployment,
        ),
        (
            "require optional forced choice to exist when specified",
            |p| first(p).forced_choice_id = "bogus",
            RuleErrorKind::UnknownDeploymentChoice,
        ),
        (
            "require optional forced choice to be non abstain when specified",
            |p| first(p).forced_choice_id = "abstain",
            RuleErrorKind::DeploymentChoiceAbstain,
        ),
        (
            "reject overlapping masks in same deployment version",
            |p| {
                p.deployments[0]
                    .1
                    .push(mock_deployment("testvote2", 0xc, 0x4, 0x8));
            },
            RuleErrorKind::DeploymentBadMask,
        ),
        (
            "require non-zero mask",
            |p| first(p).vote.mask = 0,
            RuleErrorKind::DeploymentBadMask,
        ),
        (
            "reject mask with reserved parent regular tx tree approval bit",
            |p| first(p).vote.mask |= 0x0001,
            RuleErrorKind::DeploymentBadMask,
        ),
        (
            "require consecutive mask",
            |p| first(p).vote.mask = 0xa,
            RuleErrorKind::DeploymentBadMask,
        ),
        (
            "reject too many choices",
            |p| {
                let vote = &mut first(p).vote;
                vote.choices.push(choice("maybe", 0x0006, false, false));
                vote.choices.push(choice("another", 0x0006, false, false));
            },
            RuleErrorKind::DeploymentTooManyChoices,
        ),
        (
            "reject choices without an id",
            |p| first(p).vote.choices[1].id = "",
            RuleErrorKind::DeploymentMissingChoiceID,
        ),
        (
            "reject choice with abstain bits but no abstain flag",
            |p| first(p).vote.choices[0].is_abstain = false,
            RuleErrorKind::DeploymentBadChoiceBits,
        ),
        (
            "reject choice with bits that do not conform to the mask",
            |p| first(p).vote.choices[2].bits = 0xc,
            RuleErrorKind::DeploymentBadChoiceBits,
        ),
        (
            "require exclusive abstain and no flags",
            |p| first(p).vote.choices[0].is_no = true,
            RuleErrorKind::DeploymentNonExclusiveFlags,
        ),
        (
            "require unique choice ids",
            |p| {
                let vote = &mut first(p).vote;
                vote.choices[2].id = vote.choices[1].id;
            },
            RuleErrorKind::DeploymentDuplicateChoice,
        ),
        (
            "require the abstain choice",
            |p| {
                first(p).vote.choices.remove(0);
            },
            RuleErrorKind::DeploymentMissingAbstain,
        ),
        (
            "reject more than one abstain choice",
            |p| {
                let vote = &mut first(p).vote;
                vote.choices[1].is_abstain = true;
                vote.choices[1].is_no = false;
            },
            RuleErrorKind::DeploymentTooManyAbstain,
        ),
        (
            "require a no choice",
            |p| {
                first(p).vote.choices.remove(1);
            },
            RuleErrorKind::DeploymentMissingNo,
        ),
        (
            "reject more than one no choice",
            |p| first(p).vote.choices[2].is_no = true,
            RuleErrorKind::DeploymentTooManyNo,
        ),
    ];

    // The unmodified mocked parameters are valid.
    let params = mock_params();
    make_agendas(&params, historical_agendas(params.net)).expect("mocked params");

    for (name, munger, want) in tests {
        let mut params = mock_params();
        munger(&mut params);
        let err = make_agendas(&params, historical_agendas(params.net))
            .expect_err(name)
            .kind;
        assert_eq!(err, want, "{name}");
    }
}

/// The checks dcrd's historical loop and its main network rule add to
/// `makeAgendas` (`agendas.go:490-495`, `:523-570`).
#[test]
fn historical_and_forced_choice_validation() {
    let entry = |choice_id: &'static str| HistoricalActivationState {
        anchor_height: 10,
        anchor_hash: Hash([7u8; 32]),
        choice_id,
    };
    let kind_and_text = |params: &Params, table: &[(&'static str, HistoricalActivationState)]| {
        let err = make_agendas(params, table).expect_err("refused");
        (err.kind, err.description)
    };

    // A historical activation of an agenda no deployment defines,
    // required or not: the historical loop runs before the defaults.
    let regnet = mock_params();
    assert_eq!(
        kind_and_text(&regnet, &[("bogus", entry("yes"))]),
        (
            RuleErrorKind::UnknownAgendaID,
            "agenda ID bogus for historical consensus change does not exist".to_string()
        )
    );
    assert_eq!(
        kind_and_text(&regnet, &[(VOTE_ID_TREASURY, entry("yes"))]).0,
        RuleErrorKind::UnknownAgendaID
    );

    // A historical activation of a forced agenda.
    let simnet = simnet_params();
    assert_eq!(
        kind_and_text(&simnet, &[(VOTE_ID_TREASURY, entry("yes"))]),
        (
            RuleErrorKind::HistoricalForcedChoice,
            "agenda ID treasury has both a forced choice and a historical state configured"
                .to_string()
        )
    );

    // An unknown or abstain winning choice.
    assert_eq!(
        kind_and_text(&regnet, &[("testvote", entry("maybe"))]),
        (
            RuleErrorKind::UnknownDeploymentChoice,
            "deployment ID testvote has a historical state with unknown winning choice \"maybe\""
                .to_string()
        )
    );
    assert_eq!(
        kind_and_text(&regnet, &[("testvote", entry("abstain"))]),
        (
            RuleErrorKind::DeploymentChoiceAbstain,
            "deployment ID testvote historical state choice \"abstain\" is of invalid type \
             abstain"
                .to_string()
        )
    );

    // A no winner is not a historical activation; a yes winner is.
    let agendas = make_agendas(&regnet, &[("testvote", entry("no"))]).expect("no winner");
    assert_eq!(agendas["testvote"].historical_state, None);
    let agendas = make_agendas(&regnet, &[("testvote", entry("yes"))]).expect("yes winner");
    assert_eq!(agendas["testvote"].historical_state, Some(entry("yes")));
    for (table, want) in [
        (&[("testvote", entry("no"))], None),
        (&[("testvote", entry("yes"))], Some(entry("yes"))),
    ] {
        assert_eq!(
            lookup_agenda(&regnet, table, "testvote").map(|a| a.historical_state),
            Ok(want)
        );
    }

    // A forced choice on the main network.
    let mut main = mainnet_params();
    main.deployments[0].1[0].forced_choice_id = "yes";
    let id = main.deployments[0].1[0].vote.id;
    assert_eq!(
        kind_and_text(&main, &[]),
        (
            RuleErrorKind::ForcedMainNetChoice,
            format!("deployment ID {id} has a forced choice for the main network")
        )
    );
}

/// Chain construction runs the validation: the infallible constructor
/// panics with dcrd's error text, and the database open returns it.
#[test]
fn chain_construction_validates_agendas() {
    let mut params = mock_params();
    first(&mut params).vote.mask = 0;
    let err = std::panic::catch_unwind(|| Chain::new(&params, Hash::ZERO, false))
        .err()
        .expect("Chain::new must refuse the parameters");
    let text = err
        .downcast_ref::<String>()
        .cloned()
        .expect("panic message");
    assert_eq!(text, "deployment ID testvote mask is zero");

    let dir = tempfile::tempdir().expect("tempdir");
    let opts = dcroxide_database::Options::new(dir.path().join("chain"), params.net.0);
    let db = dcroxide_database::Database::create(&opts).expect("create database");
    match Chain::open(db, &params, Hash::ZERO, false, 0) {
        Err(ChainDbError::Rule(err)) => {
            assert_eq!(err.kind, RuleErrorKind::DeploymentBadMask);
            assert_eq!(err.to_string(), "deployment ID testvote mask is zero");
        }
        Err(other) => panic!("unexpected error {other}"),
        Ok(_) => panic!("Chain::open must refuse the parameters"),
    }
}

/// Whether the BLAKE3 agenda is forced active follows the agenda's
/// forced state, which a required agenda's default supplies when the
/// network has no deployment for it (dcrd
/// `isBlake3PowAgendaForcedActive`, `agendas.go:1002-1011`).
#[test]
fn blake3_forced_active_follows_the_agenda() {
    let without_blake3 = |mut params: Params| {
        for (_, deployments) in &mut params.deployments {
            deployments.retain(|d| d.vote.id != VOTE_ID_BLAKE3_POW);
        }
        params
    };
    assert!(is_blake3_pow_agenda_forced_active(&simnet_params()));
    assert!(!is_blake3_pow_agenda_forced_active(&regnet_params()));
    assert!(!is_blake3_pow_agenda_forced_active(&mainnet_params()));
    assert!(!is_blake3_pow_agenda_forced_active(&testnet3_params()));
    assert!(is_blake3_pow_agenda_forced_active(&without_blake3(
        regnet_params()
    )));
    assert!(!is_blake3_pow_agenda_forced_active(&without_blake3(
        mainnet_params()
    )));
}

/// A chain of `len` validated blocks after genesis, returning the hash
/// of each block by height (index 0 is genesis).
fn build_chain(params: &Params, len: u32) -> (Chain, Vec<Hash>) {
    let mut chain = Chain::new(params, Hash::ZERO, false);
    let mut hashes = vec![params.genesis_block.header.block_hash()];
    let mut parent = chain.best_chain.tip().expect("genesis");
    for height in 1..=len {
        let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
        header.prev_block = chain.store.node(parent).hash;
        header.height = height;
        header.timestamp = params.genesis_block.header.timestamp + height;
        header.bits = params.pow_limit_bits;
        let id = chain.store.new_node(&header, Some(parent));
        let node = chain.store.node_mut(id);
        node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
        node.is_fully_linked = true;
        chain.index.add_node(&chain.store, id);
        hashes.push(chain.store.node(id).hash);
        parent = id;
    }
    chain.best_chain.set_tip(&chain.store, Some(parent));
    (chain, hashes)
}

/// The max block size follows the agenda and the sizes the parameters
/// offer: the larger size only when the agenda is active and a second
/// size exists (dcrd `TestMaxBlockSizeChoice`,
/// `agendas_test.go:517-603`).
#[test]
fn max_block_size_choice() {
    let with_deployment = regnet_params();
    let mut without_deployment = regnet_params();
    for (_, deployments) in &mut without_deployment.deployments {
        deployments.retain(|d| d.vote.id != VOTE_ID_MAX_BLOCK_SIZE);
    }
    let tests: [(&str, &Params, &[usize], bool, i64); 7] = [
        (
            "mainnet is never active",
            &mainnet_params(),
            &[393216, 1000000],
            false,
            393216,
        ),
        (
            "no deployment with one entry",
            &without_deployment,
            &[1000000],
            false,
            1000000,
        ),
        (
            "no deployment with two entries",
            &without_deployment,
            &[1000000, 1310720],
            false,
            1310720,
        ),
        (
            "deployment inactive with one entry",
            &with_deployment,
            &[1000000],
            false,
            1000000,
        ),
        (
            "deployment inactive with two entries",
            &with_deployment,
            &[1000000, 1310720],
            false,
            1000000,
        ),
        (
            "deployment active with one entry",
            &with_deployment,
            &[1000000],
            true,
            1000000,
        ),
        (
            "deployment active with two entries",
            &with_deployment,
            &[1000000, 1310720],
            true,
            1310720,
        ),
    ];
    for (name, base, max_sizes, force_active, want_size) in tests {
        let mut params = base.clone();
        params.maximum_block_sizes = max_sizes.to_vec();
        if force_active {
            params
                .deployments
                .iter_mut()
                .flat_map(|(_, ds)| ds)
                .find(|d| d.vote.id == VOTE_ID_MAX_BLOCK_SIZE)
                .expect("deployment")
                .forced_choice_id = "yes";
        }
        let (chain, hashes) = build_chain(&params, 10);
        assert_eq!(
            chain.max_block_size(&hashes[2], &params),
            Ok(want_size),
            "{name}"
        );
    }
}

/// The threshold state queries answer for an agenda that has only its
/// required default: the forced state, and 1 as the height its state
/// last changed, where they used to refuse the ID.  The version 3 test
/// network still keeps its single block size.
#[test]
fn default_agenda_threshold_queries() {
    for (params, want_state, want_size) in [
        (mainnet_params(), ThresholdState::Defined, 393216),
        (testnet3_params(), ThresholdState::Active, 1310720),
    ] {
        let (chain, hashes) = build_chain(&params, 10);
        assert_eq!(
            chain.next_threshold_state(&hashes[2], VOTE_ID_MAX_BLOCK_SIZE, &params),
            Ok(new_threshold_state(want_state, "")),
            "{}",
            params.name
        );
        assert_eq!(
            chain.state_last_changed_height(&hashes[2], VOTE_ID_MAX_BLOCK_SIZE, &params),
            Ok(1),
            "{}",
            params.name
        );
        assert_eq!(
            chain.max_block_size(&hashes[2], &params),
            Ok(want_size),
            "{}",
            params.name
        );
    }
}
