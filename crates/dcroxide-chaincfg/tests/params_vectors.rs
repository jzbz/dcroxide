// SPDX-License-Identifier: ISC
//! Vector and invariant tests for the four networks' parameters:
//!
//! - the serialized genesis blocks against dcrd's own test vectors
//!   (`chaincfg/*params_test.go` at release-v2.1.5), plus the genesis
//!   hashes as emitted by dcrd itself;
//! - the block-one (premine) ledger counts and totals;
//! - the deployment-definition validation dcrd performs at package init
//!   (`chaincfg/init.go`), ported here as data sanity tests since we have
//!   no Go-style init-time registry.

// Test-harness arithmetic over bounded parameter data.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::{
    Choice, ConsensusDeployment, Params, mainnet_params, regnet_params, simnet_params,
    testnet3_params,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

fn all_networks() -> [Params; 4] {
    [
        mainnet_params(),
        testnet3_params(),
        simnet_params(),
        regnet_params(),
    ]
}

/// dcrd's expected serialized genesis block bytes, verbatim from
/// `TestGenesisBlock` / `TestTestNetGenesisBlock` / `TestSimNetGenesisBlock`
/// / `TestRegNetGenesisBlock`.
const MAINNET_GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000000000\
     0dc101dfc3c6a2eb10ca0c5374e10d28feb53f7eabcc850511ceadb99174aa6600000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000ffff011b00c2eb0b000000000000000000000000a0d7b85600000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     010100000001000000000000000000000000000000000000000000000000000000000000\
     0000ffffffff00ffffffff010000000000000000000020801679e98561ada96caec2949a\
     5d41c4cab3851eb740d951c10ecbcf265c1fd9000000000000000001ffffffffffffffff\
     00000000ffffffff02000000";

const TESTNET_GENESIS_HEX: &str = "060000000000000000000000000000000000000000000000000000000000000000000000\
     2c0ad603d44a16698ac951fa22aab5e7b30293fa1d0ac72560cdfcc9eabcdfe700000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000ffff001e002d3101000000000000000000000000808f675b1aa4ae18\
     000000000000000000000000000000000000000000000000000000000000000006000000\
     010100000001000000000000000000000000000000000000000000000000000000000000\
     0000ffffffff00ffffffff010000000000000000000020801679e98561ada96caec2949a\
     5d41c4cab3851eb740d951c10ecbcf265c1fd9000000000000000001ffffffffffffffff\
     00000000ffffffff02000000";

const SIMNET_GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000000000\
     925629c5582bbfc3609d71a2f4a887443c80d54a1fe31e95e95d42f3e288945c00000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000ffff7f20000000000000000000000000000000004506865300000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     010100000001000000000000000000000000000000000000000000000000000000000000\
     0000ffffffff00ffffffff0100000000000000000000434104678afdb0fe5548271967f1\
     a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112\
     de5c384df7ba0b8d578a4c702b6bf11d5fac000000000000000001000000000000000000\
     000000000000004d04ffff001d0104455468652054696d65732030332f4a616e2f323030\
     39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c\
     6f757420666f722062616e6b7300";

const REGNET_GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000000000\
     0dc101dfc3c6a2eb10ca0c5374e10d28feb53f7eabcc850511ceadb99174aa6600000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000ffff7f20000000000000000000000000000000008006b45b00000000\
     000000000000000000000000000000000000000000000000000000000000000000000000\
     010100000001000000000000000000000000000000000000000000000000000000000000\
     0000ffffffff00ffffffff010000000000000000000020801679e98561ada96caec2949a\
     5d41c4cab3851eb740d951c10ecbcf265c1fd9000000000000000001ffffffffffffffff\
     00000000ffffffff02000000";

#[test]
fn genesis_blocks_match_dcrd_vectors() {
    let vectors = [
        ("mainnet", MAINNET_GENESIS_HEX),
        ("testnet3", TESTNET_GENESIS_HEX),
        ("simnet", SIMNET_GENESIS_HEX),
        ("regnet", REGNET_GENESIS_HEX),
    ];
    for (params, (name, want_hex)) in all_networks().iter().zip(vectors) {
        assert_eq!(params.name, name);
        let want = unhex(want_hex);
        assert_eq!(
            params.genesis_block.serialize(),
            want,
            "{name}: serialized genesis block differs from dcrd's vector",
        );
        // And the vector decodes back to the exact same in-memory block.
        let (decoded, consumed) = MsgBlock::from_bytes(&want).expect("genesis vector decodes");
        assert_eq!(consumed, want.len(), "{name}: trailing genesis bytes");
        assert_eq!(decoded, params.genesis_block, "{name}: decode round-trip");
    }
}

#[test]
fn genesis_hashes_match_dcrd() {
    // Display-form hashes as emitted by dcrd's chaincfg at release-v2.1.5.
    let want = [
        (
            "mainnet",
            "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980",
        ),
        (
            "testnet3",
            "a649dce53918caf422e9c711c858837e08d626ecfcd198969b24f7b634a49bac",
        ),
        (
            "simnet",
            "6bef82c645999585f7255cb02672921ac2f5492820090cd635fe3a59d16b4f87",
        ),
        (
            "regnet",
            "2ced94b4ae95bba344cfa043268732d230649c640f92dce2d9518823d3057cb0",
        ),
    ];
    for (params, (name, hash_str)) in all_networks().iter().zip(want) {
        assert_eq!(params.name, name);
        assert_eq!(
            params.genesis_block.block_hash(),
            params.genesis_hash,
            "{name}: genesis_hash is not the hash of genesis_block",
        );
        assert_eq!(
            alloc_format(&params.genesis_hash),
            hash_str,
            "{name}: genesis hash differs from dcrd's",
        );
    }
}

fn alloc_format(h: &dcroxide_chainhash::Hash) -> String {
    format!("{h}")
}

#[test]
fn block_one_ledgers_have_expected_totals() {
    // Counts and totals of the premine ledgers; mainnet's is the famous
    // 1,680,000 DCR airdrop + founders ledger.
    let want = [
        ("mainnet", 3146, 168_000_000_000_000_i64),
        ("testnet3", 2, 10_000_000_000_000),
        ("simnet", 3, 30_000_000_000_000),
        ("regnet", 3, 30_000_000_000_000),
    ];
    for (params, (name, count, total)) in all_networks().iter().zip(want) {
        assert_eq!(params.block_one_ledger.len(), count, "{name}: ledger count");
        assert_eq!(params.block_one_subsidy(), total, "{name}: ledger total");
        for payout in &params.block_one_ledger {
            assert_eq!(payout.script_version, 0, "{name}: ledger script version");
            assert!(payout.amount > 0, "{name}: non-positive ledger amount");
            assert!(!payout.script.is_empty(), "{name}: empty ledger script");
        }
    }
}

#[test]
fn subsidy_proportions_sum_to_ten() {
    for params in all_networks() {
        assert_eq!(params.total_subsidy_proportions(), 10, "{}", params.name);
        // The DCP0010 v2 proportions also sum to 10 (1/8/1 + tax 1).
        let v2_sum = params.work_reward_proportion_v2
            + params.stake_reward_proportion_v2
            + params.block_tax_proportion;
        assert_eq!(v2_sum, 10, "{}: v2 proportions", params.name);
    }
}

#[test]
fn pi_keys_lookup() {
    let params = mainnet_params();
    for key in &params.pi_keys {
        assert!(params.pi_key_exists(key));
        assert_eq!(key.len(), 33, "compressed secp256k1 pubkey length");
    }
    assert!(!params.pi_key_exists(&[0u8; 33]));
    assert!(!params.pi_key_exists(b""));
}

#[test]
fn vote_index_semantics() {
    // dcrd `Vote.VoteIndex`: mask off the vote bits, then find the choice
    // with exactly those bits; None (dcrd -1) when no choice matches.
    let params = mainnet_params();
    let (_, deps) = &params.deployments[0];
    let vote = &deps[0].vote; // sdiffalgorithm, mask 0x0006
    assert_eq!(vote.vote_index(0x0000), Some(0));
    assert_eq!(vote.vote_index(0x0002), Some(1));
    assert_eq!(vote.vote_index(0x0004), Some(2));
    assert_eq!(vote.vote_index(0x0006), None);
    // Bits outside the mask are ignored.
    assert_eq!(vote.vote_index(0x0001), Some(0));
    assert_eq!(vote.vote_index(0xfff9 | 0x0002), Some(1));
}

// --- Port of dcrd chaincfg/init.go deployment validation -------------------
// dcrd validates every network's deployment definitions in the package
// init function and panics on violation. We have no init-time registry, so
// the same checks run here against all four networks' data.

/// dcrd `consecOnes`.
fn consec_ones(bits: u16) -> u32 {
    let mut c = 0u32;
    let mut v = bits;
    while v != 0 {
        c += 1;
        v &= v << 1;
    }
    c
}

/// dcrd `validateChoices`.
fn validate_choices(mask: u16, choices: &[Choice]) -> Result<(), String> {
    let mask_population_count = mask.count_ones();
    if consec_ones(mask) != mask_population_count {
        return Err("invalid mask".into());
    }
    if choices.len() > 1 << mask_population_count {
        return Err("too many choices".into());
    }

    let mut num_abstain = 0;
    let mut num_no = 0;
    let mut dups = std::collections::HashSet::new();
    let s = mask.trailing_zeros();
    for (index, choice) in choices.iter().enumerate() {
        if mask & choice.bits == 0 && !choice.is_abstain {
            return Err("invalid abstain bits".into());
        }
        if mask & choice.bits != choice.bits {
            return Err("invalid vote bits".into());
        }
        if index as u16 != choice.bits >> s {
            return Err("choices not consecutive".into());
        }
        if choice.is_abstain && choice.is_no {
            return Err("abstain and no flags are mutually exclusive".into());
        }
        if choice.is_abstain {
            num_abstain += 1;
        }
        if choice.is_no {
            num_no += 1;
        }
        if !dups.insert(choice.id.to_lowercase()) {
            return Err("duplicate choice ID".into());
        }
    }

    match (num_abstain, num_no) {
        (0, _) => Err("missing abstain choice".into()),
        (n, _) if n > 1 => Err("only one choice may have abstain flag".into()),
        (_, 0) => Err("missing no choice".into()),
        (_, n) if n > 1 => Err("only one choice may have no flag".into()),
        _ => Ok(()),
    }
}

/// dcrd `validateForcedChoice`.
fn validate_forced_choice(choice_id: &str, choices: &[Choice]) -> Result<(), String> {
    if choice_id.is_empty() {
        return Ok(());
    }
    let Some(found) = choices.iter().find(|c| c.id == choice_id) else {
        return Err(format!(
            "forced choice {choice_id:?}: choice ID does not exist"
        ));
    };
    if found.is_abstain {
        return Err(format!(
            "forced choice {choice_id:?}: abstain is not a valid forced choice"
        ));
    }
    Ok(())
}

/// dcrd `validateDeployments`, over our version-sorted vector form.
fn validate_deployments(all: &[(u32, Vec<ConsensusDeployment>)]) -> Result<(), String> {
    let mut dups = std::collections::HashSet::new();
    for (version, deployments) in all {
        for (index, dep) in deployments.iter().enumerate() {
            if !dups.insert(dep.vote.id.to_lowercase()) {
                return Err(format!(
                    "version {version} deployment index {index} id {:?}: duplicate vote id",
                    dep.vote.id
                ));
            }
        }
    }
    for (version, deployments) in all {
        for (index, dep) in deployments.iter().enumerate() {
            validate_choices(dep.vote.mask, &dep.vote.choices).map_err(|e| {
                format!(
                    "version {version} deployment index {index} id {:?}: {e}",
                    dep.vote.id
                )
            })?;
            validate_forced_choice(dep.forced_choice_id, &dep.vote.choices).map_err(|e| {
                format!(
                    "version {version} deployment index {index} id {:?}: {e}",
                    dep.vote.id
                )
            })?;
        }
    }
    Ok(())
}

#[test]
fn deployments_satisfy_dcrd_init_validation() {
    for params in all_networks() {
        validate_deployments(&params.deployments)
            .unwrap_or_else(|e| panic!("invalid agenda on {}: {e}", params.name));
        // Our vector form additionally requires strictly ascending version
        // keys (dcrd's map guarantees uniqueness; sortedness is our
        // representation invariant relied on by the dump).
        for pair in params.deployments.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "{}: versions not ascending",
                params.name
            );
        }
    }
}

#[test]
fn validation_port_rejects_bad_data() {
    // Sanity-check the ported validators against dcrd's init_test.go cases:
    // non-consecutive mask, too many choices, bad abstain, non-consecutive
    // choice bits, duplicate choice, missing forced choice.
    let params = mainnet_params();
    let (_, deps) = &params.deployments[0];
    let good = &deps[0].vote;

    assert!(
        validate_choices(0x000a, &good.choices).is_err(),
        "non-consecutive mask"
    );
    let mut choices = good.choices.clone();
    choices[1].bits = 0x0004;
    assert!(
        validate_choices(good.mask, &choices).is_err(),
        "non-consecutive bits"
    );
    let mut choices = good.choices.clone();
    choices[0].is_abstain = false;
    assert!(
        validate_choices(good.mask, &choices).is_err(),
        "missing abstain"
    );
    let mut choices = good.choices.clone();
    choices[2].id = "no";
    assert!(
        validate_choices(good.mask, &choices).is_err(),
        "duplicate id"
    );

    assert!(
        validate_forced_choice("bogus", &good.choices).is_err(),
        "missing forced"
    );
    assert!(
        validate_forced_choice("abstain", &good.choices).is_err(),
        "forced abstain"
    );
    assert!(validate_forced_choice("yes", &good.choices).is_ok());
    assert!(validate_forced_choice("", &good.choices).is_ok());
}
