// SPDX-License-Identifier: ISC
//! Main network parameters (dcrd `MainNetParams`).

use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    BlockHeader, CurrencyNet, MsgBlock, MsgTx, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX, NULL_VALUE_IN,
    OutPoint, TxIn, TxOut, TxSerializeType,
};

use crate::block_one_data::{MAINNET_PAYOUTS, MAINNET_SCRIPTS_HEX};
use crate::votes::*;
use crate::{ConsensusDeployment, DnsSeed, Params, Vote, hex_decode, token_payouts};

fn deployment(vote: Vote, start_time: u64, expire_time: u64) -> ConsensusDeployment {
    ConsensusDeployment {
        vote,
        forced_choice_id: "",
        start_time,
        expire_time,
    }
}

/// The parameters for the main Decred network (dcrd `MainNetParams`).
pub fn mainnet_params() -> Params {
    // The highest proof of work value a Decred block can have for the main
    // network: 2^224 - 1.
    let main_pow_limit = {
        let mut be = [0u8; 32];
        for b in be[4..].iter_mut() {
            *b = 0xff;
        }
        Uint256::from_be_bytes(&be)
    };
    const MAIN_POW_LIMIT_BITS: u32 = 0x1d00ffff; // 486604799

    let mut genesis_block = MsgBlock {
        header: BlockHeader {
            version: 1,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO, // Calculated below.
            stake_root: Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0x1b01ffff,       // Difficulty 32767
            sbits: 2 * 100_000_000, // 2 Coin
            height: 0,
            size: 0,
            timestamp: 1454954400, // Mon, 08 Feb 2016 18:00:00 GMT
            nonce: 0x00000000,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        transactions: vec![MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                // Fully null.
                previous_out_point: OutPoint {
                    hash: Hash::ZERO,
                    index: 0xffffffff,
                    tree: 0,
                },
                sequence: 0xffffffff,
                value_in: NULL_VALUE_IN,
                block_height: NULL_BLOCK_HEIGHT,
                block_index: NULL_BLOCK_INDEX,
                signature_script: hex_decode("0000"),
            }],
            tx_out: vec![TxOut {
                value: 0x00000000,
                version: 0x0000,
                pk_script: hex_decode(
                    "801679e98561ada96caec2949a5d41c4cab3851eb740d951c10ecbcf265c1fd9",
                ),
            }],
            lock_time: 0,
            expiry: 0,
        }],
        stransactions: Vec::new(),
    };
    genesis_block.header.merkle_root = genesis_block.transactions[0].tx_hash_full();

    let genesis_hash = genesis_block.block_hash();
    Params {
        name: "mainnet",
        net: CurrencyNet::MAIN_NET,
        default_port: "9108",
        dns_seeds: vec![
            DnsSeed {
                host: "mainnet-seed.decred.mindcry.org",
                has_filtering: true,
            },
            DnsSeed {
                host: "mainnet-seed.decred.netpurgatory.com",
                has_filtering: true,
            },
            DnsSeed {
                host: "mainnet-seed.decred.org",
                has_filtering: true,
            },
        ],

        // Chain parameters
        genesis_block,
        genesis_hash,
        pow_limit: main_pow_limit,
        pow_limit_bits: MAIN_POW_LIMIT_BITS,
        reduce_min_difficulty: false,
        min_diff_reduction_time_secs: 0, // Does not apply since ReduceMinDifficulty false
        generate_supported: false,
        maximum_block_sizes: vec![393216],
        max_tx_size: 393216,
        target_time_per_block_secs: 60 * 5,

        // Version 1 difficulty algorithm (EMA + BLAKE256) parameters.
        work_diff_alpha: 1,
        work_diff_window_size: 144,
        work_diff_windows: 20,
        target_timespan_secs: 60 * 5 * 144, // TimePerBlock * WindowSize
        retarget_adjustment_factor: 4,

        // Version 2 difficulty algorithm (ASERT + BLAKE3) parameters.
        work_diff_v2_blake3_start_bits: 0x1b00a5a6,
        work_diff_v2_half_life_secs: 43200, // 144 * TimePerBlock (12 hours)

        // Subsidy parameters.
        base_subsidy: 3119582664, // 21m
        mul_subsidy: 100,
        div_subsidy: 101,
        subsidy_reduction_interval: 6144,
        work_reward_proportion: 6,
        work_reward_proportion_v2: 1,
        stake_reward_proportion: 3,
        stake_reward_proportion_v2: 8,
        block_tax_proportion: 1,

        // Block 458d6a8e11c916d4149ca8bc5c7aaaaf16cc61971b0c20764c07edf85df44eb6
        // Height: 1026597
        assume_valid: Hash::from_str(
            "458d6a8e11c916d4149ca8bc5c7aaaaf16cc61971b0c20764c07edf85df44eb6",
        )
        .expect("valid hash literal"),

        // Block 48681f17d2c8fc545f9a1d2e9ee9946e9b33d3923ed1ab6180f04a641c26302a
        // Height: 1030629
        min_known_chain_work: Some(Uint256::from_be_bytes(&hex32(
            "000000000000000000000000000000000000000000243868232c14b8224643b6",
        ))),

        rule_change_activation_quorum: 4032, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
        rule_change_activation_multiplier: 3, // 75%
        rule_change_activation_divisor: 4,
        rule_change_activation_interval: 2016 * 4, // 4 weeks
        deployments: vec![
            (
                4,
                vec![
                    deployment(sdiff_algorithm_vote(), 1493164800, 1524700800),
                    deployment(ln_support_vote(), 1493164800, 1508976000),
                ],
            ),
            (
                5,
                vec![deployment(ln_features_vote(), 1505260800, 1536796800)],
            ),
            (
                6,
                vec![deployment(fix_ln_seq_locks_vote(), 1548633600, 1580169600)],
            ),
            (
                7,
                vec![deployment(
                    header_commitments_vote(),
                    1567641600,
                    1599264000,
                )],
            ),
            (8, vec![deployment(treasury_vote(), 1596240000, 1627776000)]),
            (
                9,
                vec![
                    deployment(revert_treasury_policy_vote(), 1631750400, 1694822400),
                    deployment(explicit_version_upgrades_vote(), 1631750400, 1694822400),
                    deployment(auto_revocations_vote(), 1631750400, 1694822400),
                    deployment(change_subsidy_split_vote(), 1631750400, 1694822400),
                ],
            ),
            (
                10,
                vec![
                    deployment(blake3_pow_vote(), 1682294400, 1745452800),
                    deployment(change_subsidy_split_r2_vote(), 1682294400, 1745452800),
                ],
            ),
            (
                11,
                vec![deployment(
                    max_treasury_spend_vote(),
                    1762992000,
                    1826064000,
                )],
            ),
        ],

        // Enforce current block version once majority of the network has
        // upgraded (75%); reject previous versions at 95%.
        block_enforce_num_required: 750,
        block_reject_num_required: 950,
        block_upgrade_num_to_check: 1000,

        accept_non_std_txs: false,

        // Address encoding magics
        network_address_prefix: "D",
        pub_key_addr_id: [0x13, 0x86],      // starts with Dk
        pub_key_hash_addr_id: [0x07, 0x3f], // starts with Ds
        pkh_edwards_addr_id: [0x07, 0x1f],  // starts with De
        pkh_schnorr_addr_id: [0x07, 0x01],  // starts with DS
        script_hash_addr_id: [0x07, 0x1a],  // starts with Dc
        private_key_id: [0x22, 0xde],       // starts with Pm

        // BIP32 hierarchical deterministic extended key magics
        hd_private_key_id: [0x02, 0xfd, 0xa4, 0xe8], // starts with dprv
        hd_public_key_id: [0x02, 0xfd, 0xa9, 0x26],  // starts with dpub

        slip0044_coin_type: 42, // SLIP0044, Decred
        legacy_coin_type: 20,   // for backwards compatibility

        // Decred PoS parameters
        minimum_stake_diff: 2 * 100_000_000, // 2 Coin
        ticket_pool_size: 8192,
        tickets_per_block: 5,
        ticket_maturity: 256,
        ticket_expiry: 40960, // 5*TicketPoolSize
        coinbase_maturity: 256,
        sstx_change_maturity: 1,
        ticket_pool_size_weight: 4,
        stake_diff_alpha: 1, // Minimal
        stake_diff_window_size: 144,
        stake_diff_windows: 20,
        stake_version_interval: 144 * 2 * 7, // ~1 week
        max_fresh_stake_per_block: 20,       // 4*TicketsPerBlock
        stake_enabled_height: 256 + 256,     // CoinbaseMaturity + TicketMaturity
        stake_validation_height: 4096,       // ~14 days
        stake_base_sig_script: vec![0x00, 0x00],
        stake_majority_multiplier: 3,
        stake_majority_divisor: 4,

        // Decred organization related parameters
        // Organization address is Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx
        organization_pk_script: hex_decode("a914f5916158e3e2c4551c1796708db8367207ed13bb87"),
        organization_pk_script_version: 0,
        block_one_ledger: token_payouts(MAINNET_SCRIPTS_HEX, MAINNET_PAYOUTS),

        // Sanctioned Politeia keys.
        pi_keys: vec![
            hex_decode("03f6e7041f1cf51ee10e0a01cd2b0385ce3cd9debaabb2296f7e9dee9329da946c"),
            hex_decode("0319a37405cb4d1691971847d7719cfce70857c0f6e97d7c9174a3998cf0ab86dd"),
        ],

        // ~1 day for tspend inclusion
        treasury_vote_interval: 288,
        // ~7.2 days for short circuit approval, ~42%
        treasury_vote_interval_multiplier: 12,
        // Sum of tspends within any ~24 day window cannot exceed policy check
        treasury_expenditure_window: 2,
        // policy check is average of prior ~4.8 months + a 50% increase allowance
        treasury_expenditure_policy: 6,
        // 16000 dcr/tew as expense bootstrap
        treasury_expenditure_bootstrap: 16000 * 100_000_000,

        treasury_vote_quorum_multiplier: 1, // 20% quorum required
        treasury_vote_quorum_divisor: 5,
        treasury_vote_required_multiplier: 3, // 60% yes votes required
        treasury_vote_required_divisor: 5,

        seeders: vec![
            "mainnet-seed-1.decred.org",
            "mainnet-seed-2.decred.org",
            "mainnet-seed.jholdstock.uk",
            // A deliberate dcroxide addition on top of dcrd's list; the
            // chaincfg oracle differential excludes it when comparing
            // against dcrd's dump.
            "dcr-seed.jz.bz",
        ],
    }
}

/// Decode a 64-char hex string into a 32-byte big-endian array.
pub(crate) fn hex32(s: &str) -> [u8; 32] {
    let v = hex_decode(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}
