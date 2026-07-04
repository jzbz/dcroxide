// SPDX-License-Identifier: ISC
//! Test network (version 3) parameters (dcrd `TestNet3Params`).

use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    BlockHeader, CurrencyNet, MsgBlock, MsgTx, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX, NULL_VALUE_IN,
    OutPoint, TxIn, TxOut, TxSerializeType,
};

use crate::block_one_data::{TESTNET_PAYOUTS, TESTNET_SCRIPTS_HEX};
use crate::mainnet::hex32;
use crate::votes::*;
use crate::{ConsensusDeployment, DnsSeed, Params, Vote, hex_decode, token_payouts};

fn deployment(
    vote: Vote,
    forced_choice_id: &'static str,
    start_time: u64,
    expire_time: u64,
) -> ConsensusDeployment {
    ConsensusDeployment {
        vote,
        forced_choice_id,
        start_time,
        expire_time,
    }
}

/// The parameters for the test currency network, version 3 (dcrd
/// `TestNet3Params`).
pub fn testnet3_params() -> Params {
    // The highest proof of work value a Decred block can have for the test
    // network: 2^232 - 1.
    let test_net_pow_limit = {
        let mut be = [0u8; 32];
        for b in be[3..].iter_mut() {
            *b = 0xff;
        }
        Uint256::from_be_bytes(&be)
    };
    const TEST_NET_POW_LIMIT_BITS: u32 = 0x1e00ffff; // 503382015

    let mut genesis_block = MsgBlock {
        header: BlockHeader {
            version: 6,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO, // Calculated below.
            stake_root: Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: TEST_NET_POW_LIMIT_BITS, // Difficulty 1
            sbits: 20000000,
            height: 0,
            size: 0,
            timestamp: 1533513600, // 2018-08-06 00:00:00 +0000 UTC
            nonce: 0x18aea41a,
            extra_data: [0u8; 32],
            stake_version: 6,
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
    // NOTE: dcrd says this really should be TxHashFull, but it was defined
    // incorrectly and correcting it would change the block hash, which would
    // invalidate the entire test network. Reproduced exactly.
    genesis_block.header.merkle_root = genesis_block.transactions[0].tx_hash();

    let genesis_hash = genesis_block.block_hash();
    Params {
        name: "testnet3",
        net: CurrencyNet::TEST_NET3,
        default_port: "19108",
        dns_seeds: vec![
            DnsSeed {
                host: "testnet-seed.decred.mindcry.org",
                has_filtering: true,
            },
            DnsSeed {
                host: "testnet-seed.decred.netpurgatory.com",
                has_filtering: true,
            },
            DnsSeed {
                host: "testnet-seed.decred.org",
                has_filtering: true,
            },
        ],

        // Chain parameters.
        //
        // Note that the minimum difficulty reduction parameter only applies
        // up to and including block height 962927.
        genesis_block,
        genesis_hash,
        pow_limit: test_net_pow_limit,
        pow_limit_bits: TEST_NET_POW_LIMIT_BITS,
        reduce_min_difficulty: true,
        min_diff_reduction_time_secs: 60 * 10, // ~99.3% chance to be mined before reduction
        generate_supported: true,
        maximum_block_sizes: vec![1310720],
        max_tx_size: 1000000,
        target_time_per_block_secs: 60 * 2,

        // Version 1 difficulty algorithm (EMA + BLAKE256) parameters.
        work_diff_alpha: 1,
        work_diff_window_size: 144,
        work_diff_windows: 20,
        target_timespan_secs: 60 * 2 * 144, // TimePerBlock * WindowSize
        retarget_adjustment_factor: 4,

        // Version 2 difficulty algorithm (ASERT + BLAKE3) parameters.
        work_diff_v2_blake3_start_bits: TEST_NET_POW_LIMIT_BITS,
        work_diff_v2_half_life_secs: 720, // 6 * TimePerBlock (12 minutes)

        // Subsidy parameters.
        base_subsidy: 2500000000, // 25 Coin
        mul_subsidy: 100,
        div_subsidy: 101,
        subsidy_reduction_interval: 2048,
        work_reward_proportion: 6,
        work_reward_proportion_v2: 1,
        stake_reward_proportion: 3,
        stake_reward_proportion_v2: 8,
        block_tax_proportion: 1,

        // Block e5d29f04aa33d19dfe4935ca2e70d8f640a7263b653f57ce600b6829d6f2cf48
        // Height: 1780540
        assume_valid: Hash::from_str(
            "e5d29f04aa33d19dfe4935ca2e70d8f640a7263b653f57ce600b6829d6f2cf48",
        )
        .expect("valid hash literal"),

        // Block dc499445d16fb002e3f62388276bbf6669b9ac721d99069a77314490c4abb5a2
        // Height: 1790621
        min_known_chain_work: Some(Uint256::from_be_bytes(&hex32(
            "000000000000000000000000000000000000000000000000f377240e146195df",
        ))),

        rule_change_activation_quorum: 2520, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
        rule_change_activation_multiplier: 3, // 75%
        rule_change_activation_divisor: 4,
        rule_change_activation_interval: 5040, // 1 week
        deployments: vec![
            (
                5,
                vec![deployment(
                    sdiff_algorithm_vote(),
                    "yes",
                    1493164800,
                    1524700800,
                )],
            ),
            (
                6,
                vec![deployment(
                    ln_features_vote(),
                    "yes",
                    1505260800,
                    1536796800,
                )],
            ),
            (
                7,
                vec![deployment(
                    fix_ln_seq_locks_vote(),
                    "",
                    1548633600,
                    1580169600,
                )],
            ),
            (
                8,
                vec![deployment(
                    header_commitments_vote(),
                    "",
                    1567641600,
                    1599264000,
                )],
            ),
            (
                9,
                vec![deployment(treasury_vote(), "", 1596240000, 1627776000)],
            ),
            (
                10,
                vec![
                    deployment(revert_treasury_policy_vote(), "", 1631750400, 1694822400),
                    deployment(explicit_version_upgrades_vote(), "", 1631750400, 1694822400),
                    deployment(auto_revocations_vote(), "", 1631750400, 1694822400),
                    deployment(change_subsidy_split_vote(), "", 1631750400, 1694822400),
                ],
            ),
            (
                11,
                vec![
                    deployment(blake3_pow_vote(), "", 1682294400, 1745452800),
                    deployment(change_subsidy_split_r2_vote(), "", 1682294400, 1745452800),
                ],
            ),
            (
                12,
                vec![deployment(
                    max_treasury_spend_vote(),
                    "",
                    1762992000,
                    1826064000,
                )],
            ),
        ],

        // Enforce current block version once majority of the network has
        // upgraded (51%); reject previous versions at 75%.
        block_enforce_num_required: 51,
        block_reject_num_required: 75,
        block_upgrade_num_to_check: 100,

        accept_non_std_txs: true,

        // Address encoding magics
        network_address_prefix: "T",
        pub_key_addr_id: [0x28, 0xf7],      // starts with Tk
        pub_key_hash_addr_id: [0x0f, 0x21], // starts with Ts
        pkh_edwards_addr_id: [0x0f, 0x01],  // starts with Te
        pkh_schnorr_addr_id: [0x0e, 0xe3],  // starts with TS
        script_hash_addr_id: [0x0e, 0xfc],  // starts with Tc
        private_key_id: [0x23, 0x0e],       // starts with Pt

        // BIP32 hierarchical deterministic extended key magics
        hd_private_key_id: [0x04, 0x35, 0x83, 0x97], // starts with tprv
        hd_public_key_id: [0x04, 0x35, 0x87, 0xd1],  // starts with tpub

        slip0044_coin_type: 1, // SLIP0044, Testnet (all coins)
        legacy_coin_type: 11,  // for backwards compatibility

        // Decred PoS parameters
        minimum_stake_diff: 20000000, // 0.2 Coin
        ticket_pool_size: 1024,
        tickets_per_block: 5,
        ticket_maturity: 16,
        ticket_expiry: 6144, // 6*TicketPoolSize
        coinbase_maturity: 16,
        sstx_change_maturity: 1,
        ticket_pool_size_weight: 4,
        stake_diff_alpha: 1,
        stake_diff_window_size: 144,
        stake_diff_windows: 20,
        stake_version_interval: 144 * 2 * 7, // ~1 week
        max_fresh_stake_per_block: 20,       // 4*TicketsPerBlock
        stake_enabled_height: 16 + 16,       // CoinbaseMaturity + TicketMaturity
        stake_validation_height: 768,        // Arbitrary
        stake_base_sig_script: vec![0x00, 0x00],
        stake_majority_multiplier: 3,
        stake_majority_divisor: 4,

        // Decred organization related parameters.
        // Organization address is TcrypGAcGCRVXrES7hWqVZb5oLJKCZEtoL1.
        organization_pk_script: hex_decode("a914d585cd7426d25b4ea5faf1e6987aacfeda3db94287"),
        organization_pk_script_version: 0,
        block_one_ledger: token_payouts(TESTNET_SCRIPTS_HEX, TESTNET_PAYOUTS),

        // Sanctioned Politeia keys.
        pi_keys: vec![
            hex_decode("03beca9bbd227ca6bb5a58e03a36ba2b52fff09093bd7a50aee1193bccd257fb8a"),
            hex_decode("03e647c014f55265da506781f0b2d67674c35cb59b873d9926d483c4ced9a7bbd3"),
        ],

        // ~2 hours for tspend inclusion
        treasury_vote_interval: 60,
        // ~4.8 hours for short circuit approval
        treasury_vote_interval_multiplier: 4,
        // ~1 day policy window
        treasury_expenditure_window: 4,
        // ~6 day policy window check
        treasury_expenditure_policy: 3,
        // 10000 dcr/tew as expense bootstrap
        treasury_expenditure_bootstrap: 10000 * 100_000_000,

        treasury_vote_quorum_multiplier: 1, // 20% quorum required
        treasury_vote_quorum_divisor: 5,
        treasury_vote_required_multiplier: 3, // 60% yes votes required
        treasury_vote_required_divisor: 5,

        seeders: vec![
            "testnet-seed-1.decred.org",
            "testnet-seed-2.decred.org",
            "testnet-seed.jholdstock.uk",
        ],
    }
}
