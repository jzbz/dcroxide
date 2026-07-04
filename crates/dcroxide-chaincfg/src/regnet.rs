// SPDX-License-Identifier: ISC
//! Regression test network parameters (dcrd `RegNetParams`).

use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    BlockHeader, CurrencyNet, MsgBlock, MsgTx, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX, NULL_VALUE_IN,
    OutPoint, TxIn, TxOut, TxSerializeType,
};

use crate::block_one_data::{REGNET_PAYOUTS, REGNET_SCRIPTS_HEX};
use crate::votes::*;
use crate::{ConsensusDeployment, Params, Vote, hex_decode, token_payouts};

/// All regnet agendas are always available and never expire, with no forced
/// choice (unlike simnet).
fn deployment(vote: Vote) -> ConsensusDeployment {
    ConsensusDeployment {
        vote,
        forced_choice_id: "",
        start_time: 0,                    // Always available for vote
        expire_time: 9223372036854775807, // Never expires (math.MaxInt64)
    }
}

/// The parameters for the regression test network (dcrd `RegNetParams`).
pub fn regnet_params() -> Params {
    // The highest proof of work value a Decred block can have for the
    // regression test network: 2^255 - 1.
    let reg_net_pow_limit = {
        let mut be = [0xffu8; 32];
        be[0] = 0x7f;
        Uint256::from_be_bytes(&be)
    };
    const REG_NET_POW_LIMIT_BITS: u32 = 0x207fffff; // 545259519

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
            bits: REG_NET_POW_LIMIT_BITS,
            sbits: 0,
            height: 0,
            size: 0,
            timestamp: 1538524800, // 2018-10-03 00:00:00 +0000 UTC
            nonce: 0,
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
        name: "regnet",
        net: CurrencyNet::REG_NET,
        default_port: "18655",
        dns_seeds: Vec::new(), // NOTE: There must NOT be any seeds.

        // Chain parameters
        genesis_block,
        genesis_hash,
        pow_limit: reg_net_pow_limit,
        pow_limit_bits: REG_NET_POW_LIMIT_BITS,
        reduce_min_difficulty: false,
        min_diff_reduction_time_secs: 0, // Does not apply since ReduceMinDifficulty false
        generate_supported: true,
        maximum_block_sizes: vec![1000000, 1310720],
        max_tx_size: 1000000,
        target_time_per_block_secs: 1,

        // Version 1 difficulty algorithm (EMA + BLAKE256) parameters.
        work_diff_alpha: 1,
        work_diff_window_size: 8,
        work_diff_windows: 4,
        target_timespan_secs: 8, // TimePerBlock * WindowSize
        retarget_adjustment_factor: 4,

        // Version 2 difficulty algorithm (ASERT + BLAKE3) parameters.
        work_diff_v2_blake3_start_bits: REG_NET_POW_LIMIT_BITS,
        work_diff_v2_half_life_secs: 6, // 6 * TimePerBlock

        // Subsidy parameters.
        base_subsidy: 50000000000,
        mul_subsidy: 100,
        div_subsidy: 101,
        subsidy_reduction_interval: 128,
        work_reward_proportion: 6,
        work_reward_proportion_v2: 1,
        stake_reward_proportion: 3,
        stake_reward_proportion_v2: 8,
        block_tax_proportion: 1,

        // Not set for regnet since its chain is dynamic.
        assume_valid: Hash::ZERO,
        min_known_chain_work: None,

        rule_change_activation_quorum: 160, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
        rule_change_activation_multiplier: 3, // 75%
        rule_change_activation_divisor: 4,
        rule_change_activation_interval: 320, // Full ticket pool -- 320 seconds
        deployments: vec![
            (4, vec![deployment(max_block_size_vote())]),
            (5, vec![deployment(sdiff_algorithm_vote())]),
            (6, vec![deployment(ln_features_vote())]),
            (7, vec![deployment(fix_ln_seq_locks_vote())]),
            (8, vec![deployment(header_commitments_vote())]),
            (9, vec![deployment(treasury_vote())]),
            (
                10,
                vec![
                    deployment(revert_treasury_policy_vote()),
                    deployment(explicit_version_upgrades_vote()),
                    deployment(auto_revocations_vote()),
                    deployment(change_subsidy_split_vote()),
                ],
            ),
            (
                11,
                vec![
                    deployment(blake3_pow_vote()),
                    deployment(change_subsidy_split_r2_vote()),
                ],
            ),
            (12, vec![deployment(max_treasury_spend_vote())]),
        ],

        // Enforce current block version once majority of the network has
        // upgraded (51%); reject previous versions at 75%.
        block_enforce_num_required: 51,
        block_reject_num_required: 75,
        block_upgrade_num_to_check: 100,

        accept_non_std_txs: true,

        // Address encoding magics
        network_address_prefix: "R",
        pub_key_addr_id: [0x25, 0xe5],      // starts with Rk
        pub_key_hash_addr_id: [0x0e, 0x00], // starts with Rs
        pkh_edwards_addr_id: [0x0d, 0xe0],  // starts with Re
        pkh_schnorr_addr_id: [0x0d, 0xc2],  // starts with RS
        script_hash_addr_id: [0x0d, 0xdb],  // starts with Rc
        private_key_id: [0x22, 0xfe],       // starts with Pr

        // BIP32 hierarchical deterministic extended key magics
        hd_private_key_id: [0xea, 0xb4, 0x04, 0x48], // starts with rprv
        hd_public_key_id: [0xea, 0xb4, 0xf9, 0x87],  // starts with rpub

        slip0044_coin_type: 1, // SLIP0044, Testnet (all coins)
        legacy_coin_type: 1,

        // Decred PoS parameters
        minimum_stake_diff: 20000,
        ticket_pool_size: 64,
        tickets_per_block: 5,
        ticket_maturity: 16,
        ticket_expiry: 384, // 6*TicketPoolSize
        coinbase_maturity: 16,
        sstx_change_maturity: 1,
        ticket_pool_size_weight: 4,
        stake_diff_alpha: 1,
        stake_diff_window_size: 8,
        stake_diff_windows: 8,
        stake_version_interval: 8 * 2 * 7,
        max_fresh_stake_per_block: 20,        // 4*TicketsPerBlock
        stake_enabled_height: 16 + 16,        // CoinbaseMaturity + TicketMaturity
        stake_validation_height: 16 + 64 * 2, // CoinbaseMaturity + TicketPoolSize*2
        // NOTE: unlike every other network's [0x00, 0x00].
        stake_base_sig_script: vec![0x73, 0x57],
        stake_majority_multiplier: 3,
        stake_majority_divisor: 4,

        // Decred organization related parameters
        // Organization address is RcQR65gasxuzf7mUeBXeAux6Z37joPuUwUN
        // (3-of-3 P2SH owned by the all-zero-seed regnet test wallet, which
        // also owns the three block-one ledger outputs).
        organization_pk_script: hex_decode("a9146913bcc838bd0087fb3f6b3c868423d5e300078d87"),
        organization_pk_script_version: 0,
        block_one_ledger: token_payouts(REGNET_SCRIPTS_HEX, REGNET_PAYOUTS),

        // Sanctioned Politeia keys (well-known regnet test keys).
        pi_keys: vec![
            hex_decode("03b459ccf3ce4935a676414fd9ec93ecf7c9dad081a52ed6993bf073c627499388"),
            hex_decode("02e3af1209f4d39dd8b448ef0a5375befa85bbc50be0aa0936379d67444184a2c3"),
        ],

        treasury_vote_interval: 4,            // every 4 blocks for regnet
        treasury_vote_interval_multiplier: 3, // 3 * 4 block Expiry.

        treasury_expenditure_window: 4, // 4 * 2 * 4 blocks for policy check
        treasury_expenditure_policy: 3, // Avg of 3*4*2*4 blocks for policy check
        treasury_expenditure_bootstrap: 100 * 100_000_000, // 100 dcr/tew as expense bootstrap

        treasury_vote_quorum_multiplier: 1, // 20% quorum required
        treasury_vote_quorum_divisor: 5,
        treasury_vote_required_multiplier: 3, // 60% yes votes required
        treasury_vote_required_divisor: 5,

        seeders: Vec::new(), // NOTE: There must NOT be any seeds.
    }
}
