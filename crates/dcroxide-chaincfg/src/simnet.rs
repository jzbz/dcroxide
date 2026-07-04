// SPDX-License-Identifier: ISC
//! Simulation test network parameters (dcrd `SimNetParams`).

use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    BlockHeader, CurrencyNet, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType,
};

use crate::block_one_data::{SIMNET_PAYOUTS, SIMNET_SCRIPTS_HEX};
use crate::votes::*;
use crate::{ConsensusDeployment, Params, Vote, hex_decode, token_payouts};

/// All simnet agendas are forced to "yes", always available, never expiring.
fn forced_deployment(vote: Vote) -> ConsensusDeployment {
    ConsensusDeployment {
        vote,
        forced_choice_id: "yes",
        start_time: 0,                    // Always available for vote
        expire_time: 9223372036854775807, // Never expires (math.MaxInt64)
    }
}

/// The parameters for the simulation test network (dcrd `SimNetParams`).
pub fn simnet_params() -> Params {
    // The highest proof of work value a Decred block can have for the
    // simulation test network: 2^255 - 1.
    let sim_net_pow_limit = {
        let mut be = [0xffu8; 32];
        be[0] = 0x7f;
        Uint256::from_be_bytes(&be)
    };
    const SIM_NET_POW_LIMIT_BITS: u32 = 0x207fffff; // 545259519

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
            bits: SIM_NET_POW_LIMIT_BITS,
            sbits: 0,
            height: 0,
            size: 0,
            timestamp: 1401292357, // 2014-05-28 15:52:37 +0000 UTC
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        // NOTE: unlike the other networks, dcrd's simnet genesis input does
        // not use the null witness sentinels: ValueIn, BlockHeight, and
        // BlockIndex are all plain zero (Go zero values), and it carries
        // Bitcoin's genesis coinbase scripts. Reproduced exactly.
        transactions: vec![MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash::ZERO,
                    index: 0xffffffff,
                    tree: 0,
                },
                sequence: 0xffffffff,
                value_in: 0,
                block_height: 0,
                block_index: 0,
                signature_script: hex_decode(
                    "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368\
                     616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c\
                     6f757420666f722062616e6b73",
                ),
            }],
            tx_out: vec![TxOut {
                value: 0x00000000,
                version: 0,
                pk_script: hex_decode(
                    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61\
                     deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1\
                     1d5fac",
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
        name: "simnet",
        net: CurrencyNet::SIM_NET,
        default_port: "18555",
        dns_seeds: Vec::new(), // NOTE: There must NOT be any seeds.

        // Chain parameters
        genesis_block,
        genesis_hash,
        pow_limit: sim_net_pow_limit,
        pow_limit_bits: SIM_NET_POW_LIMIT_BITS,
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
        work_diff_v2_blake3_start_bits: SIM_NET_POW_LIMIT_BITS,
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

        // Not set for simnet since its chain is dynamic.
        assume_valid: Hash::ZERO,
        min_known_chain_work: None,

        rule_change_activation_quorum: 160, // 10 % of RuleChangeActivationInterval * TicketsPerBlock
        rule_change_activation_multiplier: 3, // 75%
        rule_change_activation_divisor: 4,
        rule_change_activation_interval: 320, // 320 seconds
        deployments: vec![
            (4, vec![forced_deployment(max_block_size_vote())]),
            (5, vec![forced_deployment(sdiff_algorithm_vote())]),
            (6, vec![forced_deployment(ln_features_vote())]),
            (7, vec![forced_deployment(fix_ln_seq_locks_vote())]),
            (8, vec![forced_deployment(header_commitments_vote())]),
            (9, vec![forced_deployment(treasury_vote())]),
            (
                10,
                vec![
                    forced_deployment(revert_treasury_policy_vote()),
                    forced_deployment(explicit_version_upgrades_vote()),
                    forced_deployment(auto_revocations_vote()),
                    forced_deployment(change_subsidy_split_vote()),
                ],
            ),
            (
                11,
                vec![
                    forced_deployment(blake3_pow_vote()),
                    forced_deployment(change_subsidy_split_r2_vote()),
                ],
            ),
            (12, vec![forced_deployment(max_treasury_spend_vote())]),
        ],

        // Enforce current block version once majority of the network has
        // upgraded (51%); reject previous versions at 75%.
        block_enforce_num_required: 51,
        block_reject_num_required: 75,
        block_upgrade_num_to_check: 100,

        accept_non_std_txs: true,

        // Address encoding magics
        network_address_prefix: "S",
        pub_key_addr_id: [0x27, 0x6f],      // starts with Sk
        pub_key_hash_addr_id: [0x0e, 0x91], // starts with Ss
        pkh_edwards_addr_id: [0x0e, 0x71],  // starts with Se
        pkh_schnorr_addr_id: [0x0e, 0x53],  // starts with SS
        script_hash_addr_id: [0x0e, 0x6c],  // starts with Sc
        private_key_id: [0x23, 0x07],       // starts with Ps

        // BIP32 hierarchical deterministic extended key magics
        hd_private_key_id: [0x04, 0x20, 0xb9, 0x03], // starts with sprv
        hd_public_key_id: [0x04, 0x20, 0xbd, 0x3d],  // starts with spub

        slip0044_coin_type: 1, // SLIP0044, Testnet (all coins)
        legacy_coin_type: 115, // ASCII for s, for backwards compatibility

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
        stake_base_sig_script: vec![0x00, 0x00],
        stake_majority_multiplier: 3,
        stake_majority_divisor: 4,

        // Decred organization related parameters
        // Organization address is ScuQxvveKGfpG1ypt6u27F99Anf7EW3cqhq
        // (3-of-3 P2SH owned by the all-zero-seed simnet test wallet, which
        // also owns the three block-one ledger outputs).
        organization_pk_script: hex_decode("a914cbb08d6ca783b533b2c7d24a51fbca92d937bf9987"),
        organization_pk_script_version: 0,
        block_one_ledger: token_payouts(SIMNET_SCRIPTS_HEX, SIMNET_PAYOUTS),

        // Sanctioned Politeia keys (well-known simnet test keys).
        pi_keys: vec![
            hex_decode("02a36b785d584555696b69d1b2bbeff4010332b301e3edd316d79438554cacb3e7"),
            hex_decode("02b2c110e7b560aa9e1545dd18dd9f7e74a3ba036297a696050c0256f1f69479d7"),
        ],

        treasury_vote_interval: 16 * 3, // 3 times coinbase (48 blocks).
        treasury_vote_interval_multiplier: 3, // 3 * 48 block Expiry.

        treasury_expenditure_window: 4, // 4 * 2 * 48 blocks for policy check
        treasury_expenditure_policy: 3, // Avg of 3*4*2*48 blocks for policy check
        treasury_expenditure_bootstrap: 100 * 100_000_000, // 100 dcr/tew as expense bootstrap

        treasury_vote_quorum_multiplier: 1, // 20% quorum required
        treasury_vote_quorum_divisor: 5,
        treasury_vote_required_multiplier: 3, // 60% yes votes required
        treasury_vote_required_divisor: 5,

        seeders: Vec::new(), // NOTE: There must NOT be any seeds.
    }
}
