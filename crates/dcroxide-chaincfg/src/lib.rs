// SPDX-License-Identifier: ISC
//! Decred network parameters, mirroring dcrd's `chaincfg` package (module
//! v3.3.0, as pinned by dcrd release-v2.1.5): all four networks' genesis
//! blocks, consensus agenda deployments, block-one (premine) ledgers, and
//! every constant the consensus and policy code consumes.
//!
//! Parity is pinned by a field-by-field canonical dump ([`Params::dump`])
//! compared against an identical dump emitted by dcrd itself via
//! `tools/oracle`, plus the genesis hashes reproducing.
//!
//! Not ported (see PARITY.md): the deployment-definition validation dcrd
//! runs in its Go package init (ported as data sanity tests instead), the
//! deprecated `Checkpoints` field no network sets, and the trivial getter
//! methods dcrd needs to satisfy external interfaces (our fields are
//! public).

#![cfg_attr(not(test), no_std)]
// Parameter data and dump formatting; arithmetic is over fixed parameter
// values (ledger sums use checked semantics via i64 wrapping like dcrd).
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use dcroxide_chainhash::Hash;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{CurrencyNet, MsgBlock};

mod block_one_data;
mod mainnet;
mod regnet;
mod simnet;
mod testnet;
mod votes;

pub use mainnet::mainnet_params;
pub use regnet::regnet_params;
pub use simnet::simnet_params;
pub use testnet::testnet3_params;
pub use votes::*;

/// A single vote choice (dcrd `Choice`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// Single unique word identifying the choice (e.g. "yes").
    pub id: &'static str,
    /// Longer description of the choice.
    pub description: &'static str,
    /// The bits used for this choice.
    pub bits: u16,
    /// Whether this is the abstain choice (bits 0, exactly one per vote).
    pub is_abstain: bool,
    /// Whether this is the hard-no choice (exactly one per vote).
    pub is_no: bool,
}

/// A voting instance (dcrd `Vote`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// Single unique word identifying the vote.
    pub id: &'static str,
    /// Longer description of what the vote is about.
    pub description: &'static str,
    /// The bits usable for this vote.
    pub mask: u16,
    /// The possible choices.
    pub choices: Vec<Choice>,
}

impl Vote {
    /// The index into [`Self::choices`] for the given vote bits, or `None`
    /// when invalid (dcrd `VoteIndex`, which returns -1).
    pub fn vote_index(&self, vote_bits: u16) -> Option<usize> {
        let masked = vote_bits & self.mask;
        self.choices.iter().position(|c| c.bits == masked)
    }
}

/// A consensus rule change to be voted on (dcrd `ConsensusDeployment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusDeployment {
    /// The vote definition.
    pub vote: Vote,
    /// When non-empty, the choice that is always considered the majority
    /// result (used on test networks for already-activated agendas).
    pub forced_choice_id: &'static str,
    /// Median block time after which voting starts (ignored when forced).
    pub start_time: u64,
    /// Median block time after which the deployment expires (ignored when
    /// forced).
    pub expire_time: u64,
}

/// A block-one payout (dcrd `TokenPayout`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPayout {
    /// The required script version.
    pub script_version: u16,
    /// The payout script.
    pub script: Vec<u8>,
    /// The amount in atoms.
    pub amount: i64,
}

/// A DNS seed (dcrd `DNSSeed`; deprecated upstream but still present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSeed {
    /// The hostname of the seed.
    pub host: &'static str,
    /// Whether the seed supports filtering by service flags.
    pub has_filtering: bool,
}

/// The parameters defining a Decred network (dcrd `Params`).
///
/// Field-for-field mirror of dcrd's struct with these representation
/// mappings: `time.Duration` fields carry a `_secs` suffix and hold whole
/// seconds; `*big.Int` fields are [`Uint256`]; the deployments map is a
/// version-sorted vector; the deprecated always-empty `Checkpoints` field
/// is omitted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Names mirror dcrd's documented fields 1:1.
pub struct Params {
    pub name: &'static str,
    pub net: CurrencyNet,
    pub default_port: &'static str,
    pub dns_seeds: Vec<DnsSeed>,
    pub genesis_block: MsgBlock,
    pub genesis_hash: Hash,
    pub pow_limit: Uint256,
    pub pow_limit_bits: u32,
    pub reduce_min_difficulty: bool,
    pub min_diff_reduction_time_secs: i64,
    pub generate_supported: bool,
    pub maximum_block_sizes: Vec<usize>,
    pub max_tx_size: usize,
    pub target_time_per_block_secs: i64,
    pub work_diff_alpha: i64,
    pub work_diff_window_size: i64,
    pub work_diff_windows: i64,
    pub target_timespan_secs: i64,
    pub retarget_adjustment_factor: i64,
    pub work_diff_v2_blake3_start_bits: u32,
    pub work_diff_v2_half_life_secs: i64,
    pub base_subsidy: i64,
    pub mul_subsidy: i64,
    pub div_subsidy: i64,
    pub subsidy_reduction_interval: i64,
    pub work_reward_proportion: u16,
    pub work_reward_proportion_v2: u16,
    pub stake_reward_proportion: u16,
    pub stake_reward_proportion_v2: u16,
    pub block_tax_proportion: u16,
    pub assume_valid: Hash,
    pub min_known_chain_work: Option<Uint256>,
    pub rule_change_activation_quorum: u32,
    pub rule_change_activation_multiplier: u32,
    pub rule_change_activation_divisor: u32,
    pub rule_change_activation_interval: u32,
    /// Deployments per stake version, sorted ascending by version.
    pub deployments: Vec<(u32, Vec<ConsensusDeployment>)>,
    pub block_enforce_num_required: u64,
    pub block_reject_num_required: u64,
    pub block_upgrade_num_to_check: u64,
    pub accept_non_std_txs: bool,
    pub network_address_prefix: &'static str,
    pub pub_key_addr_id: [u8; 2],
    pub pub_key_hash_addr_id: [u8; 2],
    pub pkh_edwards_addr_id: [u8; 2],
    pub pkh_schnorr_addr_id: [u8; 2],
    pub script_hash_addr_id: [u8; 2],
    pub private_key_id: [u8; 2],
    pub hd_private_key_id: [u8; 4],
    pub hd_public_key_id: [u8; 4],
    pub slip0044_coin_type: u32,
    pub legacy_coin_type: u32,
    pub minimum_stake_diff: i64,
    pub ticket_pool_size: u16,
    pub tickets_per_block: u16,
    pub ticket_maturity: u16,
    pub ticket_expiry: u32,
    pub coinbase_maturity: u16,
    pub sstx_change_maturity: u16,
    pub ticket_pool_size_weight: u16,
    pub stake_diff_alpha: i64,
    pub stake_diff_window_size: i64,
    pub stake_diff_windows: i64,
    pub stake_version_interval: i64,
    pub max_fresh_stake_per_block: u8,
    pub stake_enabled_height: i64,
    pub stake_validation_height: i64,
    pub stake_base_sig_script: Vec<u8>,
    pub stake_majority_multiplier: i32,
    pub stake_majority_divisor: i32,
    pub organization_pk_script: Vec<u8>,
    pub organization_pk_script_version: u16,
    pub block_one_ledger: Vec<TokenPayout>,
    pub pi_keys: Vec<Vec<u8>>,
    pub treasury_vote_interval: u64,
    pub treasury_vote_interval_multiplier: u64,
    pub treasury_vote_quorum_multiplier: u64,
    pub treasury_vote_quorum_divisor: u64,
    pub treasury_vote_required_multiplier: u64,
    pub treasury_vote_required_divisor: u64,
    pub treasury_expenditure_window: u64,
    pub treasury_expenditure_policy: u64,
    pub treasury_expenditure_bootstrap: u64,
    pub seeders: Vec<&'static str>,
}

impl Params {
    /// The total subsidy of block height 1 (dcrd `BlockOneSubsidy`).
    pub fn block_one_subsidy(&self) -> i64 {
        self.block_one_ledger.iter().map(|p| p.amount).sum()
    }

    /// The sum of the pre-DCP0010 subsidy proportions (dcrd
    /// `TotalSubsidyProportions`).
    pub fn total_subsidy_proportions(&self) -> u16 {
        self.work_reward_proportion + self.stake_reward_proportion + self.block_tax_proportion
    }

    /// Whether the provided key is a sanctioned Pi key (dcrd
    /// `PiKeyExists`).
    pub fn pi_key_exists(&self, key: &[u8]) -> bool {
        self.pi_keys.iter().any(|k| k == key)
    }

    /// A canonical line-oriented dump of every parameter, compared verbatim
    /// against the identical dump emitted by dcrd through the test oracle.
    pub fn dump(&self) -> String {
        fn hex(b: &[u8]) -> String {
            b.iter().fold(String::new(), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
        }

        let mut o = String::new();
        let w = &mut o;
        let _ = writeln!(w, "name={}", self.name);
        let _ = writeln!(w, "net={:#010x}", self.net.0);
        let _ = writeln!(w, "defaultport={}", self.default_port);
        for seed in &self.dns_seeds {
            let _ = writeln!(w, "dnsseed={} {}", seed.host, seed.has_filtering);
        }
        for seeder in &self.seeders {
            let _ = writeln!(w, "seeder={seeder}");
        }
        let _ = writeln!(w, "genesishash={}", self.genesis_hash);
        let _ = writeln!(w, "genesisblock={}", hex(&self.genesis_block.serialize()));
        let _ = writeln!(w, "powlimit={}", hex(&self.pow_limit.to_be_bytes()));
        let _ = writeln!(w, "powlimitbits={:#010x}", self.pow_limit_bits);
        let _ = writeln!(w, "reducemindifficulty={}", self.reduce_min_difficulty);
        let _ = writeln!(
            w,
            "mindiffreductiontime={}",
            self.min_diff_reduction_time_secs
        );
        let _ = writeln!(w, "generatesupported={}", self.generate_supported);
        let sizes: Vec<String> = self
            .maximum_block_sizes
            .iter()
            .map(|s| alloc::format!("{s}"))
            .collect();
        let _ = writeln!(w, "maximumblocksizes={}", sizes.join(","));
        let _ = writeln!(w, "maxtxsize={}", self.max_tx_size);
        let _ = writeln!(w, "targettimeperblock={}", self.target_time_per_block_secs);
        let _ = writeln!(w, "workdiffalpha={}", self.work_diff_alpha);
        let _ = writeln!(w, "workdiffwindowsize={}", self.work_diff_window_size);
        let _ = writeln!(w, "workdiffwindows={}", self.work_diff_windows);
        let _ = writeln!(w, "targettimespan={}", self.target_timespan_secs);
        let _ = writeln!(
            w,
            "retargetadjustmentfactor={}",
            self.retarget_adjustment_factor
        );
        let _ = writeln!(
            w,
            "workdiffv2blake3startbits={:#010x}",
            self.work_diff_v2_blake3_start_bits
        );
        let _ = writeln!(
            w,
            "workdiffv2halflifesecs={}",
            self.work_diff_v2_half_life_secs
        );
        let _ = writeln!(w, "basesubsidy={}", self.base_subsidy);
        let _ = writeln!(w, "mulsubsidy={}", self.mul_subsidy);
        let _ = writeln!(w, "divsubsidy={}", self.div_subsidy);
        let _ = writeln!(
            w,
            "subsidyreductioninterval={}",
            self.subsidy_reduction_interval
        );
        let _ = writeln!(w, "workrewardproportion={}", self.work_reward_proportion);
        let _ = writeln!(
            w,
            "workrewardproportionv2={}",
            self.work_reward_proportion_v2
        );
        let _ = writeln!(w, "stakerewardproportion={}", self.stake_reward_proportion);
        let _ = writeln!(
            w,
            "stakerewardproportionv2={}",
            self.stake_reward_proportion_v2
        );
        let _ = writeln!(w, "blocktaxproportion={}", self.block_tax_proportion);
        let _ = writeln!(w, "assumevalid={}", self.assume_valid);
        match &self.min_known_chain_work {
            Some(work) => {
                let _ = writeln!(w, "minknownchainwork={}", hex(&work.to_be_bytes()));
            }
            None => {
                let _ = writeln!(w, "minknownchainwork=nil");
            }
        }
        let _ = writeln!(
            w,
            "rulechangeactivationquorum={}",
            self.rule_change_activation_quorum
        );
        let _ = writeln!(
            w,
            "rulechangeactivationmultiplier={}",
            self.rule_change_activation_multiplier
        );
        let _ = writeln!(
            w,
            "rulechangeactivationdivisor={}",
            self.rule_change_activation_divisor
        );
        let _ = writeln!(
            w,
            "rulechangeactivationinterval={}",
            self.rule_change_activation_interval
        );
        for (version, deployments) in &self.deployments {
            for dep in deployments {
                let _ = writeln!(
                    w,
                    "deployment version={} id={} mask={:#06x} forced={} start={} expire={} desc={}",
                    version,
                    dep.vote.id,
                    dep.vote.mask,
                    dep.forced_choice_id,
                    dep.start_time,
                    dep.expire_time,
                    dep.vote.description,
                );
                for c in &dep.vote.choices {
                    let _ = writeln!(
                        w,
                        "choice id={} bits={:#06x} abstain={} no={} desc={}",
                        c.id, c.bits, c.is_abstain, c.is_no, c.description,
                    );
                }
            }
        }
        let _ = writeln!(
            w,
            "blockenforcenumrequired={}",
            self.block_enforce_num_required
        );
        let _ = writeln!(
            w,
            "blockrejectnumrequired={}",
            self.block_reject_num_required
        );
        let _ = writeln!(
            w,
            "blockupgradenumtocheck={}",
            self.block_upgrade_num_to_check
        );
        let _ = writeln!(w, "acceptnonstdtxs={}", self.accept_non_std_txs);
        let _ = writeln!(w, "networkaddressprefix={}", self.network_address_prefix);
        let _ = writeln!(w, "pubkeyaddrid={}", hex(&self.pub_key_addr_id));
        let _ = writeln!(w, "pubkeyhashaddrid={}", hex(&self.pub_key_hash_addr_id));
        let _ = writeln!(w, "pkhedwardsaddrid={}", hex(&self.pkh_edwards_addr_id));
        let _ = writeln!(w, "pkhschnorraddrid={}", hex(&self.pkh_schnorr_addr_id));
        let _ = writeln!(w, "scripthashaddrid={}", hex(&self.script_hash_addr_id));
        let _ = writeln!(w, "privatekeyid={}", hex(&self.private_key_id));
        let _ = writeln!(w, "hdprivatekeyid={}", hex(&self.hd_private_key_id));
        let _ = writeln!(w, "hdpublickeyid={}", hex(&self.hd_public_key_id));
        let _ = writeln!(w, "slip0044cointype={}", self.slip0044_coin_type);
        let _ = writeln!(w, "legacycointype={}", self.legacy_coin_type);
        let _ = writeln!(w, "minimumstakediff={}", self.minimum_stake_diff);
        let _ = writeln!(w, "ticketpoolsize={}", self.ticket_pool_size);
        let _ = writeln!(w, "ticketsperblock={}", self.tickets_per_block);
        let _ = writeln!(w, "ticketmaturity={}", self.ticket_maturity);
        let _ = writeln!(w, "ticketexpiry={}", self.ticket_expiry);
        let _ = writeln!(w, "coinbasematurity={}", self.coinbase_maturity);
        let _ = writeln!(w, "sstxchangematurity={}", self.sstx_change_maturity);
        let _ = writeln!(w, "ticketpoolsizeweight={}", self.ticket_pool_size_weight);
        let _ = writeln!(w, "stakediffalpha={}", self.stake_diff_alpha);
        let _ = writeln!(w, "stakediffwindowsize={}", self.stake_diff_window_size);
        let _ = writeln!(w, "stakediffwindows={}", self.stake_diff_windows);
        let _ = writeln!(w, "stakeversioninterval={}", self.stake_version_interval);
        let _ = writeln!(
            w,
            "maxfreshstakeperblock={}",
            self.max_fresh_stake_per_block
        );
        let _ = writeln!(w, "stakeenabledheight={}", self.stake_enabled_height);
        let _ = writeln!(w, "stakevalidationheight={}", self.stake_validation_height);
        let _ = writeln!(w, "stakebasesigscript={}", hex(&self.stake_base_sig_script));
        let _ = writeln!(
            w,
            "stakemajoritymultiplier={}",
            self.stake_majority_multiplier
        );
        let _ = writeln!(w, "stakemajoritydivisor={}", self.stake_majority_divisor);
        let _ = writeln!(
            w,
            "organizationpkscript={}",
            hex(&self.organization_pk_script)
        );
        let _ = writeln!(
            w,
            "organizationpkscriptversion={}",
            self.organization_pk_script_version
        );
        let _ = writeln!(
            w,
            "blockoneledger count={} hash={}",
            self.block_one_ledger.len(),
            hex(&self.block_one_ledger_hash()),
        );
        for key in &self.pi_keys {
            let _ = writeln!(w, "pikey={}", hex(key));
        }
        let _ = writeln!(w, "treasuryvoteinterval={}", self.treasury_vote_interval);
        let _ = writeln!(
            w,
            "treasuryvoteintervalmultiplier={}",
            self.treasury_vote_interval_multiplier
        );
        let _ = writeln!(
            w,
            "treasuryvotequorummultiplier={}",
            self.treasury_vote_quorum_multiplier
        );
        let _ = writeln!(
            w,
            "treasuryvotequorumdivisor={}",
            self.treasury_vote_quorum_divisor
        );
        let _ = writeln!(
            w,
            "treasuryvoterequiredmultiplier={}",
            self.treasury_vote_required_multiplier
        );
        let _ = writeln!(
            w,
            "treasuryvoterequireddivisor={}",
            self.treasury_vote_required_divisor
        );
        let _ = writeln!(
            w,
            "treasuryexpenditurewindow={}",
            self.treasury_expenditure_window
        );
        let _ = writeln!(
            w,
            "treasuryexpenditurepolicy={}",
            self.treasury_expenditure_policy
        );
        let _ = writeln!(
            w,
            "treasuryexpenditurebootstrap={}",
            self.treasury_expenditure_bootstrap
        );
        o
    }

    /// BLAKE-256 over a canonical serialization of the block-one ledger
    /// (per payout: script version LE ‖ script length u32 LE ‖ script ‖
    /// amount as u64 LE), used to compare the full ledger compactly.
    pub fn block_one_ledger_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        for payout in &self.block_one_ledger {
            buf.extend_from_slice(&payout.script_version.to_le_bytes());
            buf.extend_from_slice(&(payout.script.len() as u32).to_le_bytes());
            buf.extend_from_slice(&payout.script);
            buf.extend_from_slice(&(payout.amount as u64).to_le_bytes());
        }
        dcroxide_crypto::blake256::sum256(&buf)
    }
}

/// Decode a hex string with panicking semantics for the hard-coded
/// parameter constants (dcrd `hexDecode`).
pub(crate) fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex constants have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex constant"))
        .collect()
}

/// Build a block-one ledger from the generated concatenated-script data
/// (dcrd `tokenPayouts` in subsidy.go).
pub(crate) fn token_payouts(scripts_hex: &str, payouts: &[(usize, i64)]) -> Vec<TokenPayout> {
    let scripts = hex_decode(scripts_hex);
    let mut ledger = Vec::with_capacity(payouts.len());
    let mut offset = 0;
    for &(end, amount) in payouts {
        ledger.push(TokenPayout {
            script_version: 0,
            script: scripts[offset..end].to_vec(),
            amount,
        });
        offset = end;
    }
    ledger
}
