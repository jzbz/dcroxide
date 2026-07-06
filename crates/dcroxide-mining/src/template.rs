// SPDX-License-Identifier: ISC

//! The block template building blocks from dcrd's `mining.go`: the
//! parent vote sorting, the coinbase and treasurybase construction,
//! the template merkle and commitment roots, and the fee rate
//! calculation.  The template assembly itself (`NewBlockTemplate`)
//! arrives with the following piece.

use alloc::vec::Vec;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_standalone::{
    SubsidyCache, SubsidyParams, SubsidySplitVariant, calc_combined_tx_tree_merkle_root,
    calc_tx_tree_merkle_root,
};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_wire::{MsgBlock, MsgTx, TxIn, TxOut};

use crate::types::{TxAncestorStats, TxDesc, VoteDesc};

/// The size of a kilobyte (dcrd `kilobyte`).
const KILOBYTE: i64 = 1000;

/// A simple public key script containing OP_TRUE (dcrd
/// `opTrueScript`).
const OP_TRUE_SCRIPT: [u8; 1] = [0x51];

/// A block that has yet to be solved along with details about the
/// fees and signature operations of each transaction (dcrd
/// `BlockTemplate`).
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// The block, completely valid except for the proof of work.
    pub block: MsgBlock,
    /// The fee each transaction pays; the coinbase entry carries the
    /// negative sum of all other fees.
    pub fees: Vec<i64>,
    /// The signature operations each transaction performs.
    pub sig_op_counts: Vec<i64>,
    /// The height at which the template connects to the main chain.
    pub height: i64,
    /// Whether the coinbase pays to an address (false when it is
    /// redeemable by anyone).
    pub valid_pay_address: bool,
}

/// Whether any output of the listed transactions is spent by an input
/// of the given transaction (dcrd `containsTxIns`).
pub fn contains_tx_ins(txs: &[&MsgTx], tx_hashes: &[Hash], tx: &MsgTx) -> bool {
    debug_assert_eq!(txs.len(), tx_hashes.len());
    for tx_hash in tx_hashes {
        for tx_in in &tx.tx_in {
            if tx_in.previous_out_point.hash == *tx_hash {
                return true;
            }
        }
    }
    false
}

/// Whether the hash exists in the list (dcrd `hashInSlice`).
pub fn hash_in_slice(h: &Hash, list: &[Hash]) -> bool {
    list.contains(h)
}

/// The index of the transaction hash in the list, or `None` (dcrd
/// `txIndexFromTxList`, which returns -1).
pub fn tx_index_from_tx_list(hash: &Hash, list: &[Hash]) -> Option<usize> {
    list.iter().position(|h| h == hash)
}

/// Sort the given block hashes by the number of votes available for
/// them in the transaction source, returning only those with at
/// least a majority of votes, most votes first, while avoiding a
/// needless reorganization when the current top block ties the
/// leader (dcrd `SortParentsByVotes`; the source's `VotesForBlocks`
/// is supplied as a lookup).
pub fn sort_parents_by_votes(
    votes_for_blocks: impl Fn(&[Hash]) -> Vec<Vec<VoteDesc>>,
    current_top_block: Hash,
    blocks: &[Hash],
    params: &Params,
) -> Vec<Hash> {
    // Return now when no blocks were provided.
    if blocks.is_empty() {
        return Vec::new();
    }

    // Fetch the vote metadata for the provided block hashes and
    // filter out any blocks without the minimum required number of
    // votes.
    let min_votes_required = params.tickets_per_block / 2 + 1;
    let vote_metadata = votes_for_blocks(blocks);
    let mut filtered: Vec<(Hash, u16)> = Vec::with_capacity(blocks.len());
    for (block, votes) in blocks.iter().zip(&vote_metadata) {
        let num_votes = votes.len() as u16;
        if num_votes >= min_votes_required {
            filtered.push((*block, num_votes));
        }
    }

    // Return now if there are no blocks with enough votes to be
    // eligible to build on top of.
    if filtered.is_empty() {
        return Vec::new();
    }

    // Blocks with the most votes appear at the top of the list.  Go's
    // sort.Sort is unstable in general but is insertion sort (stable)
    // at the sizes involved here, matching this stable sort.
    filtered.sort_by_key(|a| core::cmp::Reverse(a.1));
    let mut sorted_useful_blocks: Vec<Hash> = filtered.iter().map(|(h, _)| *h).collect();

    // Make sure the chain is not reorganized needlessly if the top
    // block ties the current leader after the sort.
    let cur_vote_metadata = votes_for_blocks(&[current_top_block]);
    let num_top_block_votes = cur_vote_metadata
        .first()
        .map(|v| v.len() as u16)
        .unwrap_or_default();
    if filtered[0].1 == num_top_block_votes && filtered[0].0 != current_top_block {
        // Attempt to find the position of the current block being
        // built from in the list.
        let pos = filtered
            .iter()
            .position(|(h, _)| *h == current_top_block)
            .unwrap_or(0);

        // Swap the top block into the first position.
        if pos != 0 {
            sorted_useful_blocks.swap(0, pos);
        }
    }

    sorted_useful_blocks
}

/// The standard OP_RETURN output script for a coinbase, pushing the
/// height and extra nonce (dcrd `standardCoinbaseOpReturn`, which
/// autogenerates the nonce; it is injected here).
pub fn standard_coinbase_op_return(height: u32, extra_nonce: u64) -> Result<Vec<u8>, String> {
    let mut en_data = [0u8; 12];
    en_data[0..4].copy_from_slice(&height.to_le_bytes());
    en_data[4..12].copy_from_slice(&extra_nonce.to_le_bytes());
    dcroxide_txscript::stdscript::provably_pruneable_script_v0(&en_data)
        .map_err(|e| alloc::format!("{e:?}"))
}

/// The standard OP_RETURN output script for a treasurybase (dcrd
/// `standardTreasurybaseOpReturn`, nonce injected as above).
pub fn standard_treasurybase_op_return(height: u32, extra_nonce: u64) -> Result<Vec<u8>, String> {
    standard_coinbase_op_return(height, extra_nonce)
}

/// The template merkle root: the regular tree root before the header
/// commitments agenda, the DCP0005 combined root after (dcrd
/// `calcBlockMerkleRoot`).
pub fn calc_block_merkle_root(
    regular_txns: &[MsgTx],
    stake_txns: &[MsgTx],
    hdr_cmt_active: bool,
) -> Hash {
    if !hdr_cmt_active {
        return calc_tx_tree_merkle_root(regular_txns);
    }
    calc_combined_tx_tree_merkle_root(regular_txns, stake_txns)
}

/// The required v1 block commitment root for the block given the
/// previous output scripts it references (dcrd
/// `calcBlockCommitmentRootV1`).
pub fn calc_block_commitment_root_v1(
    block: &MsgBlock,
    prev_scripts: &impl dcroxide_gcs::blockcf2::PrevScripter,
) -> Result<Hash, String> {
    let filter = dcroxide_gcs::blockcf2::regular(block, prev_scripts)
        .map_err(|e| alloc::format!("{e:?}"))?;
    Ok(dcroxide_blockchain::validate::calc_commitment_root_v1(
        filter.hash(),
    ))
}

/// A coinbase transaction paying the appropriate subsidy for the
/// block height to the provided address, or redeemable by anyone
/// when no address is given (dcrd `createCoinbaseTx`).
#[allow(clippy::too_many_arguments)]
pub fn create_coinbase_tx<SP: SubsidyParams>(
    subsidy_cache: &mut SubsidyCache<SP>,
    coinbase_script: &[u8],
    op_return_pk_script: &[u8],
    next_block_height: i64,
    addr: Option<&Address>,
    voters: u16,
    params: &Params,
    is_treasury_enabled: bool,
    subsidy_split_variant: SubsidySplitVariant,
) -> MsgTx {
    // Coinbase transactions have no inputs, so the previous outpoint
    // is the zero hash and max index.
    let coinbase_input = TxIn {
        previous_out_point: dcroxide_wire::OutPoint {
            hash: Hash::ZERO,
            index: dcroxide_wire::MAX_PREV_OUT_INDEX,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        },
        sequence: dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
        block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
        block_index: dcroxide_wire::NULL_BLOCK_INDEX,
        signature_script: coinbase_script.to_vec(),
        value_in: 0,
    };

    // Block one is a special block that might pay out tokens to a
    // ledger.
    if next_block_height == 1 && !params.block_one_ledger.is_empty() {
        let mut tx = new_msg_tx();
        tx.version = 1;
        tx.tx_in.push(coinbase_input);
        tx.tx_in[0].value_in = params.block_one_subsidy();
        for payout in &params.block_one_ledger {
            tx.tx_out.push(TxOut {
                value: payout.amount,
                version: payout.script_version,
                pk_script: payout.script.clone(),
            });
        }
        return tx;
    }

    // Prior to the decentralized treasury agenda, the transaction
    // version must be 1 and there is an additional output that either
    // pays to the organization associated with the treasury or a
    // provably pruneable zero-value output script when it is
    // disabled.  Once the agenda is active, the transaction version
    // must be the new expected version and there is no treasury
    // output since it is included in the stake tree instead.
    let mut tx_version: u16 = 1;
    let mut treasury_output: Option<TxOut> = None;
    let mut treasury_subsidy: i64 = 0;
    if !is_treasury_enabled {
        if params.block_tax_proportion > 0 {
            treasury_subsidy =
                subsidy_cache.calc_treasury_subsidy(next_block_height, voters, is_treasury_enabled);
            treasury_output = Some(TxOut {
                value: treasury_subsidy,
                version: 0,
                pk_script: params.organization_pk_script.clone(),
            });
        } else {
            // Treasury disabled.
            treasury_output = Some(TxOut {
                value: 0,
                version: 0,
                pk_script: OP_TRUE_SCRIPT.to_vec(),
            });
        }
    } else {
        tx_version = dcroxide_stake::TX_VERSION_TREASURY;
    }

    // Pay to the provided address when one was specified, otherwise
    // make the coinbase redeemable by anyone.
    let (work_subsidy_script_ver, work_subsidy_script) = match addr {
        Some(addr) => addr.payment_script(),
        None => (0, OP_TRUE_SCRIPT.to_vec()),
    };

    let work_subsidy =
        subsidy_cache.calc_work_subsidy_v3(next_block_height, voters, subsidy_split_variant);
    let mut tx = new_msg_tx();
    tx.version = tx_version;
    tx.tx_in.push(coinbase_input);
    tx.tx_in[0].value_in = work_subsidy + treasury_subsidy;
    if let Some(out) = treasury_output {
        tx.tx_out.push(out);
    }
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: op_return_pk_script.to_vec(),
    });
    tx.tx_out.push(TxOut {
        value: work_subsidy,
        version: work_subsidy_script_ver,
        pk_script: work_subsidy_script,
    });
    tx
}

/// A treasurybase transaction paying the appropriate subsidy for the
/// block height to the treasury (dcrd `createTreasuryBaseTx`, nonce
/// injected).
pub fn create_treasury_base_tx<SP: SubsidyParams>(
    subsidy_cache: &mut SubsidyCache<SP>,
    next_block_height: i64,
    voters: u16,
    extra_nonce: u64,
) -> Result<MsgTx, String> {
    // Create a provably pruneable script encoding the block height to
    // ensure a unique overall transaction hash.
    let op_return_treasury =
        standard_treasurybase_op_return(next_block_height as u32, extra_nonce)?;

    const WITH_TREASURY: bool = true;
    let trsy_subsidy =
        subsidy_cache.calc_treasury_subsidy(next_block_height, voters, WITH_TREASURY);
    let mut tx = new_msg_tx();
    tx.version = dcroxide_stake::TX_VERSION_TREASURY;
    tx.tx_in.push(TxIn {
        previous_out_point: dcroxide_wire::OutPoint {
            hash: Hash::ZERO,
            index: dcroxide_wire::MAX_PREV_OUT_INDEX,
            tree: dcroxide_wire::TX_TREE_REGULAR,
        },
        sequence: dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
        block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
        block_index: dcroxide_wire::NULL_BLOCK_INDEX,
        // Must be empty by consensus.
        signature_script: Vec::new(),
        value_in: trsy_subsidy,
    });
    tx.tx_out.push(TxOut {
        value: trsy_subsidy,
        version: 0,
        pk_script: alloc::vec![0xc1], // OP_TADD
    });
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: op_return_treasury,
    });
    Ok(tx)
}

/// The minimum allowed timestamp for a block building on the current
/// best chain, as unix seconds: one second after the past median
/// time (dcrd `minimumMedianTime`).
pub fn minimum_median_time(best_median_time_unix: i64) -> i64 {
    best_median_time_unix + 1
}

/// The prioritized fee per kilobyte of a transaction, incorporating
/// its unconfirmed ancestors when their statistics are valid (dcrd
/// `calcFeePerKb`).
pub fn calc_fee_per_kb(tx_desc: &TxDesc, ancestor_stats: &TxAncestorStats) -> f64 {
    let tx_size = tx_desc.tx.serialize_size() as i64;
    if ancestor_stats.fees < 0 || ancestor_stats.size_bytes < 0 {
        return (tx_desc.fee as f64 * KILOBYTE as f64) / tx_size as f64;
    }
    ((tx_desc.fee + ancestor_stats.fees) as f64 * KILOBYTE as f64)
        / (tx_size + ancestor_stats.size_bytes) as f64
}

/// A new empty full-serialization transaction (Go `wire.NewMsgTx`).
fn new_msg_tx() -> MsgTx {
    MsgTx::from_bytes(&[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    .expect("empty transaction template")
    .0
}

use alloc::string::String;
