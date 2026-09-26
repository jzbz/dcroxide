// SPDX-License-Identifier: ISC
//! Version 2 block committed filters per DCP0005 (dcrd gcs
//! `blockcf2/blockcf.go`).

use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_stake as stake;
use dcroxide_wire::{MsgBlock, OutPoint};

use crate::{Error, FilterV2, KEY_SIZE};

/// The Golomb coding bin size for version 2 block filters (dcrd `B`).
pub const B: u8 = 19;

/// The false positive rate denominator for version 2 block filters
/// (dcrd `M`).
pub const M: u64 = 784931;

// Ticket commitment script layout offsets (dcrd commit*Idx constants).
const COMMIT_HASH_START_IDX: usize = 2;
const COMMIT_HASH_END_IDX: usize = COMMIT_HASH_START_IDX + 20;
const COMMIT_AMOUNT_END_IDX: usize = COMMIT_HASH_END_IDX + 8;

/// A previous output script referenced by a block could not be found
/// (dcrd `PrevScriptError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevScriptError {
    /// The outpoint whose script was missing.
    pub prev_out: OutPoint,
    /// The transaction referencing it.
    pub tx_hash: Hash,
    /// The input index within that transaction.
    pub tx_in_idx: usize,
}

impl core::fmt::Display for PrevScriptError {
    /// dcrd `PrevScriptError.Error`: the outpoint in `OutPoint.String`'s
    /// `hash:index` form, then its tree, then the referencing input.
    /// dcrd uses this text as the description of the `ErrMissingTxOut`
    /// rule error a filter build returns and inside the mining
    /// template's commitment-root error.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "unable to find output script {}:{} referenced by {}:{}",
            self.prev_out, self.prev_out.tree, self.tx_hash, self.tx_in_idx
        )
    }
}

/// The entries a filter is built from (dcrd `Entries`): subslices of
/// the scripts they commit to, as dcrd appends the script slices
/// themselves rather than copies.
#[derive(Default)]
pub struct Entries<'a>(pub Vec<&'a [u8]>);

impl<'a> Entries<'a> {
    /// Add a regular transaction output script (dcrd
    /// `AddRegularPkScript`); empty scripts are not committed.
    pub fn add_regular_pk_script(&mut self, script: &'a [u8]) {
        if script.is_empty() {
            return;
        }
        self.0.push(script);
    }

    /// Add a stake transaction output script, stripping the stake
    /// opcode tag (dcrd `AddStakePkScript`); empty scripts are not
    /// committed.
    pub fn add_stake_pk_script(&mut self, script: &'a [u8]) {
        if script.is_empty() {
            return;
        }
        self.0.push(&script[1..]);
    }
}

/// The key for a block's version 2 filter: the first 16 bytes of the
/// header's merkle root (dcrd `Key`).
pub fn key(merkle_root: &Hash) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&merkle_root.0[..KEY_SIZE]);
    key
}

/// Whether the script is a stake-tagged output script (dcrd
/// `isStakeOutput`).
fn is_stake_output(script_version: u16, pk_script: &[u8]) -> bool {
    stake::is_ticket_purchase_script(script_version, pk_script)
        || stake::is_vote_script(script_version, pk_script)
        || stake::is_revocation_script(script_version, pk_script)
        || stake::is_stake_change_script(script_version, pk_script)
        || stake::is_treasury_gen_script(script_version, pk_script)
}

/// The commitment hash from a ticket output commitment script (dcrd
/// `extractTicketCommitHash`).
fn extract_ticket_commit_hash(script: &[u8]) -> &[u8] {
    &script[COMMIT_HASH_START_IDX..COMMIT_HASH_END_IDX]
}

/// Whether the ticket commitment script commits to a P2SH script (dcrd
/// `isTicketCommitP2SH`).
fn is_ticket_commit_p2sh(script: &[u8]) -> bool {
    script[COMMIT_AMOUNT_END_IDX - 1] & 0x80 != 0
}

/// Converts ticket output commitment scripts into the P2PKH or P2SH
/// payment scripts they commit to, into one backing array (dcrd
/// `commitmentConverter`).
///
/// dcrd hands out subslices of that array as it goes, which Go's
/// garbage collector keeps alive across the array's regrowth.  Here the
/// converter records each script's range and the slices are taken once
/// every conversion is done ([`CommitmentConverter::scripts`]), so the
/// converted scripts join the entries after the others rather than in
/// block order.  The filter does not depend on entry order: its values
/// are hashed, deduplicated and sorted.
struct CommitmentConverter {
    all_scripts: Vec<u8>,
    ranges: Vec<core::ops::Range<usize>>,
}

impl CommitmentConverter {
    /// A converter with room for the typical commitments of the
    /// block's tickets (dcrd `makeCommitmentConverter`: two P2PKH
    /// conversions per ticket).
    fn new(num_tickets: u8) -> CommitmentConverter {
        const P2PKH_SCRIPT_LEN: usize = 25;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "at most 255 * 25 * 2 = 12750"
        )]
        CommitmentConverter {
            all_scripts: Vec::with_capacity(usize::from(num_tickets) * P2PKH_SCRIPT_LEN * 2),
            ranges: Vec::new(),
        }
    }

    /// Convert a commitment output script of a ticket purchase to the
    /// payment script it commits to (dcrd `paymentScript`).
    fn add_payment_script(&mut self, commitment_script: &[u8]) {
        const OP_DUP: u8 = 0x76;
        const OP_HASH160: u8 = 0xa9;
        const OP_DATA_20: u8 = 0x14;
        const OP_EQUAL: u8 = 0x87;
        const OP_EQUALVERIFY: u8 = 0x88;
        const OP_CHECKSIG: u8 = 0xac;

        let commitment_hash = extract_ticket_commit_hash(commitment_script);
        let start = self.all_scripts.len();
        if is_ticket_commit_p2sh(commitment_script) {
            // OP_HASH160 <20-byte hash> OP_EQUAL
            self.all_scripts
                .extend_from_slice(&[OP_HASH160, OP_DATA_20]);
            self.all_scripts.extend_from_slice(commitment_hash);
            self.all_scripts.push(OP_EQUAL);
        } else {
            // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
            self.all_scripts
                .extend_from_slice(&[OP_DUP, OP_HASH160, OP_DATA_20]);
            self.all_scripts.extend_from_slice(commitment_hash);
            self.all_scripts
                .extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        }
        self.ranges.push(start..self.all_scripts.len());
    }

    /// The converted payment scripts.
    fn scripts(&self) -> impl Iterator<Item = &[u8]> {
        self.ranges.iter().map(|r| &self.all_scripts[r.clone()])
    }
}

/// Whether the script is excluded from the filter entirely (dcrd
/// `excludeFromFilter`): nonzero versions, empty scripts, and scripts
/// beyond the maximum script size.
fn exclude_from_filter(script_version: u16, script: &[u8]) -> bool {
    script_version != 0 || script.is_empty() || script.len() > dcroxide_txscript::MAX_SCRIPT_SIZE
}

/// Provides the script version and script of previous outputs
/// referenced by a block (dcrd `PrevScripter`).
pub trait PrevScripter {
    /// The script version and script paying to the outpoint, or `None`
    /// when unknown.
    fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])>;
}

/// Build the version 2 block committed filter for the block per
/// DCP0005 (dcrd `Regular`).
pub fn regular(
    block: &MsgBlock,
    prev_scripts: &impl PrevScripter,
) -> Result<FilterV2, RegularError> {
    // Room for at least one output and one input per regular
    // transaction and two entries per stake transaction on average
    // (dcrd's `numEntriesHint`).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "lengths of in-memory Vec<MsgTx>, each element far larger than 3 bytes, so len * 2 + len < usize::MAX"
    )]
    let mut data = Entries(Vec::with_capacity(
        block.transactions.len() * 2 + block.stransactions.len(),
    ));
    let mut commitments = CommitmentConverter::new(block.header.fresh_stake);

    // Regular tree: all output scripts, plus the previous output
    // scripts spent by every non-coinbase transaction.
    for (i, tx) in block.transactions.iter().enumerate() {
        for tx_out in &tx.tx_out {
            if exclude_from_filter(tx_out.version, &tx_out.pk_script) {
                continue;
            }
            data.add_regular_pk_script(&tx_out.pk_script);
        }

        if i == 0 {
            continue;
        }

        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
            let prev_out = &tx_in.previous_out_point;
            let Some((script_ver, prev_out_script)) = prev_scripts.prev_script(prev_out) else {
                return Err(RegularError::PrevScript(PrevScriptError {
                    prev_out: *prev_out,
                    tx_hash: tx.tx_hash(),
                    tx_in_idx,
                }));
            };
            if exclude_from_filter(script_ver, prev_out_script) {
                continue;
            }
            let is_stake_tree = prev_out.tree == 1;
            if is_stake_tree && is_stake_output(script_ver, prev_out_script) {
                data.add_stake_pk_script(prev_out_script);
            } else {
                data.add_regular_pk_script(prev_out_script);
            }
        }
    }

    // Stake tree.
    for tx in &block.stransactions {
        match stake::determine_tx_type(tx) {
            stake::TxType::SStx => {
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    let prev_out = &tx_in.previous_out_point;
                    let Some((script_ver, prev_out_script)) = prev_scripts.prev_script(prev_out)
                    else {
                        return Err(RegularError::PrevScript(PrevScriptError {
                            prev_out: *prev_out,
                            tx_hash: tx.tx_hash(),
                            tx_in_idx,
                        }));
                    };
                    if exclude_from_filter(script_ver, prev_out_script) {
                        continue;
                    }
                    let is_stake_tree = prev_out.tree == 1;
                    if is_stake_tree && is_stake_output(script_ver, prev_out_script) {
                        data.add_stake_pk_script(prev_out_script);
                    } else {
                        data.add_regular_pk_script(prev_out_script);
                    }
                }

                for (tx_out_idx, tx_out) in tx.tx_out.iter().enumerate() {
                    // The ticket submission itself is not committed.
                    if tx_out_idx == 0 {
                        continue;
                    }

                    // Even outputs are stake change; commit them only
                    // when they pay a nonzero amount.
                    let is_change_output = tx_out_idx % 2 == 0;
                    if is_change_output {
                        if tx_out.value == 0 {
                            continue;
                        }
                        data.add_stake_pk_script(&tx_out.pk_script);
                        continue;
                    }

                    // Odd outputs are commitments: commit the payment
                    // script the commitment resolves to.
                    if tx_out.pk_script.is_empty() {
                        continue;
                    }
                    commitments.add_payment_script(&tx_out.pk_script);
                }
            }
            stake::TxType::SSGen => {
                for tx_out in &tx.tx_out[2..] {
                    data.add_stake_pk_script(&tx_out.pk_script);
                }
            }
            stake::TxType::SSRtx => {
                for tx_out in &tx.tx_out {
                    data.add_stake_pk_script(&tx_out.pk_script);
                }
            }
            stake::TxType::TAdd => {
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    let prev_out = &tx_in.previous_out_point;
                    let Some((script_ver, prev_out_script)) = prev_scripts.prev_script(prev_out)
                    else {
                        return Err(RegularError::PrevScript(PrevScriptError {
                            prev_out: *prev_out,
                            tx_hash: tx.tx_hash(),
                            tx_in_idx,
                        }));
                    };
                    if exclude_from_filter(script_ver, prev_out_script) {
                        continue;
                    }
                    let is_stake_tree = prev_out.tree == 1;
                    if is_stake_tree && is_stake_output(script_ver, prev_out_script) {
                        data.add_stake_pk_script(prev_out_script);
                    } else {
                        data.add_regular_pk_script(prev_out_script);
                    }
                }

                // Commit any change output paying a nonzero amount.
                if tx.tx_out.len() == 2 && tx.tx_out[1].value != 0 {
                    data.add_stake_pk_script(&tx.tx_out[1].pk_script);
                }
            }
            stake::TxType::TSpend => {
                for tx_out in &tx.tx_out[1..] {
                    data.add_stake_pk_script(&tx_out.pk_script);
                }
            }
            _ => {}
        }
    }

    // The converted commitment scripts are committed as regular
    // scripts; they are never empty.
    let mut entries = data.0;
    entries.extend(commitments.scripts());

    let key = key(&block.header.merkle_root);
    FilterV2::new(B, M, key, &entries).map_err(RegularError::Gcs)
}

/// An error from [`regular`]: either a missing previous script or a
/// filter construction error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegularError {
    /// A previous output script referenced by the block was not
    /// provided.
    PrevScript(PrevScriptError),
    /// The filter could not be constructed.
    Gcs(Error),
}

impl core::fmt::Display for RegularError {
    /// The wrapped error's own text: dcrd's `Regular` returns either
    /// error unwrapped, and its callers print `err.Error()`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegularError::PrevScript(e) => core::fmt::Display::fmt(e, f),
            RegularError::Gcs(e) => core::fmt::Display::fmt(e, f),
        }
    }
}
