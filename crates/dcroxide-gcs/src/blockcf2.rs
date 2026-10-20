// SPDX-License-Identifier: ISC
//! Version 2 block committed filters per DCP0005 (dcrd gcs
//! `blockcf2/blockcf.go`).

use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_stake as stake;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE};

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

/// Provides the script version and script of the output each input of a
/// block spends, by the input's place in the block, for
/// [`regular_by_input`].  dcrd has no counterpart: its `Regular` looks
/// each script up by the outpoint ([`PrevScripter`]).
///
/// A source that knows a block's inputs by their place, such as the
/// spend journal the block's connect built, answers without a search.
pub trait InputScripts {
    /// The script version and script of the output spent by input
    /// `tx_in_idx` of the transaction at `tx_idx` in the block's tree
    /// `tree` (`dcroxide_wire::TX_TREE_REGULAR` or `TX_TREE_STAKE`), which
    /// is `prev_out`, or `None` when unknown.  It must be the script a
    /// [`PrevScripter`] over the same state gives for `prev_out`.
    fn input_script(
        &self,
        tree: i8,
        tx_idx: usize,
        tx_in_idx: usize,
        prev_out: &OutPoint,
    ) -> Option<(u16, &[u8])>;
}

/// A [`PrevScripter`] read as [`InputScripts`]: each input's script
/// looked up by the outpoint it spends.
struct ByOutPoint<'a, P: ?Sized>(&'a P);

impl<P: PrevScripter + ?Sized> InputScripts for ByOutPoint<'_, P> {
    fn input_script(&self, _: i8, _: usize, _: usize, prev_out: &OutPoint) -> Option<(u16, &[u8])> {
        self.0.prev_script(prev_out)
    }
}

/// Build the version 2 block committed filter for the block per
/// DCP0005 (dcrd `Regular`).
///
/// Each stake transaction is classified here
/// (`dcroxide_stake::determine_tx_type`), as dcrd classifies it.  A
/// caller that holds the classifications already hands them to
/// [`regular_with_types`] instead.
pub fn regular(
    block: &MsgBlock,
    prev_scripts: &impl PrevScripter,
) -> Result<FilterV2, RegularError> {
    build(
        block,
        |_, tx| stake::determine_tx_type(tx),
        &ByOutPoint(prev_scripts),
    )
}

/// [`regular`] given the classification of each of the block's stake
/// transactions, in block order: `stake_types[i]` must be
/// `dcroxide_stake::determine_tx_type` of `block.stransactions[i]`.  The
/// filter is [`regular`]'s, byte for byte.
///
/// dcrd classifies each stake transaction where it builds the filter
/// (`blockcf2.go`'s `Regular`) and again at each other step of a block's
/// connect that reads the type.  The chain classifies each once per
/// block instead and hands the types to every step that reads them.
///
/// # Panics
///
/// When `stake_types` is not one type per stake transaction of the
/// block, in every build: a short list would leave transactions out of
/// the filter.  Under debug assertions also when a type is not that
/// transaction's.
pub fn regular_with_types(
    block: &MsgBlock,
    stake_types: &[stake::TxType],
    prev_scripts: &impl PrevScripter,
) -> Result<FilterV2, RegularError> {
    regular_by_input(block, stake_types, &ByOutPoint(prev_scripts))
}

/// [`regular_with_types`] with each previous script found by the place
/// of the input that spends it ([`InputScripts`]) rather than by its
/// outpoint.  The filter is [`regular`]'s, byte for byte, when every
/// script the source gives is the one a [`PrevScripter`] over the same
/// state gives for the input's outpoint, and a script the source does
/// not know is [`regular`]'s missing-script error for that input.
///
/// # Panics
///
/// As [`regular_with_types`] does.
pub fn regular_by_input(
    block: &MsgBlock,
    stake_types: &[stake::TxType],
    input_scripts: &impl InputScripts,
) -> Result<FilterV2, RegularError> {
    assert_eq!(
        stake_types.len(),
        block.stransactions.len(),
        "stake transaction types are not one per stake transaction of the block"
    );
    debug_assert!(
        block
            .stransactions
            .iter()
            .zip(stake_types)
            .all(|(tx, tx_type)| stake::determine_tx_type(tx) == *tx_type),
        "stake transaction types do not match the block's stake transactions"
    );
    build(block, |i, _| stake_types[i], input_scripts)
}

/// The body of [`regular`], [`regular_with_types`] and
/// [`regular_by_input`]: `stake_type` gives the classification of the
/// stake transaction at each index, and `prev_scripts` the script each
/// input spends.
fn build(
    block: &MsgBlock,
    stake_type: impl Fn(usize, &MsgTx) -> stake::TxType,
    prev_scripts: &impl InputScripts,
) -> Result<FilterV2, RegularError> {
    // Room for every entry the block can commit ([`entries_bound`]), so
    // the list is allocated once.  dcrd sizes it by `numEntriesHint`,
    // two entries per regular transaction and one per stake
    // transaction, which most blocks outgrow, and the slice is grown as
    // it fills.  The capacity is not part of the filter.
    let room = entries_bound(block);
    let mut data = Entries(Vec::with_capacity(room));
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
            let Some((script_ver, prev_out_script)) =
                prev_scripts.input_script(TX_TREE_REGULAR, i, tx_in_idx, prev_out)
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
    }

    // Stake tree.
    for (i, tx) in block.stransactions.iter().enumerate() {
        match stake_type(i, tx) {
            stake::TxType::SStx => {
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    let prev_out = &tx_in.previous_out_point;
                    let Some((script_ver, prev_out_script)) =
                        prev_scripts.input_script(TX_TREE_STAKE, i, tx_in_idx, prev_out)
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
                    let Some((script_ver, prev_out_script)) =
                        prev_scripts.input_script(TX_TREE_STAKE, i, tx_in_idx, prev_out)
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
    debug_assert!(
        entries.len() <= room,
        "the filter's entries outgrew the room made for them"
    );

    let key = key(&block.header.merkle_root);
    FilterV2::new(B, M, key, &entries).map_err(RegularError::Gcs)
}

/// An upper bound on the entries a block's filter holds: the number of
/// outputs and inputs of the transactions of both trees.
///
/// Each of them gives the filter at most one entry: an output its script
/// (a ticket's commitment output the payment script it converts to,
/// which joins the entries at the end), an input the script of the
/// output it spends.  Many give none, among them the coinbase's input, a
/// vote's inputs and its first two outputs, and every script the filter
/// excludes.
fn entries_bound(block: &MsgBlock) -> usize {
    block
        .transactions
        .iter()
        .chain(&block.stransactions)
        .map(|tx| tx.tx_in.len().saturating_add(tx.tx_out.len()))
        .fold(0, usize::saturating_add)
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

#[cfg(test)]
mod tests {
    use dcroxide_chainhash::Hash;
    use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

    use super::entries_bound;

    /// A transaction with `ins` inputs and `outs` outputs.
    fn tx(ins: usize, outs: usize) -> MsgTx {
        let input = TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: 0,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in: 0,
            block_height: 0,
            block_index: 0,
            signature_script: Vec::new(),
        };
        let output = TxOut {
            value: 0,
            version: 0,
            pk_script: Vec::new(),
        };
        MsgTx {
            tx_in: vec![input; ins],
            tx_out: vec![output; outs],
            ..MsgTx::default()
        }
    }

    /// The bound counts every input and output of both trees: for a
    /// coinbase of one input and two outputs, a transaction of two and
    /// one, and in the stake tree one of one and three and one of two
    /// and three, fifteen.  A block with no transactions has none.
    #[test]
    fn the_entries_are_bounded_by_every_input_and_output_of_the_block() {
        let (header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
        let mut block = MsgBlock {
            header,
            transactions: vec![tx(1, 2), tx(2, 1)],
            stransactions: vec![tx(1, 3), tx(2, 3)],
        };
        assert_eq!(entries_bound(&block), 15);
        block.transactions.clear();
        block.stransactions.clear();
        assert_eq!(entries_bound(&block), 0);
    }
}
