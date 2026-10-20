// SPDX-License-Identifier: ISC
//! The previous output scripts of a block's inputs, read from the spend
//! journal the block's connect has just built, for the version 2 filter
//! the chain builds as it attaches the block, whether it validates the
//! block in full (the connect checks) or adds it without (a bulk import's
//! blocks and the ancestors of the assumed valid block).
//!
//! dcrd's `blockcf2.Regular` looks each input's previous script up in the
//! view by its outpoint (`PrevScripter`, over the view the block's connect
//! has just connected it to).  The connect has by then spent every one of
//! those outputs, and in doing so appended each to the block's spend
//! journal, with its script version and script, in the order it spent them:
//! the stake tree's transactions in order, then the regular tree's, each
//! transaction's inputs in order.  The journal holds the entry the view
//! held when the input spent it, so the script it holds is the one the view
//! lookup finds after the connect: the one output the connect adds again
//! after a spend, the grandfathered same-block stake spend's, comes back
//! with the script it was spent with.  Reading the journal by the input's
//! place costs no search.  Under debug assertions the filter is built from
//! the view as well and the two compared
//! (`crate::validate::connected_block_filter`).
//!
//! A transaction's entries are found by where its connect began in the
//! journal, which the connect records as it goes (`JournalStarts`), so
//! the mapping is the connect's own and not a copy of its rules.  Only a
//! transaction whose connect journaled one entry for each of its inputs
//! is read from the journal: the regular tree's non-coinbase
//! transactions, ticket purchases and treasury adds, which are the only
//! transactions whose inputs the filter commits to.  For any input it
//! cannot place so, the source asks the view, as dcrd does, so a missing
//! script is the filter's missing-script error for that input exactly as
//! before.

use alloc::vec::Vec;

use dcroxide_gcs::blockcf2::{InputScripts, PrevScripter};
use dcroxide_wire::{MsgBlock, OutPoint, TX_TREE_STAKE};

use crate::chainio::SpentTxOut;

#[cfg(test)]
std::thread_local! {
    /// How many previous scripts this thread read from a spend journal
    /// (`JournalScripts`), and how many it had to ask the view for.  They
    /// exist in this crate's unit-test builds only, where the tests read
    /// them to tell that the filters the chain builds as it attaches
    /// blocks read the journal.
    pub(crate) static JOURNAL_READS: core::cell::Cell<(u64, u64)> =
        const { core::cell::Cell::new((0, 0)) };
}

/// Where each transaction of one tree of a block began in the spend
/// journal while the tree was connected: entry `i` is the journal's
/// length when transaction `i` was connected, and the last entry its
/// length once the tree was, so transaction `i`'s entries are
/// `journal[starts[i]..starts[i + 1]]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct JournalStarts(Vec<usize>);

impl JournalStarts {
    /// Room for a tree of `txs` transactions.
    pub(crate) fn with_capacity(txs: usize) -> JournalStarts {
        JournalStarts(Vec::with_capacity(txs.saturating_add(1)))
    }

    /// Record the journal's length, `len`, before the next transaction
    /// is connected, or after the last.
    pub(crate) fn push(&mut self, len: usize) {
        self.0.push(len);
    }

    /// The journal entries of transaction `tx_idx` of the tree, by where
    /// its connect began and the next one's did.
    fn range(&self, tx_idx: usize) -> Option<core::ops::Range<usize>> {
        let start = *self.0.get(tx_idx)?;
        let end = *self.0.get(tx_idx.checked_add(1)?)?;
        (start <= end).then_some(start..end)
    }
}

/// Where each transaction of both trees of a block began in the spend
/// journal while the block was connected: one [`JournalStarts`] per tree,
/// recorded by the connect checks (`check_transactions_and_connect_typed`)
/// for a block validated in full and by the view's connect of each tree
/// (`UtxoView::connect_stake_transactions_typed` and its regular twin) for
/// one added without.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BlockJournalStarts {
    /// Where each stake transaction's entries begin.
    pub(crate) stake: JournalStarts,
    /// Where each regular transaction's entries begin.
    pub(crate) regular: JournalStarts,
}

impl BlockJournalStarts {
    /// Room for the two trees of `block`.
    pub(crate) fn for_block(block: &MsgBlock) -> BlockJournalStarts {
        BlockJournalStarts {
            stake: JournalStarts::with_capacity(block.stransactions.len()),
            regular: JournalStarts::with_capacity(block.transactions.len()),
        }
    }
}

/// The previous output scripts of a block's inputs from the spend journal
/// its connect built, with the view the block was connected to for any
/// input it cannot place ([`InputScripts`]).
pub(crate) struct JournalScripts<'a, P: ?Sized> {
    block: &'a MsgBlock,
    /// The spend journal the connect appended to.
    journal: &'a [SpentTxOut],
    /// Where each stake transaction's entries begin.
    stake: &'a JournalStarts,
    /// Where each regular transaction's entries begin.
    regular: &'a JournalStarts,
    /// The lookup by outpoint for an input the journal cannot place.
    fallback: &'a P,
}

impl<'a, P: PrevScripter + ?Sized> JournalScripts<'a, P> {
    /// The scripts of `block`'s inputs from `journal`, which the block's
    /// connect appended to while it recorded `stake` and `regular`, and
    /// from `fallback` for an input the journal cannot place.
    pub(crate) fn new(
        block: &'a MsgBlock,
        journal: &'a [SpentTxOut],
        stake: &'a JournalStarts,
        regular: &'a JournalStarts,
        fallback: &'a P,
    ) -> JournalScripts<'a, P> {
        JournalScripts {
            block,
            journal,
            stake,
            regular,
            fallback,
        }
    }

    /// The journal entry of the input, when its transaction's connect
    /// journaled one entry for each of its inputs.
    fn entry(&self, tree: i8, tx_idx: usize, tx_in_idx: usize) -> Option<&'a SpentTxOut> {
        let (txs, starts) = if tree == TX_TREE_STAKE {
            (&self.block.stransactions, self.stake)
        } else {
            (&self.block.transactions, self.regular)
        };
        let tx = txs.get(tx_idx)?;
        let entries = starts.range(tx_idx)?;
        if entries.len() != tx.tx_in.len() || tx_in_idx >= entries.len() {
            return None;
        }
        self.journal.get(entries.start.checked_add(tx_in_idx)?)
    }
}

impl<P: PrevScripter + ?Sized> InputScripts for JournalScripts<'_, P> {
    fn input_script(
        &self,
        tree: i8,
        tx_idx: usize,
        tx_in_idx: usize,
        prev_out: &OutPoint,
    ) -> Option<(u16, &[u8])> {
        let entry = self.entry(tree, tx_idx, tx_in_idx);
        #[cfg(test)]
        JOURNAL_READS.with(|reads| {
            let (journal, view) = reads.get();
            reads.set(if entry.is_some() {
                (journal.wrapping_add(1), view)
            } else {
                (journal, view.wrapping_add(1))
            });
        });
        match entry {
            Some(entry) => Some((entry.script_version, entry.pk_script.as_slice())),
            None => self.fallback.prev_script(prev_out),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use alloc::vec;

    use dcroxide_chainhash::Hash;
    use dcroxide_gcs::blockcf2::{InputScripts, PrevScripter};
    use dcroxide_wire::{
        BlockHeader, MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE, TxIn,
    };

    use super::{JournalScripts, JournalStarts};
    use crate::chainio::SpentTxOut;

    /// A transaction spending `ins` outpoints numbered from `first`.
    fn tx(first: u32, ins: u32) -> MsgTx {
        MsgTx {
            tx_in: (first..first + ins)
                .map(|index| TxIn {
                    previous_out_point: OutPoint {
                        hash: Hash([7; 32]),
                        index,
                        tree: 0,
                    },
                    ..TxIn::default()
                })
                .collect(),
            ..MsgTx::default()
        }
    }

    /// A journal entry whose script is the byte `b`.
    fn entry(b: u8) -> SpentTxOut {
        SpentTxOut {
            amount: 0,
            pk_script: crate::PkScript::from(&[b][..]),
            ticket_min_outs: None,
            block_height: 0,
            block_index: 0,
            script_version: u16::from(b),
            packed_flags: 0,
        }
    }

    /// The view's answer: the script `0xf0 + index`, version 0.
    struct View;

    impl PrevScripter for View {
        fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])> {
            const SCRIPTS: [u8; 16] = [
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
                0xfe, 0xff,
            ];
            let i = out.index as usize;
            SCRIPTS.get(i..=i).map(|script| (0, script))
        }
    }

    fn starts(lens: &[usize]) -> JournalStarts {
        let mut starts = JournalStarts::with_capacity(lens.len());
        for &len in lens {
            starts.push(len);
        }
        starts
    }

    /// Each input of a transaction whose connect journaled one entry per
    /// input reads its own entry, by where the transaction began; every
    /// other input asks the view: a vote, which journals one entry for
    /// its two inputs, a coinbase, which journals none, a transaction
    /// past the recorded ones, and an input past its transaction's.
    #[test]
    fn an_input_reads_its_own_entry_and_any_other_asks_the_view() {
        let (header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
        // Stake: a vote of two inputs, a ticket of two; regular: a
        // coinbase of one, a transaction of two.
        let block = MsgBlock {
            header,
            stransactions: vec![tx(0, 2), tx(2, 2)],
            transactions: vec![tx(4, 1), tx(5, 2)],
        };
        let journal = vec![entry(1), entry(2), entry(3), entry(4), entry(5)];
        let stake = starts(&[0, 1, 3]);
        let regular = starts(&[3, 3, 5]);
        let scripts = JournalScripts::new(&block, &journal, &stake, &regular, &View);
        let at = |tree: i8, tx_idx: usize, tx_in_idx: usize| {
            let txs = if tree == TX_TREE_STAKE {
                &block.stransactions
            } else {
                &block.transactions
            };
            let prev_out = txs
                .get(tx_idx)
                .and_then(|tx| tx.tx_in.get(tx_in_idx))
                .map_or(
                    OutPoint {
                        hash: Hash::ZERO,
                        index: 15,
                        tree: 0,
                    },
                    |tx_in| tx_in.previous_out_point,
                );
            scripts
                .input_script(tree, tx_idx, tx_in_idx, &prev_out)
                .map(|(version, script)| (version, script.to_vec()))
        };
        let read = super::JOURNAL_READS.get();
        // The ticket's inputs: entries 1 and 2.
        assert_eq!(at(TX_TREE_STAKE, 1, 0), Some((2, vec![2])));
        assert_eq!(at(TX_TREE_STAKE, 1, 1), Some((3, vec![3])));
        // The regular transaction's: entries 3 and 4.
        assert_eq!(at(TX_TREE_REGULAR, 1, 0), Some((4, vec![4])));
        assert_eq!(at(TX_TREE_REGULAR, 1, 1), Some((5, vec![5])));
        // The vote's and the coinbase's inputs, the view's.
        assert_eq!(at(TX_TREE_STAKE, 0, 1), Some((0, vec![0xf1])));
        assert_eq!(at(TX_TREE_REGULAR, 0, 0), Some((0, vec![0xf4])));
        // Past the recorded transactions, and past the inputs.
        assert_eq!(at(TX_TREE_REGULAR, 2, 0), Some((0, vec![0xff])));
        assert_eq!(at(TX_TREE_STAKE, 1, 2), Some((0, vec![0xff])));
        let (journal_reads, view_reads) = super::JOURNAL_READS.get();
        assert_eq!(
            (journal_reads - read.0, view_reads - read.1),
            (4, 4),
            "four from the journal and four from the view"
        );

        // A journal shorter than the starts say reads nothing past its end.
        let short = &journal[..4];
        let scripts = JournalScripts::new(&block, short, &stake, &regular, &View);
        let prev_out = block.transactions[1].tx_in[1].previous_out_point;
        assert_eq!(
            scripts.input_script(TX_TREE_REGULAR, 1, 1, &prev_out),
            Some((0, &[0xf6][..]))
        );
    }
}
