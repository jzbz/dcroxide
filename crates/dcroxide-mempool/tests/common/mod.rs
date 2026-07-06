// SPDX-License-Identifier: ISC
//! Shared helpers for the pool vector replays: the parsing utilities
//! and the mirror of dcrd's mempool test `fakeChain`.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::{BASE_STANDARD_VERIFY_FLAGS, Policy, PoolChain, PoolError, UNMINED_HEIGHT};
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{
    BlockHeader, MsgTx, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_GRANULARITY,
    SEQUENCE_LOCK_TIME_IS_SECONDS, SEQUENCE_LOCK_TIME_MASK,
};

pub fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

pub fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hash_csv(hashes: &[Hash]) -> String {
    if hashes.is_empty() {
        return "-".into();
    }
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_tx(s: &str) -> MsgTx {
    MsgTx::from_bytes(&unhex(s)).expect("tx").0
}

/// The kind emitted by the dump for a pool error: the mempool kind
/// name or "chain:<kind>" for wrapped chain rule errors.
pub fn error_kind(err: &PoolError) -> String {
    match err {
        PoolError::Rule(rule) => match &rule.err {
            dcroxide_mempool::RuleErrorSource::Mempool(kind) => kind.kind_name().into(),
            dcroxide_mempool::RuleErrorSource::Chain(chain_err) => {
                format!("chain:{}", chain_err.kind.kind_name())
            }
        },
        PoolError::Other(_) => "plain".into(),
    }
}

/// A mirror of dcrd's mempool test `fakeChain`: generated utxos, a
/// faked chain height and best block, and the simplified sequence
/// lock calculation over caller-set utxo median times.
pub struct FakeChain {
    pub next_stake_diff: i64,
    pub utxos: UtxoView,
    pub utxo_times: HashMap<([u8; 32], u32, i8), i64>,
    pub headers: HashMap<[u8; 32], BlockHeader>,
    pub best_hash: Hash,
    pub best_height: i64,
    pub median_time: i64,
    pub tspend_mined: HashSet<[u8; 32]>,
    pub treasury_active: bool,
    pub script_flags: ScriptFlags,
}

impl PoolChain for FakeChain {
    fn next_stake_difficulty(&self) -> Result<i64, String> {
        Ok(self.next_stake_diff)
    }

    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        _tree_valid: bool,
    ) -> Result<UtxoView, String> {
        // All entries are cloned to ensure modifications to the
        // returned view do not affect the fake chain's view.  Entries
        // are added for the outputs of the tx and all of its inputs.
        let mut view = UtxoView::new();
        for tx_out_idx in 0..tx.tx_out.len() as u32 {
            let outpoint = dcroxide_wire::OutPoint {
                hash: *tx_hash,
                index: tx_out_idx,
                tree,
            };
            if let Some(entry) = self.utxos.lookup_entry(&outpoint) {
                view.insert_entry(&outpoint, entry.clone());
            }
        }
        for tx_in in &tx.tx_in {
            if let Some(entry) = self.utxos.lookup_entry(&tx_in.previous_out_point) {
                view.insert_entry(&tx_in.previous_out_point, entry.clone());
            }
        }
        Ok(view)
    }

    fn best_hash(&self) -> Hash {
        self.best_hash
    }

    fn best_height(&self) -> i64 {
        self.best_height
    }

    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.headers
            .get(&hash.0)
            .cloned()
            .ok_or_else(|| format!("unable to find block {hash} in fake chain"))
    }

    fn past_median_time(&self) -> i64 {
        self.median_time
    }

    fn calc_sequence_lock(
        &self,
        tx: &MsgTx,
        _tx_hash: &Hash,
        view: &UtxoView,
    ) -> Result<SequenceLock, PoolError> {
        // A value of -1 for each lock type allows a transaction to be
        // included in a block at any given height or time.
        let mut lock = SequenceLock {
            min_height: -1,
            min_time: -1,
        };

        // Sequence locks do not apply if the tx version is less than
        // 2, or the tx is a coinbase or stakebase.
        let enforce = tx.version >= 2;
        if !enforce
            || dcroxide_standalone::is_coin_base_tx(tx, false)
            || dcroxide_stake::is_ssgen(tx)
        {
            return Ok(lock);
        }

        for tx_in in &tx.tx_in {
            let sequence_num = tx_in.sequence;
            if sequence_num & SEQUENCE_LOCK_TIME_DISABLED != 0 {
                continue;
            }

            let Some(utxo) = view.lookup_entry(&tx_in.previous_out_point) else {
                return Err(PoolError::Other(format!(
                    "output {:?} referenced from transaction does not exist",
                    tx_in.previous_out_point
                )));
            };

            // Inputs in the mempool are calculated from the point of
            // view of the next block.
            let mut input_height = utxo.block_height();
            if input_height == UNMINED_HEIGHT {
                input_height = self.best_height + 1;
            }

            let relative_lock = i64::from(sequence_num & SEQUENCE_LOCK_TIME_MASK);
            if sequence_num & SEQUENCE_LOCK_TIME_IS_SECONDS != 0 {
                // The fake chain allows setting median times directly
                // for fake utxos.
                let key = (
                    tx_in.previous_out_point.hash.0,
                    tx_in.previous_out_point.index,
                    tx_in.previous_out_point.tree,
                );
                let median_time = self.utxo_times.get(&key).copied().unwrap_or(0);
                let relative_secs = relative_lock << SEQUENCE_LOCK_TIME_GRANULARITY;
                let min_time = median_time + relative_secs - 1;
                if min_time > lock.min_time {
                    lock.min_time = min_time;
                }
            } else {
                let min_height = input_height + relative_lock - 1;
                if min_height > lock.min_height {
                    lock.min_height = min_height;
                }
            }
        }

        Ok(lock)
    }

    fn is_treasury_agenda_active(&self) -> Result<bool, String> {
        Ok(self.treasury_active)
    }

    fn is_auto_revocations_agenda_active(&self) -> Result<bool, String> {
        Ok(false)
    }

    fn is_subsidy_split_agenda_active(&self) -> Result<bool, String> {
        Ok(false)
    }

    fn is_subsidy_split_r2_agenda_active(&self) -> Result<bool, String> {
        Ok(false)
    }

    fn tspend_mined_on_ancestor(&self, tspend: &Hash) -> Result<(), String> {
        if self.tspend_mined.contains(&tspend.0) {
            return Err("tspend mined".into());
        }
        Ok(())
    }

    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        Ok(self.script_flags)
    }

    fn now_unix(&self) -> i64 {
        // Frozen; the dump scenarios never rely on wall clock
        // progression (the orphan expiration machinery is
        // time-driven and deliberately untriggered).
        1751800000
    }
}

/// The pool policy dcrd's `newPoolHarness` configures for mainnet.
pub fn harness_policy(coinbase_maturity: u16) -> Policy {
    Policy {
        accept_non_std: false,
        max_orphan_txs: 5,
        max_orphan_tx_size: 1000,
        max_sig_ops_per_tx: dcroxide_blockchain::validate::MAX_SIG_OPS_PER_BLOCK / 5,
        min_relay_tx_fee: 1000,
        allow_old_votes: false,
        max_vote_age: coinbase_maturity,
    }
}

/// Build the fake chain from an `init` row: the median time, height,
/// best block, and the seed coinbase in the utxo set at height 1.
pub fn chain_from_init(f: &[&str]) -> FakeChain {
    assert_eq!(f[0], "init");
    let mut chain = FakeChain {
        next_stake_diff: 0,
        utxos: UtxoView::new(),
        utxo_times: HashMap::new(),
        headers: HashMap::new(),
        best_hash: parse_hash(f[3]),
        best_height: f[2].parse().expect("height"),
        median_time: f[1].parse().expect("median time"),
        tspend_mined: HashSet::new(),
        treasury_active: false,
        script_flags: BASE_STANDARD_VERIFY_FLAGS,
    };
    let (best_header, _) = BlockHeader::from_bytes(&unhex(f[4])).expect("header");
    chain.headers.insert(parse_hash(f[3]).0, best_header);
    let seed_coinbase = parse_tx(f[5]);
    chain
        .utxos
        .add_tx_outs(&seed_coinbase, 1, 0xffffffff, false);
    chain
}
