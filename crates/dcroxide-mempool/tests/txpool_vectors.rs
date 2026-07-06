// SPDX-License-Identifier: ISC
//! Replay of dcrd's transaction pool behavior generated with dcrd's
//! own mempool test harness (`data/txpool_vectors.txt`): the full
//! acceptance gauntlet driven through `ProcessTransaction`,
//! `MaybeAcceptTransaction(s)`, and `MaybeAcceptDependents` over a
//! mirrored fake chain — chained acceptance, orphan cascades and
//! policy, duplicates and double spends, the already-exists check,
//! fee policy in both directions, block- and time-based sequence
//! locks, expiry with pruning, ticket staging with unstaging on
//! parent confirmation, stake difficulty gates and pruning, batch
//! acceptance through the transient pool, and double spend removal —
//! comparing every verdict, accepted-transaction list, and the full
//! pool/orphan/stage/tspend state after every operation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};

use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::{
    BASE_STANDARD_VERIFY_FLAGS, Policy, PoolChain, PoolError, TxPool, UNMINED_HEIGHT,
};
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{
    BlockHeader, MsgTx, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_GRANULARITY,
    SEQUENCE_LOCK_TIME_IS_SECONDS, SEQUENCE_LOCK_TIME_MASK, TX_TREE_REGULAR,
};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_csv(hashes: &[Hash]) -> String {
    if hashes.is_empty() {
        return "-".into();
    }
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_tx(s: &str) -> MsgTx {
    MsgTx::from_bytes(&unhex(s)).expect("tx").0
}

/// The kind emitted by the dump for a pool error: the mempool kind
/// name or "chain:<kind>" for wrapped chain rule errors.
fn error_kind(err: &PoolError) -> String {
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
struct FakeChain {
    next_stake_diff: i64,
    utxos: UtxoView,
    utxo_times: HashMap<([u8; 32], u32, i8), i64>,
    headers: HashMap<[u8; 32], BlockHeader>,
    best_hash: Hash,
    best_height: i64,
    median_time: i64,
    tspend_mined: HashSet<[u8; 32]>,
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
        Ok(false)
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
        Ok(BASE_STANDARD_VERIFY_FLAGS)
    }

    fn now_unix(&self) -> i64 {
        // Frozen; the dump scenarios never rely on wall clock
        // progression (the orphan expiration machinery is
        // time-driven and deliberately untriggered).
        1751800000
    }
}

#[test]
fn txpool_vectors() {
    let params = mainnet_params();
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();

    // The init row builds the harness: the fake chain state and the
    // pool policy dcrd's newPoolHarness configures.
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    assert_eq!(init[0], "init");
    let mut chain = FakeChain {
        next_stake_diff: 0,
        utxos: UtxoView::new(),
        utxo_times: HashMap::new(),
        headers: HashMap::new(),
        best_hash: parse_hash(init[3]),
        best_height: init[2].parse().expect("height"),
        median_time: init[1].parse().expect("median time"),
        tspend_mined: HashSet::new(),
    };
    let (best_header, _) = BlockHeader::from_bytes(&unhex(init[4])).expect("header");
    chain.headers.insert(parse_hash(init[3]).0, best_header);
    let seed_coinbase = parse_tx(init[5]);
    chain
        .utxos
        .add_tx_outs(&seed_coinbase, 1, 0xffffffff, false);
    let policy = Policy {
        accept_non_std: false,
        max_orphan_txs: 5,
        max_orphan_tx_size: 1000,
        max_sig_ops_per_tx: dcroxide_blockchain::validate::MAX_SIG_OPS_PER_BLOCK / 5,
        min_relay_tx_fee: 1000,
        allow_old_votes: false,
        max_vote_age: params.coinbase_maturity,
    };
    let mut pool = TxPool::new(chain, policy, &params);
    let mut counts = [0usize; 8];

    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "utxo" => {
                // utxo <txhex> <height> <blockindex>
                let tx = parse_tx(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let block_index: u32 = f[3].parse().expect("block index");
                pool.chain
                    .utxos
                    .add_tx_outs(&tx, height, block_index, false);
            }
            "utxotime" => {
                // utxotime <hash> <idx> <unix>
                let key = (
                    parse_hash(f[1]).0,
                    f[2].parse().expect("idx"),
                    TX_TREE_REGULAR,
                );
                pool.chain
                    .utxo_times
                    .insert(key, f[3].parse().expect("time"));
            }
            "setsdiff" => {
                pool.chain.next_stake_diff = f[1].parse().expect("sdiff");
            }
            "pt" => {
                // pt <txhex> <alloworphan> <allowhighfees> <tag>
                //    (ok <acceptedcsv> | <kind> -)
                let tx = parse_tx(f[1]);
                let allow_orphan = f[2] == "true";
                let allow_high_fees = f[3] == "true";
                let tag: u64 = f[4].parse().expect("tag");
                match pool.process_transaction(&tx, allow_orphan, allow_high_fees, tag) {
                    Ok(accepted) => {
                        assert_eq!("ok", f[5], "{line}: unexpected acceptance");
                        assert_eq!(hash_csv(&accepted), f[6], "{line}: accepted list");
                    }
                    Err(err) => {
                        assert_eq!(error_kind(&err), f[5], "{line}: kind");
                    }
                }
                counts[0] += 1;
            }
            "mat" => {
                // mat <txhex> <isnew> (ok <missingcsv|-> | <kind> -)
                let tx = parse_tx(f[1]);
                let is_new = f[2] == "true";
                match pool.maybe_accept_transaction_pub(&tx, is_new) {
                    Ok(missing) => {
                        assert_eq!("ok", f[3], "{line}: unexpected acceptance");
                        let csv = if missing.is_empty() {
                            "-".to_string()
                        } else {
                            missing
                                .iter()
                                .map(|op| {
                                    format!("{}:{}:{}", raw_hex(&op.hash.0), op.index, op.tree)
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        assert_eq!(csv, f[4], "{line}: missing parents");
                    }
                    Err(err) => {
                        assert_eq!(error_kind(&err), f[3], "{line}: kind");
                    }
                }
                counts[1] += 1;
            }
            "mats" => {
                // mats <txhexcsv> <verdict>
                let txns: Vec<MsgTx> = f[1].split(',').map(parse_tx).collect();
                let errors = pool.maybe_accept_transactions(&txns);
                let verdict = match errors.len() {
                    0 => "ok".to_string(),
                    1 => error_kind(&errors[0]),
                    _ => "multi".to_string(),
                };
                assert_eq!(verdict, f[2], "{line}");
                counts[2] += 1;
            }
            "mad" => {
                // mad <txhex> <treasury> <acceptedcsv|->
                let tx = parse_tx(f[1]);
                let treasury = f[2] == "true";
                let accepted = pool.maybe_accept_dependents(&tx, &tx.tx_hash(), treasury);
                assert_eq!(hash_csv(&accepted), f[3], "{line}");
                counts[3] += 1;
            }
            "rmtx" => {
                let tx = parse_tx(f[1]);
                pool.remove_transaction(&tx, &tx.tx_hash(), f[2] == "true");
            }
            "rmds" => {
                let tx = parse_tx(f[1]);
                pool.remove_double_spends(&tx, &tx.tx_hash());
            }
            "rmorph" => {
                let tx = parse_tx(f[1]);
                pool.remove_orphan_pub(&tx.tx_hash());
            }
            "rmtag" => {
                // rmtag <tag> <count>
                let evicted = pool.remove_orphans_by_tag(f[1].parse().expect("tag"));
                assert_eq!(evicted.to_string(), f[2], "{line}");
                counts[4] += 1;
            }
            "prune" => {
                // prune <sdiff> <height>
                pool.prune_stake_tx(f[1].parse().expect("sdiff"), f[2].parse().expect("height"));
            }
            "pruneexp" => {
                pool.prune_expired_tx(f[1].parse().expect("height"));
            }
            "state" => {
                // state <count> <pool> <orphans> <staged> <tspends>
                assert_eq!(pool.count().to_string(), f[1], "{line}: count");
                assert_eq!(hash_csv(&pool.tx_hashes()), f[2], "{line}: pool");
                assert_eq!(hash_csv(&pool.orphan_hashes()), f[3], "{line}: orphans");
                assert_eq!(hash_csv(&pool.staged_hashes()), f[4], "{line}: staged");
                assert_eq!(hash_csv(&pool.tspend_hashes()), f[5], "{line}: tspends");
                counts[5] += 1;
            }
            "have" => {
                let have = pool.have_transaction(&parse_hash(f[1]));
                assert_eq!(have.to_string(), f[2], "{line}");
                counts[6] += 1;
            }
            "spent" => {
                // spent <hash> <idx> <tree> <bool>
                let outpoint = dcroxide_wire::OutPoint {
                    hash: parse_hash(f[1]),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
                };
                assert_eq!(pool.is_spent(&outpoint).to_string(), f[4], "{line}");
                counts[7] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [29, 1, 2, 1, 1, 40, 1, 1], "row counts");
}
