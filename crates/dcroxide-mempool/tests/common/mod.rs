// SPDX-License-Identifier: ISC
//! Shared helpers for the pool vector replays: the parsing utilities,
//! the mirror of dcrd's mempool test `fakeChain`, and the check of the
//! pool's log lines against the `log` rows.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::sequencelock::SequenceLock;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chainhash::Hash;
use dcroxide_mempool::log::{LogLevel, Logger};
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

/// The pool's log lines against the `log` rows `tools/mempoolvectors`
/// writes after each pool call: the lines dcrd's pool logged for the
/// call through a trace-level logger, as slog abbreviates the level and
/// formats the text, in the order it logged them but for the lines it
/// logs while ranging over a Go map, which are sorted ([`map_sorted`]).
/// The port's pool logs through [`LogRows::logger`], which keeps each
/// line as its row would read, and [`LogRows::check`] compares the two,
/// the port's sorted alike, before the next call runs.
pub struct LogRows {
    logged: Arc<Mutex<Vec<String>>>,
    expected: Vec<String>,
    checked: usize,
}

impl LogRows {
    pub fn new() -> LogRows {
        LogRows {
            logged: Arc::new(Mutex::new(Vec::new())),
            expected: Vec::new(),
            checked: 0,
        }
    }

    /// A logger at trace, the lowest level, keeping every line.
    pub fn logger(&self) -> Logger {
        let logged = Arc::clone(&self.logged);
        Logger::new(
            Arc::new(|_| true),
            Arc::new(move |level, msg: &str| {
                let tag = match level {
                    LogLevel::Trace => "TRC",
                    LogLevel::Debug => "DBG",
                    LogLevel::Info => "INF",
                    LogLevel::Warn => "WRN",
                    LogLevel::Error => "ERR",
                };
                logged
                    .lock()
                    .expect("log lines")
                    .push(format!("log {tag} {msg}"));
            }),
        )
    }

    /// Keep the row for the next check if it is a `log` row.
    pub fn take_row(&mut self, line: &str) -> bool {
        if !line.starts_with("log ") {
            return false;
        }
        self.expected.push(line.to_string());
        true
    }

    /// Compare the `log` rows kept since the last check with the lines
    /// the pool logged since then; `after` is the row of the call that
    /// logged them.
    pub fn check(&mut self, after: &str) {
        let call = after.split(' ').next().unwrap_or_default();
        let logged = map_sorted(
            call,
            std::mem::take(&mut *self.logged.lock().expect("log lines")),
        );
        let expected = std::mem::take(&mut self.expected);
        let shown: String = after.chars().take(120).collect();
        assert_eq!(logged, expected, "the lines logged after {shown}");
        self.checked += expected.len();
    }

    /// How many `log` rows the checks have compared.
    pub fn checked(&self) -> usize {
        self.checked
    }
}

/// The row of the line the pool's walks over its orphans log for each
/// orphan they remove.
const ORPHAN_REMOVAL: &str = "log TRC Removing orphan transaction ";

/// A call's lines with those logged while ranging over a Go map sorted,
/// as `tools/mempoolvectors` writes them, since dcrd's order there
/// changes from run to run and the port's is fixed: the lines of a
/// `prune` or `pruneexp` call, whose walks over the pool, the stage pool
/// and the vote tracker log (`mempool.go:2215`, `:2242`, `:2301`,
/// `:2310`, `:389`), whole, and each run of consecutive `Removing orphan
/// transaction` lines, the one line the walks over the orphans log
/// (`:509`, `:536`, `:556`, `:664`).  The rest keep the order they were
/// logged in.
pub fn map_sorted(call: &str, mut lines: Vec<String>) -> Vec<String> {
    if call == "prune" || call == "pruneexp" {
        lines.sort();
        return lines;
    }
    for run in
        lines.chunk_by_mut(|a, b| a.starts_with(ORPHAN_REMOVAL) && b.starts_with(ORPHAN_REMOVAL))
    {
        run.sort();
    }
    lines
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
/// faked chain height and best block, the headers of the blocks it
/// knows and their winning tickets, and the simplified sequence lock
/// calculation over caller-set utxo median times.
pub struct FakeChain {
    pub next_stake_diff: i64,
    pub utxos: UtxoView,
    pub utxo_times: HashMap<([u8; 32], u32, i8), i64>,
    /// The headers of the blocks the chain knows (dcrd's `blocks`, which
    /// `AddMockBlock` fills).
    pub headers: HashMap<[u8; 32], BlockHeader>,
    /// The winning tickets of each block, in the order they were added
    /// (dcrd's `winningTickets`, which `AddWinningTicket` fills).
    pub winners: HashMap<[u8; 32], Vec<Hash>>,
    pub best_hash: Hash,
    pub best_height: i64,
    pub median_time: i64,
    pub tspend_mined: HashSet<[u8; 32]>,
    pub treasury_active: bool,
    /// dcrd's harness `autoRevocationsActive`, `subsidySplitActive` and
    /// `subsidySplitR2Active` toggles, which answer the pool's agenda
    /// queries (`newPoolHarness`, `mempool_test.go:901-909`).
    pub auto_revocations_active: bool,
    pub subsidy_split_active: bool,
    pub subsidy_split_r2_active: bool,
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

    /// dcrd's fake answers a block it was never given with
    /// `blockchain.ErrUnknownBlock`, as the real chain does.
    fn header_by_hash(&self, hash: &Hash) -> Option<BlockHeader> {
        self.headers.get(&hash.0).cloned()
    }

    /// dcrd's fake answers a block it has no winners for with none, and
    /// no error.
    fn winning_tickets_by_hash(&self, hash: &Hash) -> Result<Vec<Hash>, String> {
        Ok(self.winners.get(&hash.0).cloned().unwrap_or_default())
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
        Ok(self.auto_revocations_active)
    }

    fn is_subsidy_split_agenda_active(&self) -> Result<bool, String> {
        Ok(self.subsidy_split_active)
    }

    fn is_subsidy_split_r2_agenda_active(&self) -> Result<bool, String> {
        Ok(self.subsidy_split_r2_active)
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
        // progression.
        1751800000
    }

    fn now_mono_nanos(&self) -> i64 {
        // Frozen too: the orphan expiration machinery runs on this
        // clock and is deliberately untriggered by the dump scenarios.
        0
    }

    fn random_u64(&self) -> u64 {
        // Fixed, like the clock above: the replayed dcrd scenarios
        // must not depend on a draw.  A constant is safe here because
        // both consumers reduce by modulo and neither rejects, so a
        // constant source always terminates; see
        // `PoolChain::random_u64`'s contract, which a rejecting
        // reduction would break.  Two paths would consume a draw --
        // random orphan eviction and the rival-orphan trial order --
        // and no scenario in the corpus reaches either, which was
        // checked by making this panic and replaying them all.
        0
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
        enable_ancestor_tracking: true,
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
        winners: HashMap::new(),
        best_hash: parse_hash(f[3]),
        best_height: f[2].parse().expect("height"),
        median_time: f[1].parse().expect("median time"),
        tspend_mined: HashSet::new(),
        treasury_active: false,
        auto_revocations_active: false,
        subsidy_split_active: false,
        subsidy_split_r2_active: false,
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

/// Apply a row that changes what the fake chain knows about blocks:
/// `block <hash> <header>` (dcrd's `AddMockBlock`), `besthash <hash>`
/// (`SetBestHash`, which adds no block) and `winner <block> <ticket>`
/// (`AddWinningTicket`, which lists a ticket once).  Returns whether the
/// row was one of them.
pub fn apply_block_row(chain: &mut FakeChain, f: &[&str]) -> bool {
    match f[0] {
        "block" => {
            let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
            chain.headers.insert(parse_hash(f[1]).0, header);
        }
        "besthash" => chain.best_hash = parse_hash(f[1]),
        "winner" => {
            let winners = chain.winners.entry(parse_hash(f[1]).0).or_default();
            let ticket = parse_hash(f[2]);
            if !winners.contains(&ticket) {
                winners.push(ticket);
            }
        }
        _ => return false,
    }
    true
}
