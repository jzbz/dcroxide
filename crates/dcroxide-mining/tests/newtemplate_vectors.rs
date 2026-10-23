// SPDX-License-Identifier: ISC
//! Replay of dcrd's block template assembly generated with dcrd's
//! own mining harness (`data/newtemplate_vectors.txt`): full
//! templates compared byte for byte over a mirrored fake chain and
//! thin transaction source — the fee redistribution through the
//! coinbase, the free fee rejection, both payment address variants,
//! the error injection paths, a stake validation height template
//! with votes, the vote bits tally, a fresh ticket purchase, the
//! participation-scaled fees, and the too-few-voters parent recycle.
//! dcrd's wall clock timestamp and random extra nonces are recovered
//! from its own emitted templates.
//!
//! The `autorev*` scenarios (M2-p#1) are dcrd's
//! `TestNewBlockTemplateAutoRevocations` and
//! `TestNewBlockTemplateAutoRevocationsVotesOnly`
//! (`internal/mining/mining_test.go:194`, `:401`) run through the same
//! harness with the automatic ticket revocations agenda active, as it
//! is on mainnet: revocations built for the winning tickets whose votes
//! are missing or fail validation and for the expiring tickets, the
//! source's revocations of previously missed tickets mined, the one of
//! an ineligible ticket skipped, and the requeue after a votes-only
//! queue drains.  The votes-only template is also built under each
//! subsidy split agenda (DCP0010, DCP0012), whose votes and coinbase
//! pay the matching split.  The harness's own pay address stands in
//! for the tests' fixed one.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::{
    check_transaction_inputs, count_total_sig_ops, is_finalized_transaction,
    validate_transaction_scripts,
};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_mining::log::{LogLevel, Logger};
use dcroxide_mining::{
    BlkTmplGenerator, ExtraNonces, MiningPolicy, TemplateBest, TemplateChain, TemplateTxSource,
    TxDesc, TxMiningView, VoteDesc,
};
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A mirror of the mining harness `fakeChain`.
struct FakeChain {
    best: TemplateBest,
    blocks: HashMap<[u8; 32], MsgBlock>,
    utxos: UtxoView,
    difficulty: u32,
    stake_version: u32,
    max_expenditure: i64,
    tip_generation: Vec<Hash>,
    hdr_cmt_active: bool,
    treasury_active: bool,
    auto_rev_active: bool,
    ss_active: bool,
    ssr2_active: bool,
    // Error injections.
    difficulty_err: bool,
    stake_version_err: bool,
    connect_err: bool,
    treasury_agenda_err: bool,
    fetch_view_err: bool,
    // The utxo view fetches that succeed before the rest fail, all of
    // them when `None`.
    fetch_view_budget: Cell<Option<u32>>,
    reorg_err: bool,
    tspend_votes_err: bool,
    ticket_exhaustion_err: bool,
    coinbase_sig_ops_err: bool,
    // The lines the generator logged through the chain's logger (dcrd's
    // MINR logger), at or above the level the capture is set to.
    log: Capture,
    // The wall clock recovered from dcrd's emitted template.
    adjusted_time: i64,
    subsidy_cache: RefCell<SubsidyCache<&'static dcroxide_chaincfg::Params>>,
    script_flags: ScriptFlags,
}

// The harness runs on the mainnet params with its PoW limit lowered;
// the subsidy math only reads the subsidy fields, so a leaked static
// copy of the params keeps the cache lifetime simple in this test.
fn leaked_params() -> &'static dcroxide_chaincfg::Params {
    Box::leak(Box::new(mainnet_params()))
}

impl TemplateChain for FakeChain {
    fn best_snapshot(&self) -> TemplateBest {
        self.best.clone()
    }
    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String> {
        self.blocks
            .get(&hash.0)
            .cloned()
            .ok_or_else(|| format!("unable to find block {hash} in fake chain"))
    }
    fn calc_next_required_difficulty(&self, _h: &Hash, _ts: i64) -> Result<u32, String> {
        if self.difficulty_err {
            return Err("diff err".into());
        }
        Ok(self.difficulty)
    }
    fn calc_stake_version_by_hash(&self, _h: &Hash) -> Result<u32, String> {
        if self.stake_version_err {
            return Err("sv err".into());
        }
        Ok(self.stake_version)
    }
    fn check_connect_block_template(&mut self, _b: &MsgBlock) -> Result<(), String> {
        if self.connect_err {
            return Err("cbt err".into());
        }
        Ok(())
    }
    fn check_ticket_exhaustion(&self, _h: &Hash, _p: u8) -> Result<(), String> {
        if self.ticket_exhaustion_err {
            return Err("exhaustion err".into());
        }
        Ok(())
    }
    fn check_transaction_inputs(
        &mut self,
        tx: &MsgTx,
        tx_height: i64,
        view: &UtxoView,
        check_fraud_proof: bool,
        prev_header: &BlockHeader,
        is_treasury_enabled: bool,
        is_auto_revocations_enabled: bool,
        subsidy_split_variant: SubsidySplitVariant,
    ) -> Result<i64, String> {
        let params = leaked_params();
        check_transaction_inputs(
            &mut self.subsidy_cache.borrow_mut(),
            tx,
            tx_height,
            |op| view.lookup_entry(op),
            check_fraud_proof,
            params,
            prev_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
            subsidy_split_variant,
        )
        .map_err(|e| format!("{e:?}"))
    }
    fn check_tspend_has_votes(&self, _h: &Hash, _tx: &MsgTx) -> Result<(), String> {
        if self.tspend_votes_err {
            return Err("votes err".into());
        }
        Ok(())
    }
    fn count_total_sig_ops(
        &self,
        tx: &MsgTx,
        is_cb: bool,
        is_vote: bool,
        view: &UtxoView,
        treasury: bool,
    ) -> Result<u32, String> {
        if is_cb && self.coinbase_sig_ops_err {
            return Err("sigops err".into());
        }
        count_total_sig_ops(tx, is_cb, is_vote, |op| view.lookup_entry(op), treasury)
            .map_err(|e| e.description)
    }
    fn fetch_utxo_entry(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, String> {
        Ok(self.utxos.lookup_entry(outpoint).cloned())
    }
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        tx_hash: &Hash,
        tree: i8,
        _include_regular: bool,
    ) -> Result<UtxoView, String> {
        if self.fetch_view_err || self.fetch_view_budget.get() == Some(0) {
            return Err("view err".into());
        }
        if let Some(left) = self.fetch_view_budget.get() {
            self.fetch_view_budget.set(Some(left - 1));
        }
        let mut view = UtxoView::new();
        for idx in 0..tx.tx_out.len() as u32 {
            let op = OutPoint {
                hash: *tx_hash,
                index: idx,
                tree,
            };
            if let Some(entry) = self.utxos.lookup_entry(&op) {
                view.insert_entry(&op, entry.clone());
            }
        }
        for tx_in in &tx.tx_in {
            if let Some(entry) = self.utxos.lookup_entry(&tx_in.previous_out_point) {
                view.insert_entry(&tx_in.previous_out_point, entry.clone());
            }
        }
        Ok(view)
    }
    fn fetch_utxo_view_parent_template(&self, _b: &MsgBlock) -> Result<UtxoView, String> {
        Ok(UtxoView::new())
    }
    fn force_head_reorganization(&mut self, _f: Hash, _n: Hash) -> Result<(), String> {
        if self.reorg_err {
            return Err("reorg err".into());
        }
        Ok(())
    }
    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.blocks
            .get(&hash.0)
            .map(|b| b.header)
            .ok_or_else(|| format!("unable to find block {hash} in fake chain"))
    }
    fn is_finalized_transaction(&self, tx: &MsgTx, height: i64, time_unix: i64) -> bool {
        is_finalized_transaction(tx, height, time_unix)
    }
    fn is_header_commitments_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(self.hdr_cmt_active)
    }
    fn is_treasury_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        if self.treasury_agenda_err {
            return Err("agenda err".into());
        }
        Ok(self.treasury_active)
    }
    fn is_auto_revocations_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(self.auto_rev_active)
    }
    fn is_subsidy_split_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(self.ss_active)
    }
    fn is_subsidy_split_r2_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(self.ssr2_active)
    }
    fn max_treasury_expenditure(&self, _h: &Hash) -> Result<i64, String> {
        Ok(self.max_expenditure)
    }
    fn tip_generation(&self) -> Vec<Hash> {
        self.tip_generation.clone()
    }
    fn validate_transaction_scripts(
        &self,
        tx: &MsgTx,
        view: &UtxoView,
        flags: ScriptFlags,
        auto_rev: bool,
    ) -> Result<(), String> {
        validate_transaction_scripts(tx, |op| view.lookup_entry(op), flags, None, auto_rev)
            .map_err(|e| format!("{e:?}"))
    }
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        Ok(self.script_flags)
    }
    fn adjusted_time_unix(&self) -> i64 {
        self.adjusted_time
    }
    fn logger(&self) -> Option<&Logger> {
        Some(&self.log.logger)
    }
}

/// A logger that keeps the lines at or above a level it can be set to,
/// standing in for the daemon's `MINR` logger and its `--debuglevel`.
struct Capture {
    logger: Logger,
    level: Arc<Mutex<LogLevel>>,
    lines: Arc<Mutex<Vec<(LogLevel, String)>>>,
}

impl Capture {
    /// A capture at warn, slog's level for nothing below a warning, so
    /// the replay formats no debug or trace line.
    fn new() -> Capture {
        let level = Arc::new(Mutex::new(LogLevel::Warn));
        let lines = Arc::new(Mutex::new(Vec::new()));
        let gate_level = Arc::clone(&level);
        let sink = Arc::clone(&lines);
        let logger = Logger::new(
            Arc::new(move |level| level >= *gate_level.lock().expect("level")),
            Arc::new(move |level, msg: &str| {
                sink.lock().expect("lines").push((level, msg.to_string()));
            }),
        );
        Capture {
            logger,
            level,
            lines,
        }
    }

    fn set_level(&self, level: LogLevel) {
        *self.level.lock().expect("level") = level;
    }

    /// The lines kept since the last take, emptying the capture.
    fn take(&self) -> Vec<(LogLevel, String)> {
        core::mem::take(&mut *self.lines.lock().expect("lines"))
    }

    /// The texts kept at the level since the last take, emptying the
    /// capture.
    fn take_at(&self, level: LogLevel) -> Vec<String> {
        self.take()
            .into_iter()
            .filter(|(at, _)| *at == level)
            .map(|(_, msg)| msg)
            .collect()
    }
}

/// A thin source mirroring the harness `fakeTxSource` surface the
/// generator consumes.
#[derive(Default)]
struct ThinSource {
    pool: HashMap<[u8; 32], Arc<TxDesc>>,
    outpoints: HashMap<([u8; 32], u32, i8), Arc<TxDesc>>,
    view: Option<TxMiningView>,
    votes: HashMap<[u8; 32], Vec<VoteDesc>>,
}

impl ThinSource {
    fn new() -> ThinSource {
        ThinSource {
            view: Some(TxMiningView::new(true)),
            ..ThinSource::default()
        }
    }

    fn add(&mut self, desc: Arc<TxDesc>) {
        self.pool.insert(desc.tx_hash.0, desc.clone());
        let pool = &self.pool;
        let outpoints = &self.outpoints;
        self.view.as_mut().expect("view").add_transaction(
            &desc,
            &|hash| pool.get(&hash.0).cloned(),
            &|tx, f| {
                for i in 0..tx.tx.tx_out.len() as u32 {
                    if let Some(redeemer) = outpoints.get(&(tx.tx_hash.0, i, tx.tree)) {
                        f(redeemer.clone());
                    }
                }
            },
        );
        for tx_in in &desc.tx.tx_in {
            let op = &tx_in.previous_out_point;
            self.outpoints
                .insert((op.hash.0, op.index, op.tree), desc.clone());
        }
        if desc.tx_type == TxType::SSGen {
            // Mirror the harness insertVote.
            let (block_hash, _) = dcroxide_stake::ssgen_block_voted_on(&desc.tx);
            let votes = self.votes.entry(block_hash.0).or_default();
            let ticket_hash = desc.tx.tx_in[1].previous_out_point.hash;
            if !votes.iter().any(|v| v.ticket_hash == ticket_hash) {
                let vote_bits = dcroxide_stake::ssgen_vote_bits(&desc.tx);
                votes.push(VoteDesc {
                    vote_hash: desc.tx_hash,
                    ticket_hash,
                    approves_parent: vote_bits & 0x0001 != 0,
                });
            }
        }
    }
}

impl TemplateTxSource for ThinSource {
    fn mining_view(&self) -> TxMiningView {
        // The dump harness sorts descriptors by tx hash bytes to pin
        // the priority-queue insertion order (Go map iteration is
        // random per run); mirror that here.
        let pool = &self.pool;
        let mut descs: Vec<_> = pool.values().cloned().collect();
        descs.sort_by_key(|d| d.tx_hash.0);
        self.view
            .as_ref()
            .expect("view")
            .clone_view(descs, &|hash| pool.get(&hash.0).cloned())
    }
    fn have_transaction(&self, hash: &Hash) -> bool {
        self.pool.contains_key(&hash.0)
    }
    fn have_all_transactions(&self, hashes: &[Hash]) -> bool {
        hashes.iter().all(|h| self.pool.contains_key(&h.0))
    }
    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash> {
        self.votes
            .get(&hash.0)
            .map(|v| v.iter().map(|d| d.vote_hash).collect())
            .unwrap_or_default()
    }
    fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        hashes
            .iter()
            .map(|h| self.votes.get(&h.0).cloned().unwrap_or_default())
            .collect()
    }
    fn is_reg_tx_tree_known_disapproved(&self, _hash: &Hash) -> bool {
        false
    }
}

/// Extract the extra nonce from a coinbase/treasurybase op return.
fn nonce_from(script: &[u8]) -> u64 {
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&script[6..14]);
    u64::from_le_bytes(nonce)
}

#[test]
fn newtemplate_vectors() {
    let params = leaked_params();
    let data = include_str!("data/newtemplate_vectors.txt");
    let harness_flags = ScriptFlags(
        ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS.0
            | ScriptFlags::VERIFY_CLEAN_STACK.0
            | ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY.0
            | ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY.0
            | ScriptFlags::VERIFY_SHA256.0
            | ScriptFlags::VERIFY_TREASURY.0,
    );

    let chain = FakeChain {
        best: TemplateBest::default(),
        blocks: HashMap::new(),
        utxos: UtxoView::new(),
        difficulty: 0,
        stake_version: 0,
        max_expenditure: 0,
        tip_generation: Vec::new(),
        hdr_cmt_active: true,
        treasury_active: true,
        auto_rev_active: false,
        ss_active: false,
        ssr2_active: false,
        difficulty_err: false,
        stake_version_err: false,
        connect_err: false,
        treasury_agenda_err: false,
        fetch_view_err: false,
        fetch_view_budget: Cell::new(None),
        reorg_err: false,
        tspend_votes_err: false,
        ticket_exhaustion_err: false,
        coinbase_sig_ops_err: false,
        log: Capture::new(),
        adjusted_time: 0,
        subsidy_cache: RefCell::new(SubsidyCache::new(params)),
        script_flags: harness_flags,
    };
    let policy = MiningPolicy {
        block_max_size: 375000,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    };
    // The generator owns the fake chain and source; all row handlers
    // mutate them through the generator's public fields.
    let mut g = BlkTmplGenerator::new(policy, params, chain, ThinSource::new(), 0);
    // The harness pay address is recovered from the payment output
    // of dcrd's own emitted template.
    let mut pay_addr: Option<dcroxide_txscript::stdaddr::Address> = None;
    let mut counts = [0usize; 2];
    // The automatic revocation scenarios run with the capture at debug,
    // for the count of revocations each template's build generates.
    let mut autorev = false;
    let mut autorev_lines = 0usize;

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                autorev = f[1].starts_with("autorev");
                g.chain.log.set_level(if autorev {
                    LogLevel::Debug
                } else {
                    LogLevel::Warn
                });
                g.chain.log.take();
            }
            "chainstate" => {
                g.chain.best = TemplateBest {
                    hash: parse_hash(f[1]),
                    prev_hash: parse_hash(f[2]),
                    height: f[3].parse().expect("height"),
                    median_time_unix: f[4].parse().expect("median"),
                    next_stake_diff: f[5].parse().expect("sdiff"),
                    next_final_state: {
                        let b = unhex(f[6]);
                        let mut fs = [0u8; 6];
                        fs.copy_from_slice(&b);
                        fs
                    },
                    next_pool_size: f[7].parse().expect("pool"),
                    next_winning_tickets: parse_hashes(f[8]),
                    next_expiring_tickets: parse_hashes(f[9]),
                    missed_tickets: parse_hashes(f[10]),
                };
            }
            "agendas" => {
                g.chain.hdr_cmt_active = f[1] == "true";
                g.chain.treasury_active = f[2] == "true";
                g.chain.auto_rev_active = f[3] == "true";
                g.chain.ss_active = f[4] == "true";
                g.chain.ssr2_active = f[5] == "true";
            }
            "chaincfg" => {
                g.chain.difficulty = f[1].parse().expect("difficulty");
                g.chain.stake_version = f[2].parse().expect("stake version");
                g.chain.max_expenditure = f[3].parse().expect("expenditure");
            }
            "tipgen" => g.chain.tip_generation = parse_hashes(f[1]),
            "block" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                g.chain.blocks.insert(parse_hash(f[1]).0, block);
            }
            "utxo" => {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                g.chain.utxos.add_tx_outs(
                    &tx,
                    f[2].parse().expect("height"),
                    f[3].parse().expect("index"),
                    f[4] == "true",
                );
            }
            "srctx" => {
                // srctx <name> <hex> <type> <fee> <sigops> <height>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[2])).expect("tx");
                let tx_hash = tx.tx_hash();
                let tx_type = match f[3] {
                    "0" => TxType::Regular,
                    "1" => TxType::SStx,
                    "2" => TxType::SSGen,
                    "3" => TxType::SSRtx,
                    "4" => TxType::TAdd,
                    "5" => TxType::TSpend,
                    other => panic!("unknown type {other}"),
                };
                let tree = if tx_type == TxType::Regular {
                    TX_TREE_REGULAR
                } else {
                    TX_TREE_STAKE
                };
                let tx_size = tx.serialize_size() as i64;
                g.tx_source.add(Arc::new(TxDesc {
                    tx,
                    tx_hash,
                    tree,
                    tx_type,
                    added_unix: 0,
                    height: f[6].parse().expect("height"),
                    fee: f[4].parse().expect("fee"),
                    total_sig_ops: f[5].parse().expect("sigops"),
                    tx_size,
                }));
            }
            "srcreset" => g.tx_source = ThinSource::new(),
            "errinject" => match f[1] {
                "difficulty" => g.chain.difficulty_err = true,
                "stakeversion" => {
                    g.chain.difficulty_err = false;
                    g.chain.stake_version_err = true;
                }
                "connect" => {
                    g.chain.stake_version_err = false;
                    g.chain.connect_err = true;
                }
                "treasuryagenda" => {
                    g.chain.connect_err = false;
                    g.chain.treasury_agenda_err = true;
                }
                "clear" => {
                    g.chain.treasury_agenda_err = false;
                }
                other => panic!("unknown injection {other}"),
            },
            "ntpl" => {
                // ntpl <useaddr> (ok <blockhex> <fees> <sigops>
                //      <height> <validpay> | err | none)
                let use_addr = f[1] == "true";
                let mut nonces = ExtraNonces::default();
                if f[2] == "ok" {
                    // Recover the wall clock, nonces, and payment
                    // address from dcrd's own template.
                    let (want_block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                    g.chain.adjusted_time = i64::from(want_block.header.timestamp);
                    let coinbase = &want_block.transactions[0];
                    if let Some(out) = coinbase
                        .tx_out
                        .iter()
                        .find(|o| o.value == 0 && o.pk_script.first() == Some(&0x6a))
                    {
                        nonces.coinbase = nonce_from(&out.pk_script);
                    }
                    if let Some(tb) = want_block.stransactions.first()
                        && dcroxide_stake::is_treasury_base(tb)
                    {
                        nonces.treasury = nonce_from(&tb.tx_out[1].pk_script);
                    }
                    if use_addr && pay_addr.is_none() {
                        // The last coinbase output pays the harness
                        // address as p2pkh.
                        let pay_script = &coinbase.tx_out.last().expect("payment output").pk_script;
                        assert_eq!(pay_script.len(), 25, "unexpected payment script");
                        let mut h160 = [0u8; 20];
                        h160.copy_from_slice(&pay_script[3..23]);
                        pay_addr = Some(
                            dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
                                &h160, params,
                            )
                            .expect("address"),
                        );
                    }
                }

                let result =
                    g.new_block_template(if use_addr { pay_addr.as_ref() } else { None }, &nonces);

                match result {
                    Err(e) => assert_eq!(f[2], "err", "{line}: unexpected error: {e}"),
                    Ok(None) => assert_eq!(f[2], "none", "{line}: unexpected none"),
                    Ok(Some(template)) => {
                        assert_eq!(f[2], "ok", "{line}: unexpected template");
                        assert_eq!(raw_hex(&template.block.serialize()), f[3], "{line}: block");
                        let fees = template
                            .fees
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        assert_eq!(fees, f[4], "{line}: fees");
                        let sigops = template
                            .sig_op_counts
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        assert_eq!(sigops, f[5], "{line}: sigops");
                        assert_eq!(template.height.to_string(), f[6], "{line}: height");
                        assert_eq!(
                            template.valid_pay_address.to_string(),
                            f[7],
                            "{line}: valid pay"
                        );
                        if autorev {
                            // dcrd's count (`mining.go:1075-1077`): the
                            // winning tickets left without a vote in the
                            // template, which is dcrd's, and the
                            // expiring ones, logged when there are any.
                            let votes = template
                                .block
                                .stransactions
                                .iter()
                                .filter(|tx| dcroxide_stake::is_ssgen(tx))
                                .count();
                            let missed = g.chain.best.next_winning_tickets.len() - votes;
                            let expired = g.chain.best.next_expiring_tickets.len();
                            let generated: Vec<String> = g
                                .chain
                                .log
                                .take_at(LogLevel::Debug)
                                .into_iter()
                                .filter(|msg| msg.starts_with("Generated "))
                                .collect();
                            let want = if missed + expired == 0 {
                                Vec::new()
                            } else {
                                autorev_lines += 1;
                                vec![format!(
                                    "Generated {} automatic revocations for the new block (num \
                                     missed this block: {missed}, num expired this block: \
                                     {expired})",
                                    missed + expired
                                )]
                            };
                            assert_eq!(generated, want, "{line}: revocations generated");
                        }
                        counts[1] += 1;
                    }
                }
                counts[0] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [13, 9], "row counts");
    assert_eq!(autorev_lines, AUTOREV_LINES, "revocation count lines");
}

/// The templates of the automatic revocation scenarios whose build logs
/// a count of the revocations it generates.
const AUTOREV_LINES: usize = 4;

/// A chain fixture with nothing in it, for the height-1 checks below.
fn empty_generator(
    params: &'static dcroxide_chaincfg::Params,
    best_height: i64,
) -> BlkTmplGenerator<'static, FakeChain, ThinSource> {
    // The generator reads the tip's header, so the fixture needs one.
    let tip = MsgBlock {
        header: BlockHeader {
            version: 1,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO,
            stake_root: Hash::ZERO,
            vote_bits: 1,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0x2000_0000,
            sbits: 1,
            height: best_height as u32,
            size: 0,
            timestamp: 1,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    let mut blocks = HashMap::new();
    blocks.insert(Hash::ZERO.0, tip);

    let chain = FakeChain {
        best: TemplateBest {
            height: best_height,
            median_time_unix: 1,
            next_stake_diff: 1,
            next_pool_size: 0,
            ..TemplateBest::default()
        },
        blocks,
        utxos: UtxoView::new(),
        difficulty: 0x2000_0000,
        stake_version: 0,
        max_expenditure: 0,
        tip_generation: Vec::new(),
        hdr_cmt_active: true,
        treasury_active: true,
        auto_rev_active: false,
        ss_active: false,
        ssr2_active: false,
        difficulty_err: false,
        stake_version_err: false,
        connect_err: false,
        treasury_agenda_err: false,
        fetch_view_err: false,
        fetch_view_budget: Cell::new(None),
        reorg_err: false,
        tspend_votes_err: false,
        ticket_exhaustion_err: false,
        coinbase_sig_ops_err: false,
        log: Capture::new(),
        adjusted_time: 1,
        subsidy_cache: RefCell::new(SubsidyCache::new(params)),
        script_flags: ScriptFlags(ScriptFlags::VERIFY_CLEAN_STACK.0),
    };
    let policy = MiningPolicy {
        block_max_size: 375000,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    };
    BlkTmplGenerator::new(policy, params, chain, ThinSource::new(), 0)
}

/// A confirmed anyone-can-spend output for the chain to fund from.
fn funding() -> MsgTx {
    funding_tagged(9)
}

/// A funding transaction told apart from the others by `tag`, the
/// bytes of the hash its input names.
fn funding_tagged(tag: u8) -> MsgTx {
    let mut tx = MsgTx::default();
    tx.tx_in.push(dcroxide_wire::TxIn {
        previous_out_point: OutPoint {
            hash: Hash([tag; 32]),
            index: 0,
            tree: TX_TREE_REGULAR,
        },
        sequence: 0xffff_ffff,
        value_in: 5_000_000,
        block_height: 1,
        block_index: 0,
        signature_script: Vec::new(),
    });
    tx.tx_out.push(dcroxide_wire::TxOut {
        value: 5_000_000,
        version: 0,
        pk_script: vec![0x51],
    });
    tx
}

/// An anyone-can-spend output, so script validation runs for real
/// without signing.
fn payer(funding: &MsgTx, value: i64) -> MsgTx {
    let mut tx = MsgTx::default();
    tx.tx_in.push(dcroxide_wire::TxIn {
        previous_out_point: OutPoint {
            hash: funding.tx_hash(),
            index: 0,
            tree: TX_TREE_REGULAR,
        },
        sequence: 0xffff_ffff,
        value_in: 5_000_000,
        block_height: 1,
        block_index: 0,
        signature_script: Vec::new(),
    });
    tx.tx_out.push(dcroxide_wire::TxOut {
        value,
        version: 0,
        pk_script: vec![0x51],
    });
    tx
}

/// A child spending `parent`'s first output, with the fraud proof left
/// at the null sentinels `wire.NewTxIn` defaults to.
fn spender(parent: &MsgTx, value: i64) -> MsgTx {
    let mut tx = MsgTx::default();
    tx.tx_in.push(dcroxide_wire::TxIn {
        previous_out_point: OutPoint {
            hash: parent.tx_hash(),
            index: 0,
            tree: TX_TREE_REGULAR,
        },
        sequence: 0xffff_ffff,
        value_in: dcroxide_wire::NULL_VALUE_IN,
        block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
        block_index: dcroxide_wire::NULL_BLOCK_INDEX,
        signature_script: Vec::new(),
    });
    tx.tx_out.push(dcroxide_wire::TxOut {
        value,
        version: 0,
        pk_script: vec![0x51],
    });
    tx
}

fn source_desc(tx: MsgTx, height: i64) -> Arc<TxDesc> {
    let tx_hash = tx.tx_hash();
    let tx_size = tx.serialize_size() as i64;
    Arc::new(TxDesc {
        tx,
        tx_hash,
        tree: TX_TREE_REGULAR,
        tx_type: TxType::Regular,
        added_unix: 0,
        height,
        fee: 20_000,
        total_sig_ops: 1,
        tx_size,
    })
}

/// The in-block fraud proof pass runs at height 1 (RVW-005).
///
/// dcrd guards only the chain-view refill with the height-1 escape — a
/// `break` inside that loop (`mining.go:2188-2190`) — and leaves the
/// second pass, which resolves inputs still carrying the null sentinel
/// against the block's own regular tree, to run at every height
/// (`mining.go:2224-2253`). The port wrapped both, so at height 1 it
/// neither resolved nor errored, and emitted a template whose inputs
/// still carried `NullBlockIndex`.
///
/// Not reachable on a live network: genesis pays a single zero-value
/// output, `createChainState` creates no utxo entries, and zero-value
/// spends are rejected, so no chain reaches height 1 with a spendable
/// parent. This is parity repair.
///
/// The pass's other half — the `ErrFraudProofIndex` return when the
/// parent is not in the block at all — is not covered here. Reaching it
/// needs the child selected while its parent is left out, and the
/// selector will not produce that from a fixture: with the parent absent
/// from both the source and the utxo view the child is simply never
/// chosen, so a test written that way asserts nothing.
#[test]
fn the_in_block_fraud_proof_pass_runs_at_height_one() {
    let params = leaked_params();
    let mut g = empty_generator(params, 0);
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);
    let parent = payer(&fund, 4_000_000);
    let child = spender(&parent, 3_000_000);
    let child_hash = child.tx_hash();
    g.tx_source.add(source_desc(parent.clone(), 1));
    g.tx_source.add(source_desc(child, 1));

    let template = g
        .new_block_template(
            None,
            &ExtraNonces {
                coinbase: 0,
                treasury: 0,
            },
        )
        .expect("a height-1 template with a chained pair")
        .expect("a template, not none");
    let block = &template.block;

    let idx = block
        .transactions
        .iter()
        .position(|t| t.tx_hash() == child_hash)
        .expect("the child is in the block");
    let parent_idx = block
        .transactions
        .iter()
        .position(|t| t.tx_hash() == parent.tx_hash())
        .expect("the parent is in the block");
    let tx_in = &block.transactions[idx].tx_in[0];

    // Pre-fix these are the sentinels the mempool put there.
    assert_eq!(
        (tx_in.value_in, tx_in.block_height, tx_in.block_index),
        (4_000_000, 1, parent_idx as u32),
        "the zero-conf fraud proof must be resolved from the block's own tree",
    );
}

/// The anti-regression anchor: the same pair still resolves above
/// height 1. Passes before and after — it exists so a later "fix" that
/// deletes pass one, or moves the guard onto pass two's contents,
/// cannot pass the two tests above.
#[test]
fn the_pair_still_resolves_above_height_one() {
    let params = leaked_params();
    let mut g = empty_generator(params, 100);
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);
    let parent = payer(&fund, 4_000_000);
    let child = spender(&parent, 3_000_000);
    let child_hash = child.tx_hash();
    g.tx_source.add(source_desc(parent.clone(), 100));
    g.tx_source.add(source_desc(child, 100));

    let template = g
        .new_block_template(
            None,
            &ExtraNonces {
                coinbase: 0,
                treasury: 0,
            },
        )
        .expect("a height-101 template with a chained pair")
        .expect("a template, not none");
    let block = &template.block;
    let idx = block
        .transactions
        .iter()
        .position(|t| t.tx_hash() == child_hash)
        .expect("the child is in the block");
    assert_ne!(
        block.transactions[idx].tx_in[0].block_index,
        dcroxide_wire::NULL_BLOCK_INDEX,
        "the fraud proof must be resolved above height 1 too",
    );
}

/// M2-p#2: a template error reads as dcrd's `makeError` description,
/// which is all its `Error()` returns (`internal/mining/error.go:75-77`):
/// the wrapped error's text where dcrd passes `err.Error()`, dcrd's own
/// sentence where it has one, and never the kind.  getwork hands this
/// text to the miner as "no work is available: ..."
/// (`rpcserver.go:3884-3885`).  The port used to prefix `ErrXxx: `.
#[test]
fn template_errors_read_as_dcrds_descriptions() {
    let params = leaked_params();
    let nonces = ExtraNonces::default();

    // `NewBlockTemplate`'s own difficulty and final connect checks
    // (`mining.go:2166`, `:2340-2342`).
    let mut g = empty_generator(params, 100);
    g.chain.difficulty_err = true;
    let err = g.new_block_template(None, &nonces).expect_err("difficulty");
    assert_eq!(err, "diff err");
    g.chain.difficulty_err = false;
    g.chain.connect_err = true;
    let err = g.new_block_template(None, &nonces).expect_err("connect");
    assert_eq!(
        err,
        "failed to do final check for check connect block when making new block \
         template: cbt err"
    );

    // The too-few-voters recycle at stake validation height, with no
    // votes for any parent (`mining.go:903`, `:935-937`).
    let mut g = empty_generator(params, params.stake_validation_height - 1);
    g.chain.difficulty_err = true;
    let err = g.new_block_template(None, &nonces).expect_err("difficulty");
    assert_eq!(err, "diff err");
    g.chain.difficulty_err = false;
    g.chain.connect_err = true;
    let err = g.new_block_template(None, &nonces).expect_err("connect");
    assert_eq!(
        err,
        "failed to check template: cbt err while constructing a new parent"
    );
}

/// A vote on `block_hash` at `height` spending `ticket`, shaped enough
/// for the generator's vote handling (block reference and vote bits
/// outputs) but with a ticket the chain does not hold.
fn vote_on(block_hash: Hash, height: u32, ticket: Hash) -> Arc<TxDesc> {
    let mut block_ref = vec![0x6a, 0x24];
    block_ref.extend_from_slice(&block_hash.0);
    block_ref.extend_from_slice(&height.to_le_bytes());
    let input = |hash: Hash, index: u32, tree: i8| dcroxide_wire::TxIn {
        previous_out_point: OutPoint { hash, index, tree },
        sequence: 0xffff_ffff,
        value_in: 0,
        block_height: 0,
        block_index: 0,
        signature_script: Vec::new(),
    };
    let tx = MsgTx {
        tx_in: vec![
            input(Hash::ZERO, u32::MAX, TX_TREE_REGULAR),
            input(ticket, 0, TX_TREE_STAKE),
        ],
        tx_out: vec![
            dcroxide_wire::TxOut {
                value: 0,
                version: 0,
                pk_script: block_ref,
            },
            dcroxide_wire::TxOut {
                value: 0,
                version: 0,
                pk_script: vec![0x6a, 0x02, 0x01, 0x00],
            },
        ],
        ..MsgTx::default()
    };
    let tx_hash = tx.tx_hash();
    let tx_size = tx.serialize_size() as i64;
    Arc::new(TxDesc {
        tx,
        tx_hash,
        tree: TX_TREE_STAKE,
        tx_type: TxType::SSGen,
        added_unix: 0,
        height: i64::from(height),
        fee: 0,
        total_sig_ops: 0,
        tx_size,
    })
}

/// M2-p#3: the generator logs dcrd's mining warnings, which the daemon
/// routes to `MINR`.  A source transaction whose utxo view cannot be
/// fetched is skipped with dcrd's warning (`mining.go:1374-1379`).
#[test]
fn a_utxo_view_failure_is_logged_as_dcrd_warns() {
    let params = leaked_params();
    let mut g = empty_generator(params, 100);
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);
    let tx = payer(&fund, 4_000_000);
    let tx_hash = tx.tx_hash();
    g.tx_source.add(source_desc(tx, 100));
    g.chain.fetch_view_err = true;

    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("a template")
        .expect("not none");
    assert_eq!(
        template.block.transactions.len(),
        1,
        "the transaction is skipped"
    );
    assert_eq!(
        g.chain.log.take_at(LogLevel::Warn),
        [format!(
            "Unable to fetch utxo view for tx {tx_hash}: view err"
        )]
    );
}

/// M2-p#3: a build whose parent has enough votes in the source but ends
/// with too few in the block warns as dcrd does before recycling the
/// parent (`mining.go:2174-2179`).  The votes here spend tickets the
/// chain does not hold, so the scan skips every one.
#[test]
fn too_few_voters_after_assembly_is_logged_as_dcrd_warns() {
    let params = leaked_params();
    let tip_height = params.stake_validation_height - 1;
    let mut g = empty_generator(params, tip_height);
    g.chain.tip_generation = vec![Hash::ZERO];
    for ticket in 1..=3u8 {
        g.tx_source
            .add(vote_on(Hash::ZERO, tip_height as u32, Hash([ticket; 32])));
    }

    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("the parent recycle")
        .expect("aggressive mining builds on the parent");
    assert_eq!(template.height, tip_height, "built on the tip's parent");
    assert_eq!(
        g.chain.log.take_at(LogLevel::Warn),
        ["incongruent number of voters in mempool vs mempool.voters; not enough voters found"]
    );
}

/// One template build over a single paying transaction, with the
/// capture set to `level`: the transaction, the template and the lines.
fn one_payer_build(
    level: LogLevel,
) -> (
    MsgTx,
    dcroxide_mining::BlockTemplate,
    Vec<(LogLevel, String)>,
) {
    let params = leaked_params();
    let mut g = empty_generator(params, 100);
    // A target with a mantissa, so the line's `%064x` has digits to pad.
    g.chain.difficulty = 0x1d00_ffff;
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);
    let tx = payer(&fund, 4_000_000);
    g.tx_source.add(source_desc(tx.clone(), 100));
    g.chain.log.set_level(level);
    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("a template")
        .expect("not none");
    (tx, template, g.chain.log.take())
}

/// A build logs dcrd's debug and trace lines with dcrd's texts
/// (`mining.go:1331-1332`, `:1440-1441`, `:1810-1812`, `:2345-2351`):
/// the considered count, the queue sizes, each transaction added, and
/// the template's summary, whose size is dcrd's running estimate (the
/// header and the largest count varint, the selected transactions and
/// the coinbase, less the varint bytes the real count does not need,
/// the treasurybase not counted), whose target is the 256-bit number
/// zero-padded to 64 hex digits and whose ticket price is `%v` of the
/// coin amount, in Go's exponent form for 1 atom.  Each line shows at its
/// own level and not above it.
#[test]
fn a_template_build_logs_dcrds_lines_at_their_levels() {
    let (tx, template, lines) = one_payer_build(LogLevel::Trace);
    let tx_hash = tx.tx_hash();
    let block = &template.block;
    let bytes = 180 + 9 + tx.serialize_size() + block.transactions[0].serialize_size() - (9 - 1);
    let sigops = 1 + template.sig_op_counts[0];
    let fee_per_kb = 20_000.0 * 1000.0 / tx.serialize_size() as f64;
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(
        lines[0],
        (
            LogLevel::Debug,
            "Considering 1 transactions for inclusion to new block".to_string()
        )
    );
    assert_eq!(
        lines[1],
        (
            LogLevel::Trace,
            "Priority queue len 1, dependers len 0".to_string()
        )
    );
    let (level, adding) = &lines[2];
    assert_eq!(*level, LogLevel::Trace);
    let prefix = format!("Adding tx {tx_hash} (priority ");
    let suffix = format!(", feePerKB {fee_per_kb:.2})");
    assert!(
        adding.starts_with(&prefix) && adding.ends_with(&suffix),
        "{adding}"
    );
    let priority = &adding[prefix.len()..adding.len() - suffix.len()];
    assert!(
        priority.split_once('.').is_some_and(|(int, frac)| {
            !int.is_empty()
                && frac.len() == 2
                && int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
        }),
        "the priority prints with two decimals: {priority}"
    );
    assert_eq!(
        lines[3],
        (
            LogLevel::Debug,
            format!(
                "Created new block template (2 transactions, 1 stake transactions, 0 treasury \
                 transactions, 20000 in fees, {sigops} signature operations, {bytes} bytes, \
                 target difficulty \
                 00000000ffff0000000000000000000000000000000000000000000000000000, stake \
                 difficulty 1e-08)"
            )
        )
    );
    assert_eq!(block.stransactions.len(), 1, "the treasurybase");

    let (_, _, lines) = one_payer_build(LogLevel::Debug);
    assert_eq!(
        lines.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [LogLevel::Debug, LogLevel::Debug],
        "{lines:?}"
    );
    let (_, _, lines) = one_payer_build(LogLevel::Info);
    assert!(lines.is_empty(), "{lines:?}");
}

/// A transaction paying too little to be mined for free is skipped with
/// dcrd's trace line, whose format string ends in a space, and each of
/// its children with `logSkippedDeps`'s, whose format ends in a newline
/// slog follows with its own (`mining.go:720-729`, `:1736-1743`;
/// QK-0031).
#[test]
fn a_skipped_free_transaction_and_its_dependents_are_logged_at_trace() {
    let params = leaked_params();
    let mut g = empty_generator(params, 100);
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);
    let parent = payer(&fund, 4_000_000);
    let child = spender(&parent, 3_000_000);
    let parent_hash = parent.tx_hash();
    let child_hash = child.tx_hash();
    let free = |tx: MsgTx| {
        Arc::new(TxDesc {
            fee: 0,
            ..(*source_desc(tx, 100)).clone()
        })
    };
    g.tx_source.add(free(parent));
    g.tx_source.add(free(child));
    g.chain.log.set_level(LogLevel::Trace);

    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("a template")
        .expect("not none");
    assert_eq!(template.block.transactions.len(), 1, "both are skipped");
    let lines = g.chain.log.take();
    for want in [
        format!("Skipping tx {parent_hash} with feePerKB 0.00 < TxMinFreeFee 10000 "),
        format!("Skipping tx {child_hash} since it depends on {parent_hash}\n"),
    ] {
        assert!(
            lines.contains(&(LogLevel::Trace, want.clone())),
            "{want:?} in {lines:?}"
        );
    }
}

/// With no parent holding enough votes, the build logs dcrd's debug line
/// before recycling the tip's parent (`mining.go:1254-1255`), and, when
/// it does not mine aggressively, the one for giving up
/// (`mining.go:943-944`); a parent with enough votes is named before the
/// build goes on (`mining.go:1260-1262`).
#[test]
fn the_parent_choice_is_logged_as_dcrd_logs_it() {
    let params = leaked_params();
    let tip_height = params.stake_validation_height - 1;

    let mut g = empty_generator(params, tip_height);
    g.chain.log.set_level(LogLevel::Debug);
    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("the parent recycle");
    assert!(template.is_some(), "aggressive mining builds on the parent");
    assert_eq!(
        g.chain.log.take_at(LogLevel::Debug),
        ["Too few voters found on any HEAD block, recycling a parent block to mine on"]
    );

    g.policy.aggressive_mining = false;
    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("no template, no error");
    assert!(template.is_none());
    assert_eq!(
        g.chain.log.take_at(LogLevel::Debug),
        [
            "Too few voters found on any HEAD block, recycling a parent block to mine on",
            "Not enough voters on top block to generate new block template",
        ]
    );

    let mut g = empty_generator(params, tip_height);
    g.chain.tip_generation = vec![Hash::ZERO];
    for ticket in 1..=3u8 {
        g.tx_source
            .add(vote_on(Hash::ZERO, tip_height as u32, Hash([ticket; 32])));
    }
    g.chain.log.set_level(LogLevel::Debug);
    g.new_block_template(None, &ExtraNonces::default())
        .expect("the parent recycle");
    assert_eq!(
        g.chain.log.take(),
        [
            (
                LogLevel::Debug,
                format!(
                    "Found eligible parent {} with enough votes to build block on, \
                     proceeding to create a new block template",
                    Hash::ZERO
                )
            ),
            (
                LogLevel::Debug,
                "Considering 3 transactions for inclusion to new block".to_string()
            ),
            (
                LogLevel::Warn,
                "incongruent number of voters in mempool vs mempool.voters; not enough voters \
                 found"
                    .to_string()
            ),
        ]
    );
}

/// The pass over the source logs at trace each transaction it leaves
/// out, with dcrd's texts (`mining.go:1351-1365`, `:1397-1400`): one not
/// yet final, a vote on another block, and one spending an output
/// neither the chain nor the source has.
#[test]
fn the_pass_over_the_source_logs_each_transaction_it_leaves_out() {
    let params = leaked_params();
    let mut g = empty_generator(params, 100);
    let fund = funding();
    g.chain.utxos.add_tx_outs(&fund, 1, 0, false);

    let mut locked = payer(&fund, 2);
    locked.lock_time = 1000;
    locked.tx_in[0].sequence = 0;
    let unknown = spender(&payer(&fund, 3), 3);
    let unknown_input = unknown.tx_in[0].previous_out_point;
    let vote = vote_on(Hash([0x77; 32]), 100, Hash([1; 32]));
    let vote_hash = vote.tx_hash;
    let (locked_hash, unknown_hash) = (locked.tx_hash(), unknown.tx_hash());
    g.tx_source.add(source_desc(locked, 100));
    g.tx_source.add(source_desc(unknown, 100));
    g.tx_source.add(vote);
    g.chain.log.set_level(LogLevel::Trace);

    let template = g
        .new_block_template(None, &ExtraNonces::default())
        .expect("a template")
        .expect("not none");
    assert_eq!(
        template.block.transactions.len(),
        1,
        "all three are left out"
    );
    let mut skipped: Vec<String> = g
        .chain
        .log
        .take_at(LogLevel::Trace)
        .into_iter()
        .filter(|line| line.starts_with("Skipping"))
        .collect();
    skipped.sort();
    let mut want = vec![
        format!("Skipping non-finalized tx {locked_hash}"),
        format!("Skipping ssgen tx {vote_hash} because it does not vote on the correct block"),
        format!(
            "Skipping tx {unknown_hash} because it references unspent output {unknown_input} \
             which is not available"
        ),
    ];
    want.sort();
    assert_eq!(skipped, want);
}

/// A generator for the level tests below, built afresh for each build.
type Generator = BlkTmplGenerator<'static, FakeChain, ThinSource>;

/// What a build returns.
type BuildResult = Result<Option<dcroxide_mining::BlockTemplate>, String>;

/// The lines one build over a fresh `make()` logs with the capture at
/// `level`, with the build's result.
fn build_at(
    make: &dyn Fn() -> Generator,
    level: LogLevel,
) -> (BuildResult, Vec<(LogLevel, String)>) {
    let mut g = make();
    g.chain.log.set_level(level);
    let result = g.new_block_template(None, &ExtraNonces::default());
    (result, g.chain.log.take())
}

/// The level above `level`, at which its lines must not show.
fn level_above(level: LogLevel) -> LogLevel {
    match level {
        LogLevel::Trace => LogLevel::Debug,
        LogLevel::Debug => LogLevel::Info,
        LogLevel::Info => LogLevel::Warn,
        LogLevel::Warn | LogLevel::Error => LogLevel::Error,
    }
}

/// Each line `matches` names is logged at `level` by a build with the
/// capture there, and by none with the capture a level above.  A wanted
/// line is matched by its whole text, or by its start where it ends in
/// an error text the fake chain makes up.
fn assert_logged_at(make: &dyn Fn() -> Generator, level: LogLevel, wants: &[(&str, bool)]) {
    let matches = |line: &str, (want, whole): (&str, bool)| {
        if whole {
            line == want
        } else {
            line.starts_with(want)
        }
    };
    let (_, lines) = build_at(make, level);
    for want in wants {
        assert!(
            lines
                .iter()
                .any(|(at, line)| *at == level && matches(line, *want)),
            "{want:?} at {level:?} in {lines:?}"
        );
    }
    let above = level_above(level);
    let (_, lines) = build_at(make, above);
    for want in wants {
        assert!(
            !lines.iter().any(|(_, line)| matches(line, *want)),
            "{want:?} at {above:?}: {lines:?}"
        );
    }
}

/// A generator at `best_height` over the funding transactions, with
/// `descs` in its source.
fn generator_with(
    params: &'static dcroxide_chaincfg::Params,
    best_height: i64,
    funds: &[&MsgTx],
    descs: &[Arc<TxDesc>],
) -> Generator {
    let mut g = empty_generator(params, best_height);
    for fund in funds {
        g.chain.utxos.add_tx_outs(fund, 1, 0, false);
    }
    for desc in descs {
        g.tx_source.add(desc.clone());
    }
    g
}

/// The descriptor of `tx` with its tree and type replaced.
fn typed_desc(tx: MsgTx, tree: i8, tx_type: TxType) -> Arc<TxDesc> {
    Arc::new(TxDesc {
        tree,
        tx_type,
        ..(*source_desc(tx, 100)).clone()
    })
}

/// The queue's checks log at trace each transaction they skip, with
/// dcrd's texts (`mining.go:1690-1712`, `:1752-1770`): one too big for
/// the block, one over the block's signature operations, one whose
/// inputs fail `CheckTransactionInputs` and one whose script fails.
#[test]
fn the_queues_checks_log_each_transaction_they_skip_at_trace() {
    let params = leaked_params();
    let fund = funding();
    let big = payer(&fund, 4_000_000);
    let make = || {
        let mut g = generator_with(params, 100, &[&fund], &[source_desc(big.clone(), 100)]);
        g.policy.block_max_size = 200;
        g
    };
    let want = format!(
        "Skipping tx {} (size {}) because it would exceed the max block size; cur block size \
         189, cur num tx 0",
        big.tx_hash(),
        big.serialize_size()
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);

    let heavy = Arc::new(TxDesc {
        total_sig_ops: dcroxide_blockchain::validate::MAX_SIG_OPS_PER_BLOCK + 1,
        ..(*source_desc(payer(&fund, 4_000_000), 100)).clone()
    });
    let make = || generator_with(params, 100, &[&fund], std::slice::from_ref(&heavy));
    let want = format!(
        "Skipping tx {} because it would exceed the maximum sigops per block",
        heavy.tx_hash
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);

    // Spending more than its input holds.
    let overspend = payer(&fund, 6_000_000);
    let make = || {
        generator_with(
            params,
            100,
            &[&fund],
            &[source_desc(overspend.clone(), 100)],
        )
    };
    let want = format!(
        "Skipping tx {} due to error in CheckTransactionInputs: ",
        overspend.tx_hash()
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, false)]);

    // Spending an output whose script leaves false on the stack.
    let mut false_fund = funding_tagged(8);
    false_fund.tx_out[0].pk_script = vec![0x00];
    let unspendable = payer(&false_fund, 4_000_000);
    let make = || {
        generator_with(
            params,
            100,
            &[&false_fund],
            &[source_desc(unspendable.clone(), 100)],
        )
    };
    let want = format!(
        "Skipping tx {} due to error in ValidateTransactionScripts: ",
        unspendable.tx_hash()
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, false)]);
}

/// A treasury spend is skipped at trace with dcrd's line for each check
/// it fails (`mining.go:1562-1606`): off a treasury vote interval,
/// outside its voting window, without enough votes, and over what the
/// treasury may spend, which before stake validation height is nothing.
#[test]
fn a_skipped_treasury_spend_is_logged_at_trace() {
    let params = leaked_params();
    let tspend = |expiry: u32, value_in: i64| {
        let mut tx = payer(&funding(), 0);
        tx.version = 3;
        tx.expiry = expiry;
        tx.tx_in[0].value_in = value_in;
        typed_desc(tx, TX_TREE_STAKE, TxType::TSpend)
    };

    let off_tvi = tspend(4034, 0);
    let make = || generator_with(params, 100, &[], std::slice::from_ref(&off_tvi));
    let want = format!(
        "Skipping tspend {} because block is not on a TVI: 101",
        off_tvi.tx_hash
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);

    // 3744 is a treasury vote interval, inside the window of an expiry
    // of 4034 and outside that of an expiry of 0.
    let (tvi, multiplier) = (
        params.treasury_vote_interval,
        params.treasury_vote_interval_multiplier,
    );
    assert!(dcroxide_standalone::is_treasury_vote_interval(3744, tvi));
    assert!(dcroxide_standalone::inside_tspend_window(
        3744, 4034, tvi, multiplier
    ));
    assert!(!dcroxide_standalone::inside_tspend_window(
        3744, 0, tvi, multiplier
    ));
    let outside = tspend(0, 0);
    let unvoted = tspend(4034, 0);
    let make = || {
        let mut g = generator_with(params, 3743, &[], &[outside.clone(), unvoted.clone()]);
        g.chain.tspend_votes_err = true;
        g
    };
    let want_outside = format!(
        "Skipping treasury spend {} at height 3744 because it has an expiry of 0 that is \
         outside of the voting window",
        outside.tx_hash
    );
    let want_unvoted = format!(
        "Skipping tspend {} because it doesn't have enough votes: height 3744 reason 'votes \
         err'",
        unvoted.tx_hash
    );
    assert_logged_at(
        &make,
        LogLevel::Trace,
        &[(&want_outside, true), (&want_unvoted, true)],
    );

    let overspending = tspend(4034, 1000);
    let make = || generator_with(params, 3743, &[], std::slice::from_ref(&overspending));
    let want = format!(
        "Skipping tspend {} because it spends more than allowed: treasury 0 tspend 1000",
        overspending.tx_hash
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);
}

/// Past the block's limits on treasury adds and on fresh tickets a
/// transaction is skipped at trace with dcrd's lines
/// (`mining.go:1609-1624`): the twenty-first treasury add, and with the
/// network allowing no fresh stake, a ticket.
#[test]
fn a_transaction_past_a_per_block_limit_is_logged_at_trace() {
    let params = leaked_params();
    let funds: Vec<MsgTx> = (0..21u8).map(|i| funding_tagged(100 + i)).collect();
    let tadds: Vec<Arc<TxDesc>> = funds
        .iter()
        .map(|fund| typed_desc(payer(fund, 4_000_000), TX_TREE_STAKE, TxType::TAdd))
        .collect();
    let fund_refs: Vec<&MsgTx> = funds.iter().collect();
    let make = || generator_with(params, 100, &fund_refs, &tadds);
    let (_, lines) = build_at(&make, LogLevel::Trace);
    let skipped: Vec<&String> = lines
        .iter()
        .filter(|(_, line)| line.starts_with("Skipping tadd "))
        .map(|(_, line)| line)
        .collect();
    assert_eq!(skipped.len(), 1, "{lines:?}");
    let tadd = tadds
        .iter()
        .find(|desc| skipped[0].starts_with(&format!("Skipping tadd {} ", desc.tx_hash)))
        .expect("the skipped one is one of them");
    let want = format!(
        "Skipping tadd {} because it would exceed the max number of tadds allowed in a block",
        tadd.tx_hash
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);

    let mut no_fresh_stake = mainnet_params();
    no_fresh_stake.max_fresh_stake_per_block = 0;
    let no_fresh_stake: &'static dcroxide_chaincfg::Params = Box::leak(Box::new(no_fresh_stake));
    let fund = funding();
    let ticket = typed_desc(payer(&fund, 4_000_000), TX_TREE_STAKE, TxType::SStx);
    let make = || generator_with(no_fresh_stake, 100, &[&fund], std::slice::from_ref(&ticket));
    let want = format!(
        "Skipping sstx {} because it would exceed the max number of sstx allowed in a block",
        ticket.tx_hash
    );
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);
}

/// The pass over the source skips a coinbase at trace, and the regular
/// tree's assembly logs a selected transaction of neither tree
/// (`mining.go:1346-1348`, `:2093-2098`).
#[test]
fn a_coinbase_in_the_source_and_a_transaction_of_no_tree_are_logged_at_trace() {
    let params = leaked_params();
    let coinbase = MsgTx {
        version: 3,
        tx_in: vec![dcroxide_wire::TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: TX_TREE_REGULAR,
            },
            sequence: 0xffff_ffff,
            value_in: 0,
            block_height: 0,
            block_index: 0,
            signature_script: vec![0x00, 0x00],
        }],
        tx_out: vec![dcroxide_wire::TxOut {
            value: 0,
            version: 0,
            pk_script: vec![0x51],
        }],
        ..MsgTx::default()
    };
    assert!(dcroxide_standalone::is_coin_base_tx(&coinbase, true));
    let coinbase = source_desc(coinbase, 100);
    let fund = funding();
    let treeless = typed_desc(payer(&fund, 4_000_000), 2, TxType::Regular);
    let make = || generator_with(params, 100, &[&fund], &[coinbase.clone(), treeless.clone()]);
    let want_coinbase = format!("Skipping coinbase tx {}", coinbase.tx_hash);
    let want_treeless = format!(
        "Error adding tx {} to block; invalid tree",
        treeless.tx_hash
    );
    assert_logged_at(
        &make,
        LogLevel::Trace,
        &[(&want_coinbase, true), (&want_treeless, true)],
    );
}

/// The build's debug lines for a failed reorganization to the parent
/// with the most votes (`mining.go:1271-1275`), and for the errors of
/// the ticket exhaustion check and of the coinbase's signature operation
/// count, which `log.Debug` prints as the error's text, before the build
/// returns them (`:2009-2013`, `:2069-2074`).  None shows at info.
#[test]
fn a_failed_reorganization_and_the_build_errors_are_logged_at_debug() {
    let params = leaked_params();
    let tip_height = params.stake_validation_height - 1;
    let sibling = Hash([0x55; 32]);
    let make = || {
        let mut g = empty_generator(params, tip_height);
        g.chain.tip_generation = vec![sibling];
        for ticket in 1..=3u8 {
            g.tx_source
                .add(vote_on(sibling, tip_height as u32, Hash([ticket; 32])));
        }
        g.chain.reorg_err = true;
        g
    };
    let want_found = format!(
        "Found eligible parent {sibling} with enough votes to build block on, proceeding to \
         create a new block template"
    );
    assert_logged_at(
        &make,
        LogLevel::Debug,
        &[
            (&want_found, true),
            ("failed to reorganize to new parent: reorg err", true),
        ],
    );

    let make = || {
        let mut g = empty_generator(params, 100);
        g.chain.ticket_exhaustion_err = true;
        g
    };
    assert_logged_at(&make, LogLevel::Debug, &[("exhaustion err", true)]);
    let (result, _) = build_at(&make, LogLevel::Info);
    assert_eq!(
        result.expect_err("the exhaustion check fails"),
        "exhaustion err"
    );

    let make = || {
        let mut g = empty_generator(params, 100);
        g.chain.coinbase_sig_ops_err = true;
        g
    };
    assert_logged_at(&make, LogLevel::Debug, &[("sigops err", true)]);
    let (result, _) = build_at(&make, LogLevel::Info);
    assert_eq!(result.expect_err("the count fails"), "sigops err");
}

/// A treasury add the build selects goes into the stake tree with dcrd's
/// trace line (`mining.go:2044-2051`), and is left out with
/// `maybeInsertStakeTx`'s warning when its inputs cannot be fetched for
/// the fraud proofs (`:769-773`).
#[test]
fn a_selected_treasury_add_is_logged_as_it_goes_into_the_stake_tree() {
    let params = leaked_params();
    let fund = funding();
    let mut tadd = payer(&fund, 4_000_000);
    tadd.version = 3;
    tadd.tx_out[0].pk_script = vec![0xc1];
    assert!(dcroxide_stake::is_tadd(&tadd));
    let tadd_hash = tadd.tx_hash();
    let desc = typed_desc(tadd, TX_TREE_STAKE, TxType::TAdd);
    let make = || generator_with(params, 100, &[&fund], std::slice::from_ref(&desc));
    let want = format!("maybeInsertStakeTx TADD {tadd_hash} ");
    assert_logged_at(&make, LogLevel::Trace, &[(&want, true)]);
    let (result, _) = build_at(&make, LogLevel::Info);
    let template = result.expect("a template").expect("not none");
    assert!(
        template
            .block
            .stransactions
            .iter()
            .any(|tx| tx.tx_hash() == tadd_hash),
        "the treasury add is in the stake tree"
    );

    // The pass over the source fetches the add's view once; the second
    // fetch, for its fraud proofs, fails.
    let make = || {
        let g = generator_with(params, 100, &[&fund], std::slice::from_ref(&desc));
        g.chain.fetch_view_budget.set(Some(1));
        g
    };
    let want = format!("Unable to fetch transaction store for stx {tadd_hash}: view err");
    assert_logged_at(&make, LogLevel::Warn, &[(&want, true)]);
    let (result, _) = build_at(&make, LogLevel::Info);
    let template = result.expect("a template").expect("not none");
    assert!(
        !template
            .block
            .stransactions
            .iter()
            .any(|tx| tx.tx_hash() == tadd_hash),
        "the treasury add is left out"
    );
}
