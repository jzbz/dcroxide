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

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::{
    ChainSubsidyParams, check_transaction_inputs, count_sig_ops, is_finalized_transaction,
    validate_transaction_scripts,
};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
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
    // The wall clock recovered from dcrd's emitted template.
    adjusted_time: i64,
    subsidy_cache: RefCell<SubsidyCache<ChainSubsidyParams<'static>>>,
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
            |op| view.lookup_entry(op).cloned(),
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
        Ok(())
    }
    fn count_sig_ops(&self, tx: &MsgTx, is_cb: bool, is_ssgen: bool, treasury: bool) -> i64 {
        count_sig_ops(tx, is_cb, is_ssgen, treasury)
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
        validate_transaction_scripts(tx, |op| view.lookup_entry(op).cloned(), flags, auto_rev)
            .map_err(|e| format!("{e:?}"))
    }
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        Ok(self.script_flags)
    }
    fn adjusted_time_unix(&self) -> i64 {
        self.adjusted_time
    }
}

/// A thin source mirroring the harness `fakeTxSource` surface the
/// generator consumes.
#[derive(Default)]
struct ThinSource {
    pool: HashMap<[u8; 32], Rc<TxDesc>>,
    outpoints: HashMap<([u8; 32], u32, i8), Rc<TxDesc>>,
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

    fn add(&mut self, desc: Rc<TxDesc>) {
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
        adjusted_time: 0,
        subsidy_cache: RefCell::new(SubsidyCache::new(ChainSubsidyParams(params))),
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

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {}
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
                g.tx_source.add(Rc::new(TxDesc {
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
                        counts[1] += 1;
                    }
                }
                counts[0] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [9, 5], "row counts");
}
