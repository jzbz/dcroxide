// SPDX-License-Identifier: ISC
//! Differential tests: our stake classification, extraction, lottery, and
//! reward calculations vs dcrd's blockchain/stake, live through the
//! oracle, over structured near-valid stake transactions (real tickets,
//! votes, revocations, and treasury transactions built from stdaddr
//! scripts), their mutations, random garbage, boundary-biased reward
//! inputs, and PRNG sequences.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake as stake;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_txscript::stdaddr;
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// Mirror of the oracle's `stake_analyze` dump for our side.
fn analyze_ours(tx: &MsgTx) -> String {
    let mut w = String::new();
    w.push_str(&format!("type={}\n", stake::determine_tx_type(tx) as u8));
    let ok_or = |r: Result<(), stake::RuleError>| -> String {
        match r {
            Ok(()) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    };
    w.push_str(&format!("checksstx={}\n", ok_or(stake::check_sstx(tx))));
    let ssgen_result = stake::check_ssgen_votes(tx);
    w.push_str(&format!(
        "checkssgen={}\n",
        match &ssgen_result {
            Ok(_) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    ));
    w.push_str(&format!("checkssrtx={}\n", ok_or(stake::check_ssrtx(tx))));
    w.push_str(&format!("checktadd={}\n", ok_or(stake::check_tadd(tx))));
    w.push_str(&format!(
        "checktspend={}\n",
        match stake::check_tspend(tx) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.kind.kind_name().to_string(),
        }
    ));
    // dcrd 2.2 moved the treasurybase null-outpoint check ahead of
    // the output checks, so the failure kind for multi-defect
    // transactions no longer matches the v2.1.5 oracle; the check is
    // excluded from the oracle comparison (the acceptance set is
    // unchanged and still covered through the type classification)
    // and the new precedence is pinned natively below.
    if stake::is_sstx(tx) {
        let info = stake::tx_sstx_stake_output_info(tx);
        for i in 0..info.is_p2sh.len() {
            w.push_str(&format!(
                "commit={} {} {} {} {} {} {} {}\n",
                info.is_p2sh[i],
                hex(&info.addresses[i]),
                info.amounts[i],
                info.change_amounts[i],
                info.spend_rules[i][0],
                info.spend_rules[i][1],
                info.spend_limits[i][0],
                info.spend_limits[i][1],
            ));
        }
    }
    if stake::is_ssgen(tx) {
        let (block_hash, height) = stake::ssgen_block_voted_on(tx);
        w.push_str(&format!("votedon={block_hash} {height}\n"));
        w.push_str(&format!("votebits={}\n", stake::ssgen_vote_bits(tx)));
        w.push_str(&format!("voteversion={}\n", stake::ssgen_version(tx)));
        for v in ssgen_result.expect("is_ssgen implies ok") {
            w.push_str(&format!("tv={} {}\n", v.hash, v.vote));
        }
    }
    w
}

fn analyze_theirs(oracle: &mut Oracle, tx: &MsgTx) -> String {
    let result = oracle.call_ok("stake_analyze", &tx.serialize());
    let dump = String::from_utf8(unhex(&result)).expect("dump is UTF-8");
    // Strip the treasurybase check row: its failure precedence
    // changed in dcrd 2.2 (see analyze_ours).
    dump.lines()
        .filter(|line| !line.starts_with("checktreasurybase="))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn random_hash(rng: &mut SplitMix64) -> Hash {
    let mut h = [0u8; 32];
    rng.fill(&mut h);
    Hash(h)
}

/// A random funding-style input (regular tree, plausible outpoint).
fn funding_input(rng: &mut SplitMix64) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: random_hash(rng),
            index: rng.below(4) as u32,
            tree: 0,
        },
        sequence: 0xffff_ffff,
        value_in: rng.below(1 << 44) as i64,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: rng.bytes(16),
    }
}

/// A stakebase (null) input.
fn stakebase_input() -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: Hash::ZERO,
            index: u32::MAX,
            tree: 0,
        },
        sequence: 0xffff_ffff,
        value_in: 0,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: Vec::new(),
    }
}

fn out(value: i64, pk_script: Vec<u8>) -> TxOut {
    TxOut {
        value,
        version: 0,
        pk_script,
    }
}

fn base_tx(version: u16) -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version,
        tx_in: Vec::new(),
        tx_out: Vec::new(),
        lock_time: 0,
        expiry: 0,
    }
}

/// A random P2PKH-ECDSA or P2SH stake address.
fn random_stake_addr(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> stdaddr::Address {
    let mut hash = [0u8; 20];
    rng.fill(&mut hash);
    if rng.below(2) == 0 {
        stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, params).expect("20 bytes")
    } else {
        stdaddr::new_address_script_hash_v0_from_hash(&hash, params).expect("20 bytes")
    }
}

/// A structurally valid ticket purchase with 1-3 inputs.
fn build_ticket(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let n = rng.below(3) as usize + 1;
    let mut tx = base_tx(1);
    let vote_addr = random_stake_addr(rng, params);
    let (_, submission) = vote_addr.voting_rights_script().expect("stake address");
    let ticket_price = rng.below(1 << 40) as i64 + n as i64;
    tx.tx_out.push(out(ticket_price, submission));

    for _ in 0..n {
        tx.tx_in.push(funding_input(rng));
        let commit_addr = random_stake_addr(rng, params);
        let amount = rng.below(1 << 40) as i64 + 1;
        let vote_fee = if rng.below(2) == 0 {
            0
        } else {
            1 << rng.below(20)
        };
        let revoke_fee = if rng.below(2) == 0 {
            0
        } else {
            1 << rng.below(20)
        };
        let (_, commitment) = commit_addr
            .reward_commitment_script(amount, vote_fee, revoke_fee)
            .expect("stake address");
        tx.tx_out.push(out(0, commitment));
        let change_addr = random_stake_addr(rng, params);
        let (_, change) = change_addr.stake_change_script().expect("stake address");
        tx.tx_out.push(out(rng.below(1 << 30) as i64, change));
    }
    tx
}

/// A structurally valid vote for a random ticket shape.
fn build_vote(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let with_tv = rng.below(3) == 0;
    let mut tx = base_tx(if with_tv { 3 } else { 1 });

    tx.tx_in.push(stakebase_input());
    tx.tx_in.push(TxIn {
        previous_out_point: OutPoint {
            hash: random_hash(rng),
            index: 0,
            tree: 1,
        },
        sequence: 0xffff_ffff,
        value_in: rng.below(1 << 44) as i64,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: rng.bytes(16),
    });

    // Block reference: OP_RETURN OP_DATA_36 <32-byte hash><4-byte height>.
    let mut reference = vec![0x6a, 0x24];
    reference.extend_from_slice(&random_hash(rng).0);
    reference.extend_from_slice(&(rng.below(1 << 20) as u32).to_le_bytes());
    tx.tx_out.push(out(0, reference));

    // Vote bits: OP_RETURN OP_DATA_N <2-byte bits [+ extra]>.
    let extra = rng.below(4) as usize * 2;
    let mut votebits = vec![0x6a, (2 + extra) as u8];
    votebits.extend_from_slice(&(rng.next_u64() as u16).to_le_bytes());
    votebits.extend(rng.bytes(extra + 1).iter().take(extra));
    while votebits.len() < 2 + 2 + extra {
        votebits.push(0);
    }
    tx.tx_out.push(out(0, votebits));

    // SSGen-tagged payouts.
    for _ in 0..(rng.below(3) + 1) {
        let addr = random_stake_addr(rng, params);
        let (_, payout) = addr.pay_vote_commitment_script().expect("stake address");
        tx.tx_out.push(out(rng.below(1 << 40) as i64, payout));
    }

    // Sometimes a treasury vote output.
    if with_tv {
        let n_votes = rng.below(3) as usize + 1;
        let mut tv = vec![0x6a, (2 + n_votes * 33) as u8];
        tv.extend_from_slice(b"TV");
        for _ in 0..n_votes {
            tv.extend_from_slice(&random_hash(rng).0);
            tv.push(if rng.below(2) == 0 { 0x01 } else { 0x02 });
        }
        tx.tx_out.push(out(0, tv));
    }
    tx
}

/// A structurally valid revocation.
fn build_revocation(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let auto = rng.below(2) == 0;
    let mut tx = base_tx(if auto { 2 } else { 1 });
    tx.tx_in.push(TxIn {
        previous_out_point: OutPoint {
            hash: random_hash(rng),
            index: 0,
            tree: 1,
        },
        sequence: 0xffff_ffff,
        value_in: rng.below(1 << 40) as i64,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: if auto { Vec::new() } else { rng.bytes(16) },
    });
    for _ in 0..(rng.below(3) + 1) {
        let addr = random_stake_addr(rng, params);
        let (_, payout) = addr.pay_revoke_commitment_script().expect("stake address");
        tx.tx_out.push(out(rng.below(1 << 39) as i64, payout));
    }
    tx
}

/// A treasury add, spend, or base template.
fn build_treasury(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let mut tx = base_tx(3);
    match rng.below(3) {
        // TAdd.
        0 => {
            tx.tx_in.push(funding_input(rng));
            tx.tx_out.push(out(rng.below(1 << 40) as i64, vec![0xc1]));
            if rng.below(2) == 0 {
                let addr = random_stake_addr(rng, params);
                let (_, change) = addr.stake_change_script().expect("stake address");
                tx.tx_out.push(out(rng.below(1 << 30) as i64, change));
            }
        }
        // TSpend.
        1 => {
            let mut sig_script = Vec::with_capacity(100);
            sig_script.push(0x40); // OP_DATA_64
            sig_script.extend(core::iter::repeat_n(0x11u8, 64));
            sig_script.push(0x21); // OP_DATA_33
            sig_script.push(if rng.below(2) == 0 { 0x02 } else { 0x03 });
            sig_script.extend(core::iter::repeat_n(0x22u8, 32));
            sig_script.push(0xc2); // OP_TSPEND
            tx.tx_in.push(TxIn {
                previous_out_point: OutPoint {
                    hash: Hash::ZERO,
                    index: u32::MAX,
                    tree: 0,
                },
                sequence: 0xffff_ffff,
                value_in: rng.below(1 << 40) as i64,
                block_height: 0,
                block_index: 0xffff_ffff,
                signature_script: sig_script,
            });
            // OP_RETURN <32-byte random>.
            let mut opret = vec![0x6a, 0x20];
            opret.extend_from_slice(&random_hash(rng).0);
            tx.tx_out.push(out(0, opret));
            for _ in 0..(rng.below(2) + 1) {
                let addr = random_stake_addr(rng, params);
                let (_, payout) = addr.pay_from_treasury_script().expect("stake address");
                tx.tx_out.push(out(rng.below(1 << 39) as i64, payout));
            }
        }
        // Treasury base.
        _ => {
            tx.tx_in.push(stakebase_input());
            tx.tx_out.push(out(rng.below(1 << 40) as i64, vec![0xc1]));
            let mut opret = vec![0x6a, 0x0c];
            opret.extend_from_slice(&(rng.below(1 << 20) as u32).to_le_bytes());
            opret.extend_from_slice(&rng.next_u64().to_le_bytes());
            tx.tx_out.push(out(0, opret));
        }
    }
    tx
}

/// Mutate a transaction to probe classification boundaries.
fn mutate(rng: &mut SplitMix64, tx: &mut MsgTx) {
    match rng.below(8) {
        0 => tx.version = rng.below(5) as u16,
        1 => {
            if !tx.tx_out.is_empty() {
                let i = rng.below(tx.tx_out.len() as u64) as usize;
                if !tx.tx_out[i].pk_script.is_empty() {
                    let j = rng.below(tx.tx_out[i].pk_script.len() as u64) as usize;
                    tx.tx_out[i].pk_script[j] ^= 1 << rng.below(8);
                }
            }
        }
        2 => {
            if !tx.tx_out.is_empty() {
                let i = rng.below(tx.tx_out.len() as u64) as usize;
                tx.tx_out[i].version = rng.below(3) as u16;
            }
        }
        3 => {
            if tx.tx_out.len() > 1 {
                tx.tx_out.pop();
            }
        }
        4 => {
            let extra = tx
                .tx_out
                .first()
                .cloned()
                .unwrap_or_else(|| out(0, vec![0x51]));
            tx.tx_out.push(extra);
        }
        5 => {
            if !tx.tx_in.is_empty() {
                let i = rng.below(tx.tx_in.len() as u64) as usize;
                tx.tx_in[i].previous_out_point.tree = (rng.below(3) as i8) - 1;
            }
        }
        6 => {
            if !tx.tx_in.is_empty() {
                let i = rng.below(tx.tx_in.len() as u64) as usize;
                tx.tx_in[i].previous_out_point.index = rng.below(4) as u32;
            }
        }
        _ => {
            if !tx.tx_out.is_empty() {
                let i = rng.below(tx.tx_out.len() as u64) as usize;
                let cut = rng.below(tx.tx_out[i].pk_script.len() as u64 + 1) as usize;
                tx.tx_out[i].pk_script.truncate(cut);
            }
        }
    }
}

#[test]
fn stake_classification_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stake-classify-differential");
    let params = mainnet_params();

    const ROUNDS: usize = 600;
    for round in 0..ROUNDS {
        let mut tx = match rng.below(5) {
            0 => build_ticket(&mut rng, &params),
            1 => build_vote(&mut rng, &params),
            2 => build_revocation(&mut rng, &params),
            3 => build_treasury(&mut rng, &params),
            _ => {
                // Random garbage transaction.
                let mut tx = base_tx(rng.below(4) as u16);
                for _ in 0..(rng.below(3) + 1) {
                    tx.tx_in.push(funding_input(&mut rng));
                }
                for _ in 0..(rng.below(4) + 1) {
                    tx.tx_out
                        .push(out(rng.below(1 << 40) as i64, rng.bytes(48)));
                }
                tx
            }
        };
        // Mutate half of the structured transactions.
        if rng.below(2) == 0 {
            mutate(&mut rng, &mut tx);
        }
        if tx.tx_in.is_empty() || tx.tx_out.is_empty() {
            continue; // Wire-level sanity elsewhere; the checks index freely.
        }

        let ours = analyze_ours(&tx);
        let theirs = analyze_theirs(&mut oracle, &tx);
        assert_eq!(
            ours,
            theirs,
            "stake analyze divergence at round {round}: tx={}",
            hex(&tx.serialize())
        );
    }
}

#[test]
fn lottery_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stake-lottery-differential");

    const ROUNDS: usize = 200;
    for round in 0..ROUNDS {
        let seed = rng.bytes(64);
        let n_rand = rng.below(64) as usize + 1;
        let pool_size = rng.below(8192) as u32 + 1;
        let winners = (rng.below(6) + 1).min(u64::from(pool_size)) as u16;

        // Ours.
        let mut w = String::new();
        w.push_str(&format!("iv={}\n", stake::calc_hash256_prng_iv(&seed)));
        let mut prng = stake::Hash256Prng::new(&seed);
        for _ in 0..n_rand {
            w.push_str(&format!("rand={}\n", prng.hash256_rand()));
        }
        w.push_str(&format!("state={}\n", prng.state_hash()));
        let mut prng2 = stake::Hash256Prng::new(&seed);
        let picked = stake::find_ticket_idxs(pool_size as usize, winners, &mut prng2)
            .expect("winners <= pool size");
        for idx in &picked {
            w.push_str(&format!("winner={idx}\n"));
        }
        w.push_str(&format!("winstate={}\n", prng2.state_hash()));

        // Theirs.
        let mut req = Vec::new();
        req.extend_from_slice(&(n_rand as u16).to_be_bytes());
        req.extend_from_slice(&pool_size.to_be_bytes());
        req.extend_from_slice(&winners.to_be_bytes());
        req.extend_from_slice(&seed);
        let theirs = oracle.call_ok("stake_lottery", &req);
        let theirs = String::from_utf8(unhex(&theirs)).expect("dump is UTF-8");

        assert_eq!(
            w,
            theirs,
            "lottery divergence at round {round}: seed={}",
            hex(&seed)
        );
    }
}

#[test]
fn rewards_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stake-rewards-differential");

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        let n = rng.below(5) as usize + 1;
        let contribs: Vec<i64> = (0..n)
            .map(|_| match rng.below(4) {
                0 => 1,
                1 => rng.below(1 << 20) as i64 + 1,
                _ => rng.below(1 << 44) as i64 + 1,
            })
            .collect();
        let total: i64 = contribs.iter().sum();
        // Purchase near total contributions to exercise remainders.
        let purchase = (total - rng.below(64) as i64).max(1);
        let subsidy = rng.below(1 << 30) as i64;
        let mode = rng.below(3) as u8;
        let prev_header = rng.bytes(180);

        let ours = match mode {
            0 => stake::calculate_rewards(&contribs, purchase, subsidy),
            1 => stake::calculate_revocation_rewards(&contribs, purchase, &prev_header, false),
            _ => stake::calculate_revocation_rewards(&contribs, purchase, &prev_header, true),
        };
        let ours_text: String = ours.iter().map(|a| format!("{a}\n")).collect();

        let mut req = Vec::new();
        req.push(mode);
        req.extend_from_slice(&(purchase as u64).to_be_bytes());
        req.extend_from_slice(&(subsidy as u64).to_be_bytes());
        req.push(n as u8);
        for c in &contribs {
            req.extend_from_slice(&(*c as u64).to_be_bytes());
        }
        req.extend_from_slice(&prev_header);
        let theirs = oracle.call_ok("stake_calc_rewards", &req);
        let theirs = String::from_utf8(unhex(&theirs)).expect("dump is UTF-8");

        assert_eq!(
            ours_text, theirs,
            "rewards divergence at round {round}: mode={mode} purchase={purchase} \
             subsidy={subsidy} contribs={contribs:?}"
        );
    }
}

#[test]
fn create_revocation_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stake-revocation-differential");
    let params = mainnet_params();

    const ROUNDS: usize = 200;
    for round in 0..ROUNDS {
        // Build a valid ticket and derive a revocation from it on both
        // sides.
        let ticket = build_ticket(&mut rng, &params);
        let ticket_hash = random_hash(&mut rng);
        let auto = rng.below(2) == 0;
        let version: u16 = if auto {
            2
        } else {
            [1u16, 2, 3][rng.below(3) as usize]
        };
        let fee: i64 = if auto {
            0
        } else {
            [0i64, 1, 1 << 10, 1 << 24][rng.below(4) as usize]
        };
        let prev_header = rng.bytes(180);

        let min_outs = stake::convert_to_minimal_outputs(&ticket);
        let ours = stake::create_revocation_from_ticket(
            &ticket_hash,
            &min_outs,
            fee,
            version,
            &params,
            &prev_header,
            auto,
        );

        let mut req = Vec::new();
        let net = "mainnet";
        req.push(net.len() as u8);
        req.extend_from_slice(net.as_bytes());
        req.extend_from_slice(&(fee as u64).to_be_bytes());
        req.extend_from_slice(&version.to_be_bytes());
        req.push(u8::from(auto));
        req.extend_from_slice(&ticket_hash.0);
        req.extend_from_slice(&(prev_header.len() as u16).to_be_bytes());
        req.extend_from_slice(&prev_header);
        req.extend_from_slice(&ticket.serialize());
        let resp = oracle.call("stake_create_revocation", &req);

        match (&ours, resp["result"].as_str(), resp["kind"].as_str()) {
            (Ok(tx), Some(their_hex), _) => {
                assert_eq!(
                    hex(&tx.serialize()),
                    their_hex,
                    "revocation divergence at round {round}"
                );
            }
            (Err(e), None, Some(kind)) => {
                assert_eq!(
                    e.kind.kind_name(),
                    kind,
                    "revocation error kind divergence at round {round}"
                );
            }
            (ours, result, kind) => panic!(
                "revocation verdict divergence at round {round}: ours={ours:?} \
                 result={result:?} kind={kind:?}"
            ),
        }
    }
}

/// dcrd 2.2's treasurybase failure precedence: the null-outpoint
/// check runs before the output checks, so a transaction that is
/// defective in both ways fails with the outpoint kind (the v2.1.5
/// oracle reported the output kind for the same transaction).
#[test]
fn treasurybase_null_outpoint_precedence() {
    // Version-3 transaction: one input with a NON-null outpoint and
    // an empty signature script, plus a valid OP_TADD first output
    // and a WRONG-LENGTH second output.
    let mut tx = MsgTx {
        version: 3,
        ..MsgTx::default()
    };
    tx.tx_in.push(TxIn {
        previous_out_point: OutPoint {
            hash: Hash([0x57; 32]),
            index: 1,
            tree: 0,
        },
        sequence: 0xffff_ffff,
        value_in: 0,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: Vec::new(),
    });
    tx.tx_out.push(out(1, vec![0xc1])); // OP_TADD
    tx.tx_out.push(out(0, vec![0x6a; 24])); // wrong second output

    let err = stake::check_treasury_base(&tx).expect_err("defective treasurybase");
    assert_eq!(err.kind.kind_name(), "ErrTreasuryBaseInvalid");
    assert!(
        err.description.contains("is not a null outpoint"),
        "unexpected message: {}",
        err.description
    );

    // With the null outpoint fixed, the later output check fires.
    tx.tx_in[0].previous_out_point = OutPoint {
        hash: Hash([0; 32]),
        index: u32::MAX,
        tree: 0,
    };
    let err = stake::check_treasury_base(&tx).expect_err("bad second output");
    assert_eq!(err.kind.kind_name(), "ErrTreasuryBaseInvalidOpcode1");
}
