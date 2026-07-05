// SPDX-License-Identifier: ISC
//! Differential tests: our GCS filters vs dcrd's gcs/v4, live through
//! the oracle, over random entry sets and keys for both filter
//! versions (serialization, hashes, and match verdicts), and DCP0005
//! version 2 block filters over structured blocks with real stake
//! transactions and randomized previous-script sets.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_gcs::{FilterV1, FilterV2, blockcf2};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_txscript::stdaddr;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

fn dump(oracle: &mut Oracle, cmd: &str, req: &[u8]) -> String {
    let result = oracle.call_ok(cmd, req);
    String::from_utf8(unhex(&result)).expect("dump is UTF-8")
}

fn random_hash(rng: &mut SplitMix64) -> Hash {
    let mut h = [0u8; 32];
    rng.fill(&mut h);
    Hash(h)
}

#[test]
fn filter_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("gcs-filter-differential");

    const ROUNDS: usize = 250;
    for round in 0..ROUNDS {
        let version = 1 + rng.below(2) as u8;
        let b = rng.below(21) as u8;
        // Keep M within a few doublings of 2^B: the Golomb quotient is
        // unary-coded, so a tiny B with a huge M makes encoding take
        // astronomically long (in dcrd exactly the same way; the
        // pathology is inherent to the parameters, not implementation
        // behavior).
        let m: u64 = match rng.below(3) {
            0 if b >= 13 => blockcf2::M,
            1 => 1u64 << b,
            _ => rng.below(1u64 << (u32::from(b) + 6)) + 1,
        };
        let mut key = [0u8; 16];
        rng.fill(&mut key);

        // Entries, including duplicates and (for v2 skip behavior)
        // empties.
        let n_entries = rng.below(50) as usize;
        let mut entries: Vec<Vec<u8>> = Vec::with_capacity(n_entries);
        for _ in 0..n_entries {
            match rng.below(8) {
                0 => entries.push(Vec::new()),
                1 if !entries.is_empty() => {
                    let i = rng.below(entries.len() as u64) as usize;
                    entries.push(entries[i].clone());
                }
                _ => {
                    let n = rng.below(40) as usize + 1;
                    entries.push(rng.bytes(n));
                }
            }
        }

        // Match candidates: members and non-members, all non-empty
        // (dcrd's MatchAny can index out of range when handed empty
        // entries; see the quirk note on FilterV2::matches_any).
        let n_match = rng.below(12) as usize;
        let mut match_entries: Vec<Vec<u8>> = Vec::with_capacity(n_match);
        for _ in 0..n_match {
            let member: Vec<&Vec<u8>> = entries.iter().filter(|e| !e.is_empty()).collect();
            if !member.is_empty() && rng.below(2) == 0 {
                match_entries.push(member[rng.below(member.len() as u64) as usize].clone());
            } else {
                // Guaranteed non-empty: rng.bytes returns a *random*
                // length up to the cap, and dcrd's MatchAny panics on
                // empty search entries (the quirk documented on
                // matches_any).
                let mut v = vec![0u8; rng.below(40) as usize + 1];
                rng.fill(&mut v);
                match_entries.push(v);
            }
        }

        // Ours.
        let entry_refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        let match_refs: Vec<&[u8]> = match_entries.iter().map(Vec::as_slice).collect();
        let mut ours = String::new();
        match version {
            1 => {
                let f = FilterV1::new(b, key, &entry_refs).expect("b <= 32");
                ours.push_str(&format!("bytes={}\n", hex(f.bytes())));
                ours.push_str(&format!("n={}\n", f.n()));
                ours.push_str(&format!("hash={}\n", f.hash()));
                for entry in &match_refs {
                    ours.push_str(&format!("match={}\n", f.matches(key, entry)));
                }
                ours.push_str(&format!("matchany={}\n", f.matches_any(key, &match_refs)));

                // Serialization round trip through from_bytes.
                let f2 = FilterV1::from_bytes(b, f.bytes()).expect("round trip");
                assert_eq!(f2.n(), f.n(), "round {round}: v1 n");
                assert_eq!(f2.hash(), f.hash(), "round {round}: v1 hash");
            }
            _ => {
                let f = FilterV2::new(b, m, key, &entry_refs).expect("b <= 32");
                ours.push_str(&format!("bytes={}\n", hex(f.bytes())));
                ours.push_str(&format!("n={}\n", f.n()));
                ours.push_str(&format!("hash={}\n", f.hash()));
                for entry in &match_refs {
                    ours.push_str(&format!("match={}\n", f.matches(key, entry)));
                }
                ours.push_str(&format!("matchany={}\n", f.matches_any(key, &match_refs)));

                let f2 = FilterV2::from_bytes(b, m, f.bytes()).expect("round trip");
                assert_eq!(f2.n(), f.n(), "round {round}: v2 n");
                assert_eq!(f2.hash(), f.hash(), "round {round}: v2 hash");
                for entry in &match_refs {
                    assert_eq!(
                        f2.matches(key, entry),
                        f.matches(key, entry),
                        "round {round}: v2 reloaded match"
                    );
                }
            }
        }

        // Theirs.
        let mut req = Vec::new();
        req.push(version);
        req.push(b);
        req.extend_from_slice(&m.to_be_bytes());
        req.extend_from_slice(&key);
        req.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for e in &entries {
            req.extend_from_slice(&(e.len() as u16).to_be_bytes());
            req.extend_from_slice(e);
        }
        req.extend_from_slice(&(match_entries.len() as u32).to_be_bytes());
        for e in &match_entries {
            req.extend_from_slice(&(e.len() as u16).to_be_bytes());
            req.extend_from_slice(e);
        }
        let theirs = dump(&mut oracle, "gcs_filter", &req);

        assert_eq!(
            ours, theirs,
            "gcs filter divergence at round {round}: version={version} b={b} m={m}"
        );
    }
}

// ----------------------------------------------------------------------
// blockcf2 differential.
// ----------------------------------------------------------------------

struct MapPrevScripts(HashMap<(Hash, u32, i8), (u16, Vec<u8>)>);

impl blockcf2::PrevScripter for MapPrevScripts {
    fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])> {
        self.0
            .get(&(out.hash, out.index, out.tree))
            .map(|(v, s)| (*v, s.as_slice()))
    }
}

/// A random previous-output script: standard forms, stake-tagged forms,
/// garbage, empties, nonzero versions, and oversized scripts.
fn random_prev_script(rng: &mut SplitMix64) -> (u16, Vec<u8>) {
    let version = if rng.below(8) == 0 { 1 } else { 0 };
    let script = match rng.below(8) {
        // P2PKH.
        0 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend(rng.bytes(20).iter());
            while s.len() < 23 {
                s.push(0);
            }
            s.truncate(23);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        // Stake-tagged P2PKH (vote/ticket/change/revoke/tgen tags).
        1 | 2 => {
            let tag = [0xba, 0xbb, 0xbc, 0xbd, 0xc3][rng.below(5) as usize];
            let mut s = vec![tag, 0x76, 0xa9, 0x14];
            let h = rng.bytes(20);
            s.extend_from_slice(&h);
            while s.len() < 24 {
                s.push(0);
            }
            s.truncate(24);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        // Empty.
        3 => Vec::new(),
        // Oversized (excluded from the filter).
        4 if rng.below(4) == 0 => vec![0x51; dcroxide_txscript::MAX_SCRIPT_SIZE + 1],
        // Garbage.
        _ => {
            let n = rng.below(40) as usize + 1;
            rng.bytes(n)
        }
    };
    (version, script)
}

fn funding_input(rng: &mut SplitMix64, tree: i8) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: random_hash(rng),
            index: rng.below(4) as u32,
            tree,
        },
        sequence: 0xffff_ffff,
        value_in: rng.below(1 << 40) as i64,
        block_height: 0,
        block_index: 0,
        signature_script: rng.bytes(16),
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

fn random_stake_addr(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> stdaddr::Address {
    let mut hash = [0u8; 20];
    rng.fill(&mut hash);
    if rng.below(2) == 0 {
        stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, params).expect("20 bytes")
    } else {
        stdaddr::new_address_script_hash_v0_from_hash(&hash, params).expect("20 bytes")
    }
}

/// A structurally valid ticket purchase (compact version of the stake
/// differential builder).
fn build_ticket(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let n = rng.below(2) as usize + 1;
    let mut tx = base_tx(1);
    let (_, submission) = random_stake_addr(rng, params)
        .voting_rights_script()
        .expect("stake address");
    tx.tx_out
        .push(out(rng.below(1 << 40) as i64 + 1, submission));
    for _ in 0..n {
        tx.tx_in.push(funding_input(rng, 0));
        let (_, commitment) = random_stake_addr(rng, params)
            .reward_commitment_script(rng.below(1 << 40) as i64 + 1, 0, 0)
            .expect("stake address");
        tx.tx_out.push(out(0, commitment));
        let (_, change) = random_stake_addr(rng, params)
            .stake_change_script()
            .expect("stake address");
        // Sometimes a zero-value change output, which the filter
        // excludes.
        let change_value = if rng.below(3) == 0 {
            0
        } else {
            rng.below(1 << 30) as i64
        };
        tx.tx_out.push(out(change_value, change));
    }
    tx
}

/// A structurally valid vote.
fn build_vote(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let mut tx = base_tx(1);
    tx.tx_in.push(TxIn {
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
    });
    tx.tx_in.push(funding_input(rng, 1));

    let mut reference = vec![0x6a, 0x24];
    reference.extend_from_slice(&random_hash(rng).0);
    reference.extend_from_slice(&(rng.below(1 << 20) as u32).to_le_bytes());
    tx.tx_out.push(out(0, reference));

    let mut votebits = vec![0x6a, 0x02];
    votebits.extend_from_slice(&(rng.next_u64() as u16).to_le_bytes());
    tx.tx_out.push(out(0, votebits));

    for _ in 0..(rng.below(2) + 1) {
        let (_, payout) = random_stake_addr(rng, params)
            .pay_vote_commitment_script()
            .expect("stake address");
        tx.tx_out.push(out(rng.below(1 << 40) as i64, payout));
    }
    tx
}

/// A structurally valid revocation.
fn build_revocation(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let mut tx = base_tx(1);
    tx.tx_in.push(funding_input(rng, 1));
    for _ in 0..(rng.below(2) + 1) {
        let (_, payout) = random_stake_addr(rng, params)
            .pay_revoke_commitment_script()
            .expect("stake address");
        tx.tx_out.push(out(rng.below(1 << 39) as i64, payout));
    }
    tx
}

/// A structurally valid treasury add or spend.
fn build_treasury(rng: &mut SplitMix64, params: &dcroxide_chaincfg::Params) -> MsgTx {
    let mut tx = base_tx(3);
    if rng.below(2) == 0 {
        // TAdd with optional change.
        tx.tx_in.push(funding_input(rng, 0));
        tx.tx_out.push(out(rng.below(1 << 40) as i64, vec![0xc1]));
        if rng.below(2) == 0 {
            let (_, change) = random_stake_addr(rng, params)
                .stake_change_script()
                .expect("stake address");
            let value = if rng.below(3) == 0 {
                0
            } else {
                rng.below(1 << 30) as i64
            };
            tx.tx_out.push(out(value, change));
        }
    } else {
        // TSpend.
        let mut sig_script = Vec::with_capacity(100);
        sig_script.push(0x40);
        sig_script.extend(core::iter::repeat_n(0x11u8, 64));
        sig_script.push(0x21);
        sig_script.push(0x02);
        sig_script.extend(core::iter::repeat_n(0x22u8, 32));
        sig_script.push(0xc2);
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
        let mut opret = vec![0x6a, 0x20];
        opret.extend_from_slice(&random_hash(rng).0);
        tx.tx_out.push(out(0, opret));
        for _ in 0..(rng.below(2) + 1) {
            let (_, payout) = random_stake_addr(rng, params)
                .pay_from_treasury_script()
                .expect("stake address");
            tx.tx_out.push(out(rng.below(1 << 39) as i64, payout));
        }
    }
    tx
}

/// A regular transaction with assorted output scripts.
fn build_regular(rng: &mut SplitMix64, coinbase: bool) -> MsgTx {
    let mut tx = base_tx(1);
    if coinbase {
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
            signature_script: rng.bytes(8),
        });
    } else {
        for _ in 0..(rng.below(3) + 1) {
            let tree = if rng.below(4) == 0 { 1 } else { 0 };
            tx.tx_in.push(funding_input(rng, tree));
        }
    }
    for _ in 0..(rng.below(3) + 1) {
        let (version, script) = random_prev_script(rng);
        let mut tx_out = out(rng.below(1 << 40) as i64, script);
        tx_out.version = version;
        tx.tx_out.push(tx_out);
    }
    tx
}

#[test]
fn blockcf2_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("gcs-blockcf2-differential");
    let params = mainnet_params();

    const ROUNDS: usize = 120;
    for round in 0..ROUNDS {
        // Build the block: a coinbase plus regular txs, plus stake txs.
        let mut raw_header = [0u8; 180];
        rng.fill(&mut raw_header);
        let (mut header, _) = BlockHeader::from_bytes(&raw_header).expect("header");

        let mut transactions = vec![build_regular(&mut rng, true)];
        for _ in 0..rng.below(3) {
            transactions.push(build_regular(&mut rng, false));
        }
        let mut stransactions = Vec::new();
        for _ in 0..rng.below(4) {
            stransactions.push(match rng.below(4) {
                0 => build_ticket(&mut rng, &params),
                1 => build_vote(&mut rng, &params),
                2 => build_revocation(&mut rng, &params),
                _ => build_treasury(&mut rng, &params),
            });
        }
        header.fresh_stake = stransactions.len() as u8;
        let block = MsgBlock {
            header,
            transactions,
            stransactions,
        };

        // Previous scripts for every input in the block; occasionally
        // drop one to exercise the missing-script error.
        let mut prevs: HashMap<(Hash, u32, i8), (u16, Vec<u8>)> = HashMap::new();
        for tx in block
            .transactions
            .iter()
            .skip(1)
            .chain(&block.stransactions)
        {
            for tx_in in &tx.tx_in {
                let op = &tx_in.previous_out_point;
                prevs.insert((op.hash, op.index, op.tree), random_prev_script(&mut rng));
            }
        }
        let drop_one = rng.below(8) == 0 && !prevs.is_empty();
        if drop_one {
            let key = *prevs.keys().next().expect("non-empty");
            prevs.remove(&key);
        }

        // Ours.
        let ours = match blockcf2::regular(&block, &MapPrevScripts(prevs.clone())) {
            Ok(f) => format!(
                "key={}\nbytes={}\nn={}\nhash={}\n",
                hex(&blockcf2::key(&block.header.merkle_root)),
                hex(f.bytes()),
                f.n(),
                f.hash()
            ),
            Err(blockcf2::RegularError::PrevScript(_)) => "prevscripterror".to_string(),
            Err(e) => panic!("unexpected error at round {round}: {e:?}"),
        };

        // Theirs.
        let mut req = Vec::new();
        req.extend_from_slice(&(prevs.len() as u16).to_be_bytes());
        for ((hash, index, tree), (version, script)) in &prevs {
            req.extend_from_slice(&hash.0);
            req.extend_from_slice(&index.to_be_bytes());
            req.push(*tree as u8);
            req.extend_from_slice(&version.to_be_bytes());
            req.extend_from_slice(&(script.len() as u16).to_be_bytes());
            req.extend_from_slice(script);
        }
        req.extend_from_slice(&block.serialize());
        let resp = oracle.call("gcs_blockcf2", &req);
        let theirs = match resp["result"].as_str() {
            Some(result) => String::from_utf8(unhex(result)).expect("dump is UTF-8"),
            None => {
                assert_eq!(
                    resp["kind"].as_str(),
                    Some("PrevScriptError"),
                    "round {round}: unexpected oracle error: {resp}"
                );
                "prevscripterror".to_string()
            }
        };

        assert_eq!(ours, theirs, "blockcf2 divergence at round {round}");
    }
}
