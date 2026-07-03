// SPDX-License-Identifier: ISC
//! Differential tests: our MsgTx/BlockHeader codecs vs. dcrd's `wire`
//! package, live.
//!
//! Three angles:
//! - structured: random transactions/headers we encode must decode in dcrd
//!   with identical re-encoding and identical BLAKE-256 hashes;
//! - mutated: random corruptions must produce the same accept/reject verdict
//!   in both implementations (and identical results when both accept);
//! - garbage: fully random buffers, same verdict comparison.

use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_wire::{BlockHeader, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

fn random_hash(rng: &mut SplitMix64) -> dcroxide_chainhash::Hash {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    dcroxide_chainhash::Hash(b)
}

fn random_tx(rng: &mut SplitMix64) -> MsgTx {
    let ser_type = match rng.below(3) {
        0 => TxSerializeType::Full,
        1 => TxSerializeType::NoWitness,
        _ => TxSerializeType::OnlyWitness,
    };
    let n_in = rng.below(5) as usize;
    let n_out = rng.below(5) as usize;
    MsgTx {
        ser_type,
        version: rng.next_u64() as u16,
        tx_in: (0..n_in)
            .map(|_| TxIn {
                previous_out_point: OutPoint {
                    hash: random_hash(rng),
                    index: rng.next_u64() as u32,
                    tree: rng.next_u64() as i8,
                },
                sequence: rng.next_u64() as u32,
                value_in: rng.next_u64() as i64,
                block_height: rng.next_u64() as u32,
                block_index: rng.next_u64() as u32,
                signature_script: rng.bytes(80),
            })
            .collect(),
        tx_out: (0..n_out)
            .map(|_| TxOut {
                value: rng.next_u64() as i64,
                version: rng.next_u64() as u16,
                pk_script: rng.bytes(80),
            })
            .collect(),
        lock_time: rng.next_u64() as u32,
        expiry: rng.next_u64() as u32,
    }
}

fn random_header(rng: &mut SplitMix64) -> BlockHeader {
    let mut final_state = [0u8; 6];
    rng.fill(&mut final_state);
    let mut extra_data = [0u8; 32];
    rng.fill(&mut extra_data);
    BlockHeader {
        version: rng.next_u64() as i32,
        prev_block: random_hash(rng),
        merkle_root: random_hash(rng),
        stake_root: random_hash(rng),
        vote_bits: rng.next_u64() as u16,
        final_state,
        voters: rng.next_u64() as u16,
        fresh_stake: rng.next_u64() as u8,
        revocations: rng.next_u64() as u8,
        pool_size: rng.next_u64() as u32,
        bits: rng.next_u64() as u32,
        sbits: rng.next_u64() as i64,
        height: rng.next_u64() as u32,
        size: rng.next_u64() as u32,
        timestamp: rng.next_u64() as u32,
        nonce: rng.next_u64() as u32,
        extra_data,
        stake_version: rng.next_u64() as u32,
    }
}

/// Both sides decode `bytes` as a MsgTx; verdicts must agree, and on mutual
/// success the oracle's txid/hashes/re-encoding must match ours (computed
/// from *our decoded* transaction, so witness-only field-zeroing semantics
/// are exercised identically).
fn check_tx_bytes(oracle: &mut Oracle, bytes: &[u8], ctx: &str) {
    let ours = MsgTx::from_bytes(bytes);
    let resp = oracle.call("msgtx_decode", bytes);
    match (&ours, resp.get("error").and_then(|e| e.as_str())) {
        (Ok((tx, consumed)), None) => {
            let reencoded = unhex(resp["reencoded"].as_str().expect("reencoded"));
            assert_eq!(tx.serialize(), reencoded, "{ctx}: re-encoding");
            assert_eq!(
                &bytes[..*consumed],
                reencoded.as_slice(),
                "{ctx}: consumed prefix is canonical"
            );
            assert_eq!(
                tx.tx_hash().to_string(),
                resp["txid"].as_str().expect("txid"),
                "{ctx}: txid"
            );
            assert_eq!(
                tx.tx_hash_witness().to_string(),
                resp["witness_hash"].as_str().expect("witness_hash"),
                "{ctx}: witness hash"
            );
            assert_eq!(
                tx.tx_hash_full().to_string(),
                resp["full_hash"].as_str().expect("full_hash"),
                "{ctx}: full hash"
            );
        }
        (Err(_), Some(_)) => {} // both reject: verdict parity (error-kind
        // text mapping is tracked as a later ratchet in PARITY.md)
        (ours, oracle_err) => panic!(
            "{ctx}: verdict mismatch: ours {ours:?}, oracle error {oracle_err:?}, input {}",
            hex(bytes)
        ),
    }
}

#[test]
fn msgtx_structured_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("msgtx structured differential");
    for i in 0..1_500 {
        let tx = random_tx(&mut rng);
        let bytes = tx.serialize();
        check_tx_bytes(&mut oracle, &bytes, &format!("structured case {i}"));
    }
}

#[test]
fn msgtx_mutated_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("msgtx mutation differential");
    for i in 0..3_000 {
        let tx = random_tx(&mut rng);
        let mut bytes = tx.serialize();
        match rng.below(3) {
            // Truncate at a random point.
            0 => {
                let cut = rng.below(bytes.len() as u64 + 1) as usize;
                bytes.truncate(cut);
            }
            // Flip 1–4 random bytes.
            1 => {
                for _ in 0..=rng.below(4) {
                    if bytes.is_empty() {
                        break;
                    }
                    let pos = rng.below(bytes.len() as u64) as usize;
                    bytes[pos] ^= rng.next_u64() as u8;
                }
            }
            // Replace with pure garbage.
            _ => {
                bytes = rng.bytes(200);
            }
        }
        check_tx_bytes(&mut oracle, &bytes, &format!("mutation case {i}"));
    }
}

#[test]
fn blockheader_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("blockheader differential");

    for i in 0..500 {
        let header = random_header(&mut rng);
        let bytes = header.serialize();
        let resp = oracle.call("blockheader_decode", &bytes);
        assert!(
            resp.get("error").is_none(),
            "case {i}: oracle rejected our header encoding: {resp}"
        );
        let reencoded = unhex(resp["reencoded"].as_str().expect("reencoded"));
        assert_eq!(bytes.as_slice(), reencoded.as_slice(), "case {i}: bytes");
        assert_eq!(
            header.block_hash().to_string(),
            resp["block_hash"].as_str().expect("block_hash"),
            "case {i}: block hash"
        );

        // Truncations must be rejected by both sides.
        let cut = rng.below(180) as usize;
        let truncated = &bytes[..cut];
        let ours = BlockHeader::from_bytes(truncated);
        let resp = oracle.call("blockheader_decode", truncated);
        assert!(
            ours.is_err() && resp.get("error").is_some(),
            "case {i}: truncation verdict mismatch at len {cut}: ours {ours:?}, oracle {resp}"
        );
    }
}
