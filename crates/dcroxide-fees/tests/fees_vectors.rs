// SPDX-License-Identifier: ISC
//! Replay of dcrd's fee estimator behavior generated inside dcrd's
//! internal/fees package (`data/fees_vectors.txt`): bucket bound
//! generation including the extra bucket insertion, mempool tracking
//! with the integer-division rate downsampling, the tspend and
//! below-minimum exclusions, mined transaction processing across
//! confirmation ranges and height gaps, stale block rejection, decay
//! over empty blocks, and the estimate surface with every error kind
//! — comparing estimates, raw median fees, and complete bucket
//! state snapshots bit for bit through the database row codec.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_fees::{EstimateFeeError, Estimator, EstimatorConfig, serialize_bucket};
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

fn tx_type(v: &str) -> TxType {
    match v {
        "0" => TxType::Regular,
        "1" => TxType::SStx,
        "2" => TxType::SSGen,
        "3" => TxType::SSRtx,
        "4" => TxType::TAdd,
        "5" => TxType::TSpend,
        "6" => TxType::TreasuryBase,
        other => panic!("unknown tx type {other}"),
    }
}

fn err_name(err: &EstimateFeeError) -> &'static str {
    match err {
        EstimateFeeError::NonPositiveTarget => "nonpos",
        EstimateFeeError::TargetConfTooLarge { .. } => "toolarge",
        EstimateFeeError::NoSuccessPctBucketFound => "nopct",
        EstimateFeeError::NotEnoughTxsForEstimate => "notenough",
    }
}

#[test]
fn fees_vectors() {
    let data = include_str!("data/fees_vectors.txt");
    let mut estimator: Option<Estimator> = None;
    let mut max_confirms = 0u32;
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "cfg" => {
                // cfg <maxconf> <minfee> <maxfee> <extrafee> <stepbits>
                max_confirms = f[1].parse().expect("max confirms");
                let cfg = EstimatorConfig {
                    max_confirms,
                    min_bucket_fee: f[2].parse().expect("min fee"),
                    max_bucket_fee: f[3].parse().expect("max fee"),
                    extra_bucket_fee: f[4].parse().expect("extra fee"),
                    fee_rate_step: f64::from_bits(
                        u64::from_str_radix(f[5], 16).expect("step bits"),
                    ),
                };
                estimator = Some(Estimator::new(&cfg).expect("estimator"));
            }
            "bounds" => {
                // bounds <bits csv>: the generated bucket fee bounds
                // match dcrd's bit for bit.
                let est = estimator.as_ref().expect("estimator");
                let bounds: Vec<String> = est
                    .bucket_fee_bounds
                    .iter()
                    .map(|b| format!("{:016x}", b.to_bits()))
                    .collect();
                assert_eq!(bounds.join(","), f[1], "{line}");
                counts[0] += 1;
            }
            "enable" => {
                estimator
                    .as_mut()
                    .expect("estimator")
                    .enable(f[1].parse().expect("height"));
            }
            "addmp" => {
                // addmp <hash> <fee> <size> <type>
                estimator
                    .as_mut()
                    .expect("estimator")
                    .add_mem_pool_transaction(
                        &parse_hash(f[1]),
                        f[2].parse().expect("fee"),
                        f[3].parse().expect("size"),
                        tx_type(f[4]),
                    );
                counts[1] += 1;
            }
            "rmmp" => {
                estimator
                    .as_mut()
                    .expect("estimator")
                    .remove_mem_pool_transaction(&parse_hash(f[1]));
            }
            "block" => {
                // block <height> <regularcsv|-> <stakecsv|->
                estimator.as_mut().expect("estimator").process_block(
                    f[1].parse().expect("height"),
                    &parse_hashes(f[2]),
                    &parse_hashes(f[3]),
                );
                counts[2] += 1;
            }
            "est" => {
                // est <target> (ok <amount> | <err>)
                let result = estimator
                    .as_ref()
                    .expect("estimator")
                    .estimate_fee(f[1].parse().expect("target"));
                match result {
                    Ok(amount) => {
                        assert_eq!("ok", f[2], "{line}: unexpected estimate");
                        assert_eq!(amount.to_string(), f[3], "{line}: amount");
                    }
                    Err(err) => {
                        assert_eq!(err_name(&err), f[2], "{line}: error");
                    }
                }
                counts[3] += 1;
            }
            "estm" => {
                // estm <target> <pctbits> (ok <ratebits> | <err>)
                let pct = f64::from_bits(u64::from_str_radix(f[2], 16).expect("pct"));
                let result = estimator
                    .as_ref()
                    .expect("estimator")
                    .estimate_median_fee(f[1].parse().expect("target"), pct);
                match result {
                    Ok(rate) => {
                        assert_eq!("ok", f[3], "{line}: unexpected estimate");
                        assert_eq!(format!("{:016x}", rate.to_bits()), f[4], "{line}: rate");
                    }
                    Err(err) => {
                        assert_eq!(err_name(&err), f[3], "{line}: error");
                    }
                }
                counts[4] += 1;
            }
            "snap" => {
                // snap <nbuckets>: the following row/mrow entries pin
                // every bucket through the database row codec.
                let est = estimator.as_ref().expect("estimator");
                assert_eq!(est.buckets.len().to_string(), f[1], "{line}");
                counts[5] += 1;
            }
            "row" | "mrow" => {
                // row|mrow <idx> <hex>
                let est = estimator.as_ref().expect("estimator");
                let idx: usize = f[1].parse().expect("idx");
                let bucket = if f[0] == "row" {
                    &est.buckets[idx]
                } else {
                    &est.mem_pool[idx]
                };
                assert_eq!(raw_hex(&serialize_bucket(bucket)), f[2], "{line}");
                // The codec round trips.
                let decoded = dcroxide_fees::deserialize_bucket(&unhex(f[2]), max_confirms)
                    .expect("bucket decode");
                assert_eq!(&decoded, bucket, "{line}: round trip");
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [2, 21, 26, 16, 5, 4], "row counts");
}
