// SPDX-License-Identifier: ISC
//! Replay of dcrd's committed filter serving battery
//! (`data/cfilterserve_vectors.txt`): a real regnet chain built from
//! dcrd's own fullblocktests generator, with dcrd's real
//! FilterByBlockHash and LocateCFiltersV2 exercised directly.  The
//! block bytes are recorded so the chain engine here rebuilds the
//! same chain and serves the same version 2 GCS filters and header
//! commitment inclusion proofs, comparing filter bytes, proof
//! indices, proof hashes, and the ancestor/unknown-block/no-filter
//! error kinds row for row.  The block hashes differ per generation
//! (the generator stamps timestamps), so the block bytes are frozen
//! alongside the expectations.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::MsgBlock;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    // dcrd prints hashes in reverse byte order.
    for (i, b) in bytes.iter().rev().enumerate() {
        h[i] = *b;
    }
    Hash(h)
}

fn proof_csv(hashes: &[Hash]) -> String {
    hashes
        .iter()
        .map(|h| h.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn cfilter_serving_matches_dcrd() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/cfilterserve_vectors.txt");

    // First pass: build the chain from the frozen blocks.
    let mut now: i64 = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split('|').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "block {} rejected: {errs:?}", f[1]);
            }
            _ => {}
        }
    }

    // Second pass: check the serving methods.
    for line in data.lines() {
        let f: Vec<&str> = line.split('|').collect();
        match f[0] {
            "fbh" => {
                // fbh|name|hash|ok|filterhex|proofindex|proofcsv
                //   or fbh|name|hash|err|kind
                let name = f[1];
                let hash = parse_hash(f[2]);
                let out = chain.filter_by_block_hash(&hash);
                if f[3] == "err" {
                    let err = out.unwrap_err();
                    assert_eq!(err.kind.to_string(), f[4], "fbh {name}");
                } else {
                    let (filter, proof) = out.unwrap_or_else(|e| panic!("fbh {name}: {e:?}"));
                    assert_eq!(hex(filter.bytes()), f[4], "fbh {name} filter");
                    assert_eq!(
                        proof.proof_index.to_string(),
                        f[5],
                        "fbh {name} proof index"
                    );
                    assert_eq!(
                        proof_csv(&proof.proof_hashes),
                        f[6],
                        "fbh {name} proof hashes"
                    );
                }
            }
            "lcf" => {
                let name = f[1];
                if f[2] == "err" {
                    // lcf|name|err|kind — reconstruct the start/end from
                    // the matching scenario is not needed; the error is
                    // checked against the known request below.
                    check_locate_error(&chain, name, f[3]);
                } else {
                    // lcf|name|ok|count|f1;f2;...
                    let count: usize = f[3].parse().unwrap();
                    let (start, end) = locate_range(name);
                    let msg = chain
                        .locate_cfilters_v2(&start, &end)
                        .unwrap_or_else(|e| panic!("lcf {name}: {e:?}"));
                    assert_eq!(msg.cfilters.len(), count, "lcf {name} count");
                    let parts: Vec<&str> = if f[4].is_empty() {
                        Vec::new()
                    } else {
                        f[4].split(';').collect()
                    };
                    assert_eq!(parts.len(), count, "lcf {name} parts");
                    for (cf, part) in msg.cfilters.iter().zip(parts) {
                        // blockhash:datahex:proofindex:proofcsv
                        let pf: Vec<&str> = part.splitn(4, ':').collect();
                        assert_eq!(cf.block_hash, parse_hash(pf[0]), "lcf {name} hash");
                        assert_eq!(hex(&cf.data), pf[1], "lcf {name} data");
                        assert_eq!(cf.proof_index.to_string(), pf[2], "lcf {name} proof index");
                        assert_eq!(
                            proof_csv(&cf.proof_hashes),
                            pf[3],
                            "lcf {name} proof hashes"
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// The frozen block hashes the locate scenarios request, resolved from
/// the tip index by height offsets that mirror the dump.
fn locate_range(name: &str) -> (Hash, Hash) {
    // The dump's ranges are expressed against the block heights it
    // processed; recompute them from the vector's own filter rows.
    let data = include_str!("data/cfilterserve_vectors.txt");
    let block_hash = |height: usize| -> Hash {
        let line = data
            .lines()
            .find(|l| l.starts_with(&format!("blk|{height}|")))
            .unwrap();
        let hex_block = line.split('|').nth(2).unwrap();
        let (block, _) = MsgBlock::from_bytes(&unhex(hex_block)).unwrap();
        block.header.block_hash()
    };
    match name {
        "range" => (block_hash(1), block_hash(10)),
        "single" => (block_hash(5), block_hash(5)),
        _ => panic!("unknown locate range {name}"),
    }
}

fn check_locate_error(chain: &Chain, name: &str, kind: &str) {
    let data = include_str!("data/cfilterserve_vectors.txt");
    let block_hash = |height: usize| -> Hash {
        let line = data
            .lines()
            .find(|l| l.starts_with(&format!("blk|{height}|")))
            .unwrap();
        let (block, _) = MsgBlock::from_bytes(&unhex(line.split('|').nth(2).unwrap())).unwrap();
        block.header.block_hash()
    };
    let mut unknown = [0u8; 32];
    unknown[0] = 0xab;
    let unknown = Hash(unknown);
    let (start, end) = match name {
        "unknownstart" => (unknown, block_hash(10)),
        "notancestor" => (block_hash(10), block_hash(5)),
        _ => panic!("unknown locate error scenario {name}"),
    };
    let err = chain.locate_cfilters_v2(&start, &end).unwrap_err();
    assert_eq!(err.kind.to_string(), kind, "lcf {name}");
}
