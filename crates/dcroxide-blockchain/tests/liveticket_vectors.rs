// SPDX-License-Identifier: ISC
//! Replay of dcrd's live-ticket query battery
//! (`data/liveticket_vectors.txt`): a real regnet chain built past the
//! stake validation height from dcrd's own fullblocktests generator,
//! with dcrd's real LiveTickets, CheckLiveTicket, and BestSnapshot
//! exercised directly.  The block bytes are recorded so the chain
//! engine here rebuilds the same chain and queries the same stake
//! state, comparing the full ordered live ticket set, the per-ticket
//! membership checks (live tickets, an unknown hash, and a block
//! hash), and the best snapshot hash and height.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
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

#[test]
fn live_ticket_queries_match_dcrd() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/liveticket_vectors.txt");

    // The blocks carry wall-clock timestamps, so replay against the
    // generation time the dump recorded.
    let now: i64 = data
        .lines()
        .find_map(|l| l.strip_prefix("now|"))
        .expect("now row")
        .parse()
        .unwrap();

    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("blk|") {
            let hex_block = rest.split('|').nth(1).unwrap();
            let (block, _) = MsgBlock::from_bytes(&unhex(hex_block)).expect("block");
            let (_, errs) = chain.process_block(&block, now, &params);
            assert!(errs.is_empty(), "block rejected: {errs:?}");
        }
    }

    for line in data.lines() {
        let f: Vec<&str> = line.split('|').collect();
        match f[0] {
            "bs" => {
                // bs|hash|height
                let snap = chain.best_snapshot();
                assert_eq!(snap.hash, parse_hash(f[1]), "best snapshot hash");
                assert_eq!(snap.height.to_string(), f[2], "best snapshot height");
            }
            "lt" => {
                // lt|count|csv
                let count: usize = f[1].parse().unwrap();
                let want: Vec<Hash> = if f[2].is_empty() {
                    Vec::new()
                } else {
                    f[2].split(',').map(parse_hash).collect()
                };
                assert_eq!(want.len(), count, "live ticket count field");
                let got = chain.live_tickets();
                assert_eq!(got.len(), count, "live ticket count");
                // dcrd's LiveTickets and the port both iterate the live
                // treap in key order, so the full ordered set matches.
                assert_eq!(got, want, "live ticket set");
            }
            "clt" => {
                // clt|name|hash|bool
                let name = f[1];
                let hash = parse_hash(f[2]);
                let want: bool = f[3].parse().unwrap();
                assert_eq!(
                    chain.check_live_ticket(&hash),
                    want,
                    "check_live_ticket {name}"
                );
            }
            _ => {}
        }
    }

    // The batched query mirrors the per-ticket checks.
    let live = chain.live_tickets();
    let mut probes = live.clone();
    let mut unknown = [0u8; 32];
    unknown[0] = 0xef;
    probes.push(Hash(unknown));
    let results = chain.check_live_tickets(&probes);
    assert_eq!(results.len(), probes.len());
    for (i, &r) in results.iter().enumerate() {
        assert_eq!(r, i < live.len(), "check_live_tickets index {i}");
    }
}
