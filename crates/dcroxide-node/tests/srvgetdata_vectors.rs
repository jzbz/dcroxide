// SPDX-License-Identifier: ISC
//! Replay of frozen server getblocks and getheaders vectors generated
//! by an in-package dump that built a real regnet chain from dcrd's
//! own fullblocktests generator and drove dcrd's real OnGetBlocks and
//! OnGetHeaders over a live piped serverPeer at release-v2.1.5.  The
//! chain queries (LocateBlocks/LocateHeaders/ChainWork) are pinned
//! separately; the rows freeze their outputs as inputs and this
//! replay checks the server-specific wrapping — the known-inventory
//! filter and the continue-hash for getblocks, and the
//! empty-headers-on-low-work gate for getheaders — reproduces dcrd's
//! peer-visible response.  The block hashes differ per generation
//! (the generator stamps timestamps), so each row is self-contained.

// Index arithmetic over pinned vector rows and hex parsing.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_node::server::{
    GetBlocksResponse, GetHeadersResponse, build_get_blocks_response, build_get_headers_response,
};
use dcroxide_wire::{BlockHeader, InvType, InvVect};

const VECTORS: &str = include_str!("data/srvgetdata_vectors.txt");

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn parse_hash(s: &str) -> Hash {
    let bytes = hex_decode(s);
    // dcrd prints hashes in reverse byte order.
    let mut h = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        h[i] = *b;
    }
    Hash(h)
}

/// A placeholder block header; the getheaders wrapping decision is
/// opaque to header contents and only carries the located count.
fn zero_header() -> BlockHeader {
    BlockHeader {
        version: 0,
        prev_block: Hash([0u8; 32]),
        merkle_root: Hash([0u8; 32]),
        stake_root: Hash([0u8; 32]),
        vote_bits: 0,
        final_state: [0u8; 6],
        voters: 0,
        fresh_stake: 0,
        revocations: 0,
        pool_size: 0,
        bits: 0,
        sbits: 0,
        height: 0,
        size: 0,
        timestamp: 0,
        nonce: 0,
        extra_data: [0u8; 32],
        stake_version: 0,
    }
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

fn block_inv(hashes: &[Hash]) -> Vec<InvVect> {
    hashes
        .iter()
        .map(|h| InvVect {
            inv_type: InvType::BLOCK,
            hash: *h,
        })
        .collect()
}

#[test]
fn server_getblocks_matches_dcrd() {
    for line in VECTORS.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f[0] != "gb" {
            continue;
        }
        let name = f[1];
        let located = parse_hashes(f[2]);
        let known = parse_hashes(f[3]);
        let sent = parse_hashes(f[4]);
        let continue_hash = if f[5] == "none" {
            None
        } else {
            Some(parse_hash(f[5]))
        };

        let known_set: std::collections::HashSet<Hash> = known.iter().copied().collect();
        let out = build_get_blocks_response(&located, |iv| known_set.contains(&iv.hash));

        let want = GetBlocksResponse {
            inv: block_inv(&sent),
            continue_hash,
        };
        assert_eq!(out, want, "gb row {name}");
    }
}

#[test]
fn server_getheaders_matches_dcrd() {
    for line in VECTORS.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f[0] != "gh" {
            continue;
        }
        let name = f[1];
        let located_count: usize = f[2].parse().unwrap();
        let chain_work_errored: bool = f[3].parse().unwrap();
        let below_min: bool = f[4].parse().unwrap();
        let sent_count: usize = f[5].parse().unwrap();
        let sent_empty: bool = f[6].parse().unwrap();

        // The located headers are opaque to the wrapping decision; a
        // vector of the right length reproduces the observable count.
        let located: Vec<BlockHeader> = (0..located_count).map(|_| zero_header()).collect();
        let out = build_get_headers_response(chain_work_errored, below_min, located);

        match out {
            GetHeadersResponse::Empty => {
                assert!(sent_empty, "gh row {name}: expected non-empty");
                assert_eq!(sent_count, 0, "gh row {name}");
            }
            GetHeadersResponse::Headers(headers) => {
                assert_eq!(headers.len(), sent_count, "gh row {name}");
                assert_eq!(headers.is_empty(), sent_empty, "gh row {name}");
            }
        }
    }
}

/// The continue hash is set when the response fills an entire message;
/// fullblocktests does not reach a 500-block response, so this pins
/// that branch directly.
#[test]
fn getblocks_continue_hash_on_full_message() {
    let located: Vec<Hash> = (0..dcroxide_node::server::MAX_BLOCKS_PER_MSG)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = (i >> 8) as u8;
            Hash(h)
        })
        .collect();
    let out = build_get_blocks_response(&located, |_| false);
    assert_eq!(out.inv.len(), dcroxide_node::server::MAX_BLOCKS_PER_MSG);
    assert_eq!(out.continue_hash, Some(located[located.len() - 1]));
}
