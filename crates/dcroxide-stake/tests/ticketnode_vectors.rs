// SPDX-License-Identifier: ISC
//! Replay of dcrd's ticket pool state machine generated inside dcrd's
//! blockchain/stake package (`data/ticketnode_vectors.txt`): 120
//! connected blocks of ticket purchases, votes with misses,
//! revocations, and expiries over a small synthetic parameter set,
//! followed by 30 disconnects, comparing the pool size, lottery final
//! state, next winners, missed/revoked counts, and full undo data at
//! every step, plus the connect error kinds.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_stake::ticketdb::UndoTicketData;
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
use dcroxide_testutil::unhex;

const PARAMS: StakeNodeParams = StakeNodeParams {
    votes_per_block: 5,
    stake_validation_begin_height: 24,
    stake_enable_height: 8,
    ticket_expiry_blocks: 40,
};

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

fn parse_undo(s: &str) -> Vec<UndoTicketData> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',')
        .map(|row| {
            let mut it = row.split(':');
            let hash = parse_hash(it.next().expect("hash"));
            let height: u32 = it.next().expect("height").parse().expect("height");
            let flags: u8 = it.next().expect("flags").parse().expect("flags");
            UndoTicketData {
                ticket_hash: hash,
                ticket_height: height,
                missed: flags & 1 != 0,
                revoked: flags & 2 != 0,
                spent: flags & 4 != 0,
                expired: flags & 8 != 0,
            }
        })
        .collect()
}

fn check_state(node: &Node, f: &[&str], line: &str) {
    let height: u32 = f[1].parse().expect("height");
    let pool_size: usize = f[2].parse().expect("poolsize");
    let final_state = unhex(f[3]);
    let winners = parse_hashes(f[4]);
    let missed: usize = f[5].parse().expect("missed");
    let revoked: usize = f[6].parse().expect("revoked");
    let undo = parse_undo(f[7]);

    assert_eq!(node.height(), height, "{line}: height");
    assert_eq!(node.pool_size(), pool_size, "{line}: pool size");
    assert_eq!(
        &node.final_state()[..],
        &final_state[..],
        "{line}: final state"
    );
    assert_eq!(node.winners(), winners, "{line}: winners");
    assert_eq!(node.missed_tickets().len(), missed, "{line}: missed count");
    assert_eq!(
        node.revoked_tickets().len(),
        revoked,
        "{line}: revoked count"
    );
    assert_eq!(node.undo_data(), undo, "{line}: undo data");
}

#[test]
fn ticketnode_vectors() {
    let data = include_str!("data/ticketnode_vectors.txt");
    let mut lines = data.lines().peekable();

    let mut node = Node::genesis(PARAMS);
    // Per-height history for the disconnect phase: the block's lottery
    // IV, its new tickets, and the node connected at that height.
    let mut ivs: Vec<Hash> = vec![Hash([0u8; 32])];
    let mut news: Vec<Vec<Hash>> = vec![Vec::new()];
    let mut nodes: Vec<Node> = vec![node.clone()];

    let mut counts = [0usize; 3];
    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "blk" => {
                let iv = parse_hash(f[2]);
                let voted = parse_hashes(f[3]);
                let revoked = parse_hashes(f[4]);
                let new_tickets = parse_hashes(f[5]);
                node = node
                    .connect(iv, &voted, &revoked, &new_tickets)
                    .unwrap_or_else(|e| panic!("{line}: connect failed: {e:?}"));
                ivs.push(iv);
                news.push(new_tickets);
                nodes.push(node.clone());

                let state_line = lines.next().expect("state row after blk");
                let sf: Vec<&str> = state_line.split(' ').collect();
                assert_eq!(sf[0], "state", "expected state row");
                check_state(&node, &sf, state_line);
                counts[0] += 1;
            }
            "err" => {
                let want_kind = f[2];
                let result = match f[1] {
                    "unknownvote" => node.connect(Hash([0x11; 32]), &[Hash([0x22; 32])], &[], &[]),
                    "badrevoke" => node.connect(Hash([0x11; 32]), &[], &[Hash([0x33; 32])], &[]),
                    "dupticket" => {
                        let dup = node.live_tickets()[0];
                        node.connect(Hash([0x11; 32]), &[], &[], &[dup])
                    }
                    other => panic!("unknown err case {other}"),
                };
                let err = match result {
                    Ok(_) => panic!("{line}: expected error"),
                    Err(e) => e,
                };
                assert_eq!(err.kind.kind_name(), want_kind, "{line}: kind");
                counts[1] += 1;
            }
            "undo" => {
                let h: usize = f[1].parse().expect("height");
                let parent_iv = ivs[h - 1];
                let parent_utds = nodes[h - 1].undo_data().to_vec();
                let parent_tickets = news[h - 1].clone();
                node = node
                    .disconnect(parent_iv, &parent_utds, &parent_tickets)
                    .unwrap_or_else(|e| panic!("{line}: disconnect failed: {e:?}"));
                // Trim history back to the restored height.
                ivs.truncate(h);
                news.truncate(h);
                nodes.truncate(h);

                let state_line = lines.next().expect("state row after undo");
                let sf: Vec<&str> = state_line.split(' ').collect();
                assert_eq!(sf[0], "state", "expected state row");
                check_state(&node, &sf, state_line);
                counts[2] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [120, 3, 30], "row counts");
}
