// SPDX-License-Identifier: ISC
//! The handle on a stake node's missed tickets reads as the list does.
//!
//! [`Node::missed_ticket_set`] hands out the node's immutable missed
//! treap in place of the list dcrd's `MissedTickets` builds, for a
//! holder that may never read it.  This replays dcrd's ticket state
//! vectors (`data/ticketnode_vectors.txt`: 120 connected blocks with
//! misses, revocations and expiries, then 30 disconnects) and checks
//! at every node that each way of reading the handle agrees with the
//! list, and that a handle keeps naming the set of the node it came
//! from while later nodes are built from it.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_stake::ticketnode::{MissedTickets, Node, StakeNodeParams};
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

/// Check every way of reading the node's handle against its list, and
/// return both.
fn check(node: &Node, what: &str) -> (MissedTickets, Vec<Hash>) {
    let want = node.missed_tickets();
    let set = node.missed_ticket_set();
    assert_eq!(set.to_vec(), want, "{what}: the list");
    assert_eq!(set.len(), want.len(), "{what}: the count");
    assert_eq!(set.is_empty(), want.is_empty(), "{what}: emptiness");
    for ticket in &want {
        assert!(set.contains(ticket), "{what}: {ticket} is missed");
        assert!(node.exists_missed_ticket(ticket), "{what}: {ticket}");
    }
    // A ticket is in one set at a time, so the other two sets hold
    // only tickets that are not missed.
    for ticket in node.live_tickets().iter().chain(&node.revoked_tickets()) {
        assert!(!set.contains(ticket), "{what}: {ticket} is not missed");
    }
    assert!(
        !set.contains(&Hash([0xa5; 32])),
        "{what}: an unknown ticket"
    );
    assert_eq!(format!("{set:?}"), format!("{want:?}"), "{what}: debug");
    assert_eq!(format!("{set:#?}"), format!("{want:#?}"), "{what}: pretty");
    (set, want)
}

#[test]
fn the_handle_reads_as_the_missed_ticket_list_at_every_node() {
    let empty = MissedTickets::default();
    assert!(empty.is_empty(), "the default handle is the empty set");
    assert_eq!(empty.to_vec(), Vec::<Hash>::new());
    assert_eq!(format!("{empty:?}"), "[]");

    let data = include_str!("data/ticketnode_vectors.txt");
    let mut node = Node::genesis(PARAMS);
    // Per-height history for the disconnect phase, as the vector
    // replay keeps it.
    let mut ivs: Vec<Hash> = vec![Hash([0u8; 32])];
    let mut news: Vec<Vec<Hash>> = vec![Vec::new()];
    let mut nodes: Vec<Node> = vec![node.clone()];

    // The handle of every node, with the list it read as then.
    let mut held = vec![check(&node, "genesis")];
    let mut largest = 0;
    let mut changed_by_connect = 0;
    let mut changed_by_disconnect = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let before = node.missed_tickets();
        match f[0] {
            "blk" => {
                let iv = parse_hash(f[2]);
                let new_tickets = parse_hashes(f[5]);
                node = node
                    .connect(iv, &parse_hashes(f[3]), &parse_hashes(f[4]), &new_tickets)
                    .unwrap_or_else(|e| panic!("{line}: connect failed: {e:?}"));
                ivs.push(iv);
                news.push(new_tickets);
                nodes.push(node.clone());
                changed_by_connect += usize::from(node.missed_tickets() != before);
            }
            "undo" => {
                let h: usize = f[1].parse().expect("height");
                node = node
                    .disconnect(ivs[h - 1], nodes[h - 1].undo_data(), &news[h - 1])
                    .unwrap_or_else(|e| panic!("{line}: disconnect failed: {e:?}"));
                ivs.truncate(h);
                news.truncate(h);
                nodes.truncate(h);
                changed_by_disconnect += usize::from(node.missed_tickets() != before);
            }
            _ => continue,
        }
        let (set, list) = check(&node, line.get(..24).unwrap_or(line));
        largest = largest.max(list.len());
        held.push((set, list));
    }
    assert_eq!(held.len(), 1 + 120 + 30, "one node per vector step");
    // The vectors must exercise what the checks above claim to hold.
    assert!(largest >= 8, "the order needs a long list, got {largest}");
    assert!(changed_by_connect >= 20, "got {changed_by_connect}");
    assert!(changed_by_disconnect >= 10, "got {changed_by_disconnect}");

    // The treap is persistent: every transition above built new ones
    // and left each handle naming the set of its own node.
    for (i, (set, list)) in held.iter().enumerate() {
        assert_eq!(&set.to_vec(), list, "the handle of step {i} changed");
    }
}
