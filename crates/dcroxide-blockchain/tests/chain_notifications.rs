// SPDX-License-Identifier: ISC
//! The chain event notifications (dcrd `blockchain.Notification`)
//! observed over the frozen reorganization and block-processing
//! vectors: a recording callback replays the same block sequences the
//! state vectors validate and asserts dcrd's emission order — no
//! reorg events for plain extensions, the started / disconnected /
//! connected / reorganization / done sequence for competing-branch
//! reorgs, new-tickets pairing at and above the stake enabled height,
//! and the post-reorg acceptance events with dcrd's same-block quirk.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::notifications::Notification;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, OutPoint};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

/// A recorded event: the variant name plus the fields the assertions
/// consult.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    NewTipChecked(Hash),
    Accepted {
        block_hash: Hash,
        fork_len: i64,
        best_height: i64,
    },
    Connected {
        block_hash: Hash,
        parent_hash: Hash,
        height: i64,
    },
    Disconnected {
        block_hash: Hash,
        parent_hash: Hash,
    },
    ReorgStarted,
    ReorgDone,
    Reorganization {
        old_height: i64,
        new_height: i64,
        old_hash: Hash,
        new_hash: Hash,
    },
    NewTickets {
        hash: Hash,
        height: i64,
    },
}

/// Install a recording callback on the chain and return the shared
/// event log.
fn record_events(chain: &mut Chain) -> Arc<Mutex<Vec<Event>>> {
    let events: Arc<Mutex<Vec<Event>>> = Arc::default();
    let sink = Arc::clone(&events);
    chain.set_notification_callback(Box::new(move |n| {
        let event = match n {
            Notification::NewTipBlockChecked(block) => {
                Event::NewTipChecked(block.header.block_hash())
            }
            Notification::BlockAccepted(d) => Event::Accepted {
                block_hash: d.block.header.block_hash(),
                fork_len: d.fork_len,
                best_height: d.best_height,
            },
            Notification::BlockConnected(d) => Event::Connected {
                block_hash: d.block.header.block_hash(),
                parent_hash: d.parent_block.header.block_hash(),
                height: i64::from(d.block.header.height),
            },
            Notification::BlockDisconnected(d) => Event::Disconnected {
                block_hash: d.block.header.block_hash(),
                parent_hash: d.parent_block.header.block_hash(),
            },
            Notification::ChainReorgStarted => Event::ReorgStarted,
            Notification::ChainReorgDone => Event::ReorgDone,
            Notification::Reorganization(d) => Event::Reorganization {
                old_height: d.old_height,
                new_height: d.new_height,
                old_hash: d.old_hash,
                new_hash: d.new_hash,
            },
            Notification::NewTickets(d) => Event::NewTickets {
                hash: d.hash,
                height: d.height,
            },
        };
        sink.lock().expect("event log").push(event);
    }));
    events
}

/// Assert the invariants every notification batch obeys, given the
/// tips observed before and after the driving call.
fn check_batch(events: &[Event], old_tip: (Hash, i64), new_tip: (Hash, i64), line: &str) {
    let started = events.iter().filter(|e| *e == &Event::ReorgStarted).count();
    let done = events.iter().filter(|e| *e == &Event::ReorgDone).count();
    let reorgs: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::Reorganization { .. }))
        .collect();
    assert!(started <= 1, "{line}: at most one reorg-started");
    assert_eq!(started, done, "{line}: every started closes with done");

    if started == 0 {
        // A plain extension: nothing may disconnect and no reorg
        // events may fire.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::Disconnected { .. })),
            "{line}: extension must not disconnect"
        );
        assert!(reorgs.is_empty(), "{line}: extension sends no reorg event");
    } else {
        // The started event precedes every other event, and done is
        // last.
        assert_eq!(events.first(), Some(&Event::ReorgStarted), "{line}");
        assert_eq!(events.last(), Some(&Event::ReorgDone), "{line}");
        // The reorganization event carries the observed tip movement.
        if new_tip != old_tip {
            assert_eq!(reorgs.len(), 1, "{line}: one reorganization event");
            let Event::Reorganization {
                old_height,
                new_height,
                old_hash,
                new_hash,
            } = reorgs[0]
            else {
                unreachable!()
            };
            assert_eq!((*old_hash, *old_height), old_tip, "{line}: old tip");
            assert_eq!((*new_hash, *new_height), new_tip, "{line}: new tip");
        } else {
            assert!(reorgs.is_empty(), "{line}: unmoved tip sends no event");
        }
        // Disconnections precede connections within the batch.
        let last_disconnect = events
            .iter()
            .rposition(|e| matches!(e, Event::Disconnected { .. }));
        let first_connect = events
            .iter()
            .position(|e| matches!(e, Event::Connected { .. }));
        if let (Some(d), Some(c)) = (last_disconnect, first_connect) {
            assert!(d < c, "{line}: disconnects come before connects");
        }
    }

    // Connected heights strictly ascend and every connect at or above
    // the stake enabled height is immediately followed by its
    // new-tickets event.
    let stake_enabled_height = simnet_params().stake_enabled_height;
    let mut last_height = i64::MIN;
    for (i, event) in events.iter().enumerate() {
        if let Event::Connected {
            block_hash, height, ..
        } = event
        {
            assert!(*height > last_height, "{line}: connect heights ascend");
            last_height = *height;
            if *height >= stake_enabled_height {
                assert_eq!(
                    events.get(i + 1),
                    Some(&Event::NewTickets {
                        hash: *block_hash,
                        height: *height,
                    }),
                    "{line}: new tickets pair with the connect"
                );
            }
        }
    }
}

/// The tip hash and height, or the zero sentinel for an empty chain.
fn tip_of(chain: &Chain) -> (Hash, i64) {
    (chain.state_snapshot.hash, chain.state_snapshot.height)
}

#[test]
fn reorg_vectors_emit_dcrds_notification_sequence() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let events = record_events(&mut chain);
    let data = include_str!("data/reorg_vectors.txt");
    let now: i64 = 2_000_000_000;
    let mut reorg_batches = 0usize;
    let mut saw_competing_reorg = false;
    let mut saw_extension = false;

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                let key = (
                    parse_hash(f[1]).0,
                    f[2].parse::<u32>().expect("idx"),
                    f[3].parse::<i8>().expect("tree"),
                );
                let mut entry = UtxoEntry::new(
                    f[4].parse().expect("amt"),
                    unhex(f[9]),
                    f[5].parse().expect("h"),
                    f[6].parse().expect("bi"),
                    f[7].parse().expect("sv"),
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                entry.set_packed_flags_bits(f[8].parse().expect("fl"));
                let mut seed_view = UtxoView::new();
                let op = OutPoint {
                    hash: Hash(key.0),
                    index: key.1,
                    tree: key.2,
                };
                entry.set_state_bits(1);
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                {
                    let node = chain.store.node_mut(id);
                    node.status =
                        BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
                    node.is_fully_linked = true;
                }
                chain.index.add_node(&chain.store, id);
                chain.index.add_best_chain_candidate(id);
                chain.blocks.insert(block.header.block_hash().0, block);
            }
            "reorg" => {
                let target = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("target node");
                let old_tip = tip_of(&chain);
                let errs = chain.reorganize_chain(Some(target), now, &params);
                assert!(errs.is_empty() == (f[2] == "ok"), "{line}");
                let new_tip = tip_of(&chain);

                let batch: Vec<Event> = core::mem::take(&mut *events.lock().expect("event log"));
                // The reorganization path never emits acceptance or
                // new-tip events; those belong to process_block.
                assert!(
                    !batch
                        .iter()
                        .any(|e| matches!(e, Event::Accepted { .. } | Event::NewTipChecked(_))),
                    "{line}: no acceptance events from reorganize_chain"
                );
                check_batch(&batch, old_tip, new_tip, line);
                if batch.first() == Some(&Event::ReorgStarted) {
                    saw_competing_reorg = true;
                    assert!(
                        batch
                            .iter()
                            .any(|e| matches!(e, Event::Disconnected { .. })),
                        "{line}: a competing-branch reorg disconnects"
                    );
                } else if batch.iter().any(|e| matches!(e, Event::Connected { .. })) {
                    saw_extension = true;
                }
                reorg_batches += 1;
            }
            _ => {}
        }
    }

    assert!(reorg_batches >= 4, "the vectors drive several reorgs");
    assert!(saw_competing_reorg, "a competing-branch reorg was covered");
    assert!(saw_extension, "a plain extension was covered");
}

#[test]
fn process_block_emits_acceptance_events_after_the_reorg() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let events = record_events(&mut chain);
    let data = include_str!("data/processblock_vectors.txt");
    let now: i64 = 2_000_000_000;
    let mut saw_multi_accept = false;

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                let op = OutPoint {
                    hash: parse_hash(f[1]),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
                };
                let mut entry = UtxoEntry::new(
                    f[4].parse().expect("amt"),
                    unhex(f[9]),
                    f[5].parse().expect("h"),
                    f[6].parse().expect("bi"),
                    f[7].parse().expect("sv"),
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                entry.set_packed_flags_bits(f[8].parse().expect("fl"));
                let mut seed_view = UtxoView::new();
                entry.set_state_bits(1);
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
            }
            "bulk" => {
                chain.bulk_import_mode = f[1] == "1";
            }
            "hdr" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let _ = chain.process_block_header(&header, now, &params);
            }
            "pb" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let block_hash = block.header.block_hash();
                let _ = chain.process_block(&block, now, &params);
                let new_tip = tip_of(&chain);

                let batch: Vec<Event> = core::mem::take(&mut *events.lock().expect("event log"));
                let accepted: Vec<&Event> = batch
                    .iter()
                    .filter(|e| matches!(e, Event::Accepted { .. }))
                    .collect();
                for event in &accepted {
                    let Event::Accepted {
                        block_hash: accepted_hash,
                        fork_len,
                        best_height,
                    } = event
                    else {
                        unreachable!()
                    };
                    // dcrd sends the PROCESSED block for every
                    // accepted node, even when out-of-order delivery
                    // links several at once (the quirk is kept), with
                    // the post-reorg best height.
                    assert_eq!(*accepted_hash, block_hash, "{line}: same-block quirk");
                    assert_eq!(*best_height, new_tip.1, "{line}: post-reorg best height");
                    assert!(*fork_len >= 0, "{line}");
                }
                if accepted.len() > 1 {
                    saw_multi_accept = true;
                }
                // Acceptance events come after every connect of the
                // batch (dcrd notifies relative to the final chain).
                if let (Some(last_connect), Some(first_accept)) = (
                    batch
                        .iter()
                        .rposition(|e| matches!(e, Event::Connected { .. })),
                    batch
                        .iter()
                        .position(|e| matches!(e, Event::Accepted { .. })),
                ) {
                    assert!(last_connect < first_accept, "{line}: accept after connect");
                }
                // The crafted chain sits far in the past, so the
                // chain never believes it is current and the early
                // new-tip event stays silent, like dcrd's run.
                assert!(
                    !batch.iter().any(|e| matches!(e, Event::NewTipChecked(_))),
                    "{line}: not current, no new-tip event"
                );
            }
            _ => {}
        }
    }

    assert!(
        saw_multi_accept,
        "the out-of-order delivery links several nodes in one call"
    );
}
