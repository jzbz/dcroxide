// SPDX-License-Identifier: ISC
//! Replay of dcrd's ticket database persistence generated inside
//! dcrd's blockchain/stake package over a real ffldb
//! (`data/stakedb_vectors.txt`): `InitDatabaseState`, sixty connected
//! blocks of ticket purchases, votes with misses, revocations, and
//! expiries written through `WriteConnectedBestNode`, ten disconnects
//! written through `WriteDisconnectedBestNode` (restoring bookkeeping
//! from the database rows exactly like dcrd's nil-undo path), and
//! `LoadBestNode` round trips — comparing every ticket database
//! bucket row byte for byte at checkpoints (the database info
//! creation date is masked since dcrd stamps the wall clock) and the
//! loaded node state including the recomputed lottery final state.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::calc_hash256_prng_iv;
use dcroxide_stake::stakedb::{
    db_fetch_block_undo_data, db_fetch_new_tickets, init_database_state, load_best_node,
    write_connected_best_node, write_disconnected_best_node,
};
use dcroxide_stake::ticketdb::{
    LIVE_TICKETS_BUCKET_NAME, MISSED_TICKETS_BUCKET_NAME, REVOKED_TICKETS_BUCKET_NAME,
    STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, STAKE_CHAIN_STATE_KEY_NAME, STAKE_DB_INFO_BUCKET_NAME,
    TICKETS_IN_BLOCK_BUCKET_NAME,
};
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
use dcroxide_testutil::unhex;
use dcroxide_wire::BlockHeader;
use tempfile::TempDir;

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

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_csv(hashes: &[Hash]) -> String {
    if hashes.is_empty() {
        return "-".to_string();
    }
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

/// Collect every ticket database row exactly like the dump emits
/// them: the five buckets in dcrd's order, the chain state metadata
/// row, and the database info row with the date bytes masked.
fn collect_rows(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    db.view(|tx| {
        let meta = tx.metadata();
        let buckets: [(&str, &[u8]); 5] = [
            ("livetickets", LIVE_TICKETS_BUCKET_NAME),
            ("missedtickets", MISSED_TICKETS_BUCKET_NAME),
            ("revokedtickets", REVOKED_TICKETS_BUCKET_NAME),
            ("stakeblockundo", STAKE_BLOCK_UNDO_DATA_BUCKET_NAME),
            ("ticketsinblock", TICKETS_IN_BLOCK_BUCKET_NAME),
        ];
        for (name, key) in buckets {
            let bucket = meta.bucket(key).expect("bucket");
            bucket.for_each(|k, v| {
                rows.push((name.to_string(), k.to_vec(), v.to_vec()));
                Ok(())
            })?;
        }
        let state = meta.get(STAKE_CHAIN_STATE_KEY_NAME).expect("chain state");
        rows.push((
            "meta".to_string(),
            STAKE_CHAIN_STATE_KEY_NAME.to_vec(),
            state,
        ));
        let info_bucket = meta.bucket(STAKE_DB_INFO_BUCKET_NAME).expect("info bucket");
        let mut info = info_bucket.get(STAKE_DB_INFO_BUCKET_NAME).expect("info");
        for byte in info.iter_mut().take(8).skip(4) {
            *byte = 0;
        }
        rows.push((
            "dbinfo".to_string(),
            STAKE_DB_INFO_BUCKET_NAME.to_vec(),
            info,
        ));
        Ok(())
    })
    .expect("view");
    rows
}

#[test]
fn stakedb_vectors() {
    let params = StakeNodeParams {
        votes_per_block: 5,
        stake_validation_begin_height: 24,
        stake_enable_height: 8,
        ticket_expiry_blocks: 40,
    };
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("sdb"), 0x12141c16);
    let db = Database::create(&opts).expect("create");

    let data = include_str!("data/stakedb_vectors.txt");
    let mut node: Option<Node> = None;
    // Per-height synthetic headers and block hashes.
    let mut infos: Vec<(Vec<u8>, Hash)> = Vec::new();
    let mut counts = [0usize; 5];

    let mut lines = data.lines().peekable();
    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "init" => {
                let genesis_hash = parse_hash(f[1]);
                db.update(|tx| {
                    let genesis = init_database_state(tx, params, &genesis_hash, 0)
                        .expect("init database state");
                    node = Some(genesis);
                    Ok(())
                })
                .expect("update");
                infos.push((vec![0u8; 180], genesis_hash));
                counts[0] += 1;
            }
            "blk" => {
                // blk <headerhex> <voted> <revoked> <news>
                let header_bytes = unhex(f[1]);
                let iv = calc_hash256_prng_iv(&header_bytes);
                let voted = parse_hashes(f[2]);
                let revoked = parse_hashes(f[3]);
                let news = parse_hashes(f[4]);
                let connected = node
                    .as_ref()
                    .expect("init first")
                    .connect(iv, &voted, &revoked, &news)
                    .unwrap_or_else(|e| panic!("{line}: connect failed: {e:?}"));
                let (header, _) = BlockHeader::from_bytes(&header_bytes).expect("header");
                let block_hash = header.block_hash();
                db.update(|tx| {
                    write_connected_best_node(tx, &connected, &block_hash)
                        .expect("write connected");
                    Ok(())
                })
                .expect("update");
                infos.push((header_bytes, block_hash));
                node = Some(connected);
                counts[1] += 1;
            }
            "disc" => {
                let cur = node.take().expect("node");
                let height = cur.height() as usize;
                let (parent_header, parent_hash) = infos[height - 1].clone();
                let parent_iv = calc_hash256_prng_iv(&parent_header);
                let child_undo = cur.undo_data().to_vec();
                // Restore the parent's bookkeeping from the database
                // rows, mirroring dcrd's nil-undo disconnect path.
                let mut utds = Vec::new();
                let mut tickets = Vec::new();
                db.view(|tx| {
                    utds = db_fetch_block_undo_data(tx, (height - 1) as u32).expect("undo row");
                    tickets = db_fetch_new_tickets(tx, (height - 1) as u32).expect("tickets row");
                    Ok(())
                })
                .expect("view");
                let parent = cur
                    .disconnect(parent_iv, &utds, &tickets)
                    .unwrap_or_else(|e| panic!("{line}: disconnect failed: {e:?}"));
                db.update(|tx| {
                    write_disconnected_best_node(tx, &parent, &parent_hash, &child_undo)
                        .expect("write disconnected");
                    Ok(())
                })
                .expect("update");
                node = Some(parent);
                counts[2] += 1;
            }
            "ckpt" => {
                // Collect the expected rows until endckpt and compare.
                let mut expected = Vec::new();
                for row_line in lines.by_ref() {
                    if row_line == "endckpt" {
                        break;
                    }
                    let rf: Vec<&str> = row_line.split(' ').collect();
                    assert_eq!(rf[0], "row", "expected row line");
                    expected.push((rf[1].to_string(), unhex(rf[2]), unhex(rf[3])));
                }
                let mut got = collect_rows(&db);
                let key = |r: &(String, Vec<u8>, Vec<u8>)| (r.0.clone(), r.1.clone());
                got.sort_by_key(&key);
                expected.sort_by_key(&key);
                assert_eq!(got.len(), expected.len(), "{line}: row count");
                for (g, e) in got.iter().zip(expected.iter()) {
                    assert_eq!(g.0, e.0, "{line}: bucket");
                    assert_eq!(raw_hex(&g.1), raw_hex(&e.1), "{line}: key in {}", g.0);
                    assert_eq!(
                        raw_hex(&g.2),
                        raw_hex(&e.2),
                        "{line}: value for {} in {}",
                        raw_hex(&g.1),
                        g.0
                    );
                }
                counts[3] += 1;
            }
            "load" => {
                // load <height> <hash> <header> <pool> <fs> <winners>
                //   <missedcount> <undocount>
                let height: u32 = f[1].parse().expect("height");
                let hash = parse_hash(f[2]);
                let header_bytes = unhex(f[3]);
                db.view(|tx| {
                    let loaded = load_best_node(tx, height, &hash, &header_bytes, params)
                        .expect("load best node");
                    assert_eq!(loaded.pool_size().to_string(), f[4], "{line}: pool");
                    assert_eq!(raw_hex(&loaded.final_state()), f[5], "{line}: fs");
                    assert_eq!(hash_csv(loaded.winners()), f[6], "{line}: winners");
                    assert_eq!(
                        loaded.missed_tickets().len().to_string(),
                        f[7],
                        "{line}: missed"
                    );
                    assert_eq!(loaded.undo_data().len().to_string(), f[8], "{line}: undo");
                    Ok(())
                })
                .expect("view");
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [1, 60, 10, 5, 2], "row counts");
}
