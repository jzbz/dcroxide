// SPDX-License-Identifier: ISC
//! Replay of dcrd's RPC and network-sync chain query surface
//! (`data/query_vectors.txt`): block locators and inventory location
//! over a mainnet block index with a side chain (mirroring dcrd's own
//! `TestLocateInventory` layout), the threshold state RPC surface
//! (`NextThresholdState`, `StateLastChangedHeight`), vote counting
//! (`GetVoteCounts`, `CountVoteVersion`), stake version walks
//! (`GetStakeVersions`), deployment version info (`GetVoteInfo`), and
//! the stake difficulty estimators over a regnet fake chain that runs
//! the DCP0001 agenda through Started, LockedIn, and Active with real
//! votes, plus the forced-choice fast paths on simnet.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::BlockHeader;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_csv(hashes: &[Hash]) -> String {
    if hashes.is_empty() {
        return "-".into();
    }
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

fn parse_votes(s: &str) -> Vec<(u32, u16)> {
    if s == "-" {
        return Vec::new();
    }
    s.split(',')
        .map(|v| {
            let (ver, bits) = v.split_once('|').expect("vote");
            (ver.parse().expect("version"), bits.parse().expect("bits"))
        })
        .collect()
}

/// Insert a fully validated node for the given header, mirroring the
/// dump's fake chain construction.
fn add_node(chain: &mut Chain, header: &BlockHeader) {
    let prev = chain
        .index
        .lookup_node(&header.prev_block)
        .expect("previous node");
    let id = chain.store.new_node(header, Some(prev));
    {
        let node = chain.store.node_mut(id);
        node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
        node.is_fully_linked = true;
    }
    chain.index.add_node(&chain.store, id);
}

#[test]
fn query_vectors() {
    let main_params = mainnet_params();
    let reg_params = regnet_params();
    let sim_params = simnet_params();
    let mut chain = Chain::new(&main_params, Hash::ZERO, false);
    let mut params: &Params = &main_params;
    // The deterministic header recipe the dump's fake nodes use.
    let mut ts_base: i64 = 1401292357;
    let data = include_str!("data/query_vectors.txt");
    let mut counts = [0usize; 12];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "net" => {
                match f[1] {
                    "regnet" => {
                        params = &reg_params;
                        ts_base = 1538524800;
                    }
                    "simnet" => {
                        params = &sim_params;
                        ts_base = 1401292357;
                    }
                    other => panic!("unknown network {other}"),
                }
                chain = Chain::new(params, Hash::ZERO, false);
            }
            "lnode" => {
                // lnode <headerhex>: a locator-scenario node given by
                // its full header.
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                add_node(&mut chain, &header);
                counts[0] += 1;
            }
            "ltip" => {
                let tip = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("tip node");
                chain.best_chain.set_tip(&chain.store, Some(tip));
            }
            "vnode" => {
                // vnode <blockver> <stakever> <sbits> <poolsize>
                //       <fresh> <votescsv>: a vote-scenario node built
                // from the shared deterministic recipe.
                let tip = chain.best_chain.tip().expect("tip");
                let tip_node = chain.store.node(tip);
                let height = (tip_node.height + 1) as u32;
                let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0;
                header.version = f[1].parse().expect("block version");
                header.prev_block = tip_node.hash;
                header.vote_bits = 0x01;
                header.bits = params.pow_limit_bits;
                header.sbits = f[3].parse().expect("sbits");
                header.height = height;
                header.pool_size = f[4].parse().expect("pool size");
                header.fresh_stake = f[5].parse().expect("fresh stake");
                header.timestamp = (ts_base + i64::from(height)) as u32;
                header.nonce = height;
                header.stake_version = f[2].parse().expect("stake version");
                add_node(&mut chain, &header);
                let id = chain
                    .index
                    .lookup_node(&header.block_hash())
                    .expect("new node");
                chain.store.node_mut(id).votes = parse_votes(f[6]);
                chain.best_chain.set_tip(&chain.store, Some(id));
                counts[1] += 1;
            }
            "chk" => {
                // chk <height> <hash>: the fake chains are
                // byte-identical to dcrd's.
                let height: i64 = f[1].parse().expect("height");
                let hash = chain.block_hash_by_height(height).expect("hash at height");
                assert_eq!(hash, parse_hash(f[2]), "{line}");
                counts[2] += 1;
            }
            "loc" => {
                // loc <locatorcsv> <stophash> <max> <expected>
                let locator = parse_hashes(f[1]);
                let stop = parse_hash(f[2]);
                let max: u32 = f[3].parse().expect("max");
                let hashes = chain.locate_blocks(&locator, &stop, max);
                assert_eq!(hash_csv(&hashes), f[4], "{line}");
                counts[3] += 1;
            }
            "loch" => {
                // loch <locatorcsv> <stophash> <expected header hashes>
                let locator = parse_hashes(f[1]);
                let stop = parse_hash(f[2]);
                let headers = chain.locate_headers(&locator, &stop);
                let hashes: Vec<Hash> = headers.iter().map(|h| h.block_hash()).collect();
                assert_eq!(hash_csv(&hashes), f[3], "{line}");
                counts[4] += 1;
            }
            "bloc" => {
                // bloc <hash> <expected locator>
                let locator = chain.block_locator_from_hash(&parse_hash(f[1]));
                assert_eq!(hash_csv(&locator), f[2], "{line}");
                counts[5] += 1;
            }
            "gvc" => {
                // gvc <version> <id> (<total> <abstain> <choices> | err <kind>)
                let version: u32 = f[1].parse().expect("version");
                match chain.get_vote_counts(version, f[2], params) {
                    Ok(vc) => {
                        assert_eq!(vc.total.to_string(), f[3], "{line}: total");
                        assert_eq!(vc.total_abstain.to_string(), f[4], "{line}: abstain");
                        let choices = vc
                            .vote_choices
                            .iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        assert_eq!(choices, f[5], "{line}: choices");
                    }
                    Err(e) => {
                        assert_eq!("err", f[3], "{line}: unexpected error {e:?}");
                        assert_eq!(e.kind.kind_name(), f[4], "{line}: kind");
                    }
                }
                counts[6] += 1;
            }
            "cvv" => {
                // cvv <version> <total>
                let version: u32 = f[1].parse().expect("version");
                let total = chain.count_vote_version(version, params);
                assert_eq!(total.to_string(), f[2], "{line}");
            }
            "nts" => {
                // nts <height> <id> (<state> <choice|-> | err <kind>)
                let height: i64 = f[1].parse().expect("height");
                let hash = chain.block_hash_by_height(height).expect("hash at height");
                let state = chain
                    .next_threshold_state(&hash, f[2], params)
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"));
                assert_eq!(state.state.go_name(), f[3], "{line}: state");
                let choice = state
                    .choice
                    .as_ref()
                    .map_or("-".to_string(), |c| c.id.to_string());
                assert_eq!(choice, f[4], "{line}: choice");
                counts[7] += 1;
            }
            "ntse" | "slce" => {
                // ntse|slce <id|hash> <kind>: the unknown deployment
                // and unknown block error paths against the tip and a
                // fabricated hash.
                let tip = chain.best_chain.tip().expect("tip");
                let tip_hash = chain.store.node(tip).hash;
                let mut unknown = Hash::ZERO;
                unknown.0[0] = 0x02;
                let (hash, id) = match f[1] {
                    "id" => (tip_hash, "bogusagenda"),
                    "hash" => (unknown, "sdiffalgorithm"),
                    other => panic!("unknown error case {other}"),
                };
                let kind = if f[0] == "ntse" {
                    chain
                        .next_threshold_state(&hash, id, params)
                        .expect_err("must fail")
                        .kind
                } else {
                    chain
                        .state_last_changed_height(&hash, id, params)
                        .expect_err("must fail")
                        .kind
                };
                assert_eq!(kind.kind_name(), f[2], "{line}");
                counts[8] += 1;
            }
            "slc" => {
                // slc <height> <id> <lastchanged>
                let height: i64 = f[1].parse().expect("height");
                let hash = chain.block_hash_by_height(height).expect("hash at height");
                let last_changed = chain
                    .state_last_changed_height(&hash, f[2], params)
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"));
                assert_eq!(last_changed.to_string(), f[3], "{line}");
            }
            "gsv" => {
                // gsv <hash> <count> (<result> | err)
                let hash = parse_hash(f[1]);
                let count: i32 = f[2].parse().expect("count");
                match chain.get_stake_versions(&hash, count) {
                    Ok(svs) => {
                        let mut out = String::new();
                        if svs.is_empty() {
                            out.push('-');
                        }
                        for (i, sv) in svs.iter().enumerate() {
                            if i > 0 {
                                out.push(';');
                            }
                            out.push_str(&format!(
                                "{}:{}:{}:{}",
                                raw_hex(&sv.hash.0),
                                sv.height,
                                sv.block_version,
                                sv.stake_version
                            ));
                            for vote in &sv.votes {
                                out.push_str(&format!(":{}|{}", vote.0, vote.1));
                            }
                        }
                        assert_eq!(out, f[3], "{line}");
                    }
                    Err(e) => {
                        assert_eq!("err", f[3], "{line}: unexpected error {e}");
                    }
                }
                counts[9] += 1;
            }
            "gvi" => {
                // gvi <hash> <version> (<id:state:choice csv> | err <kind>)
                let hash = parse_hash(f[1]);
                let version: u32 = f[2].parse().expect("version");
                match chain.get_vote_info(&hash, version, params) {
                    Ok(vi) => {
                        let out = vi
                            .agendas
                            .iter()
                            .zip(&vi.agenda_status)
                            .map(|(agenda, status)| {
                                let choice = status
                                    .choice
                                    .as_ref()
                                    .map_or("-".to_string(), |c| c.id.to_string());
                                format!("{}:{}:{}", agenda.vote.id, status.state.go_name(), choice)
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        assert_eq!(out, f[3], "{line}");
                    }
                    Err(e) => {
                        assert_eq!("err", f[3], "{line}: unexpected error {e:?}");
                        assert_eq!(e.kind.kind_name(), f[4], "{line}: kind");
                    }
                }
                counts[10] += 1;
            }
            "est" => {
                // est <height> <tickets> <usemax> (<value>|toomany)
                let height: i64 = f[1].parse().expect("height");
                let hash = chain.block_hash_by_height(height).expect("hash at height");
                let new_tickets: i64 = f[2].parse().expect("tickets");
                let use_max = f[3] == "true";
                match chain.estimate_next_stake_difficulty(&hash, new_tickets, use_max, params) {
                    Ok(est) => assert_eq!(est.to_string(), f[4], "{line}"),
                    Err(e) => {
                        assert_eq!("toomany", f[4], "{line}: unexpected error {e}");
                        assert!(
                            e.contains("too much fresh stake")
                                || e.contains("more than the maximum remaining"),
                            "{line}: message {e}"
                        );
                    }
                }
                counts[11] += 1;
            }
            "estu" => {
                // estu <kind>: an unknown block hash surfaces dcrd's
                // ErrUnknownBlock context error as a message string.
                let mut unknown = Hash::ZERO;
                unknown.0[0] = 0x02;
                let err = chain
                    .estimate_next_stake_difficulty(&unknown, 0, true, params)
                    .expect_err("must fail");
                assert!(err.contains("is not known"), "{line}: message {err}");
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(
        counts,
        [20, 1320, 9, 11, 11, 4, 9, 16, 4, 5, 3, 18],
        "row counts"
    );
}
