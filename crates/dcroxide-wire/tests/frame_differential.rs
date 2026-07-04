// SPDX-License-Identifier: ISC
//! Differential tests: full message framing vs. dcrd's
//! `ReadMessage`/`WriteMessage`, live, across every implemented message
//! type — structured frames must round-trip byte-identically through both
//! implementations, and corrupted frames must produce the same verdict and
//! error kind.

// Test-harness arithmetic over bounded generator values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_wire::{
    BlockHeader, BlockLocator, CurrencyNet, InvType, InvVect, Message, MsgAddr, MsgBlock,
    MsgCFHeaders, MsgCFTypes, MsgCFilter, MsgCFilterV2, MsgCFiltersV2, MsgFeeFilter, MsgGetBlocks,
    MsgGetCFHeaders, MsgGetCFilter, MsgGetCFilterV2, MsgGetCFsV2, MsgGetData, MsgGetHeaders,
    MsgGetInitState, MsgHeaders, MsgInitState, MsgInv, MsgMiningState, MsgNotFound, MsgPing,
    MsgPong, MsgReject, MsgTx, MsgVersion, NetAddress, OutPoint, PROTOCOL_VERSION,
    REMOVE_REJECT_VERSION, ServiceFlag, TxIn, TxOut, TxSerializeType, read_message, write_message,
};

fn random_hash(rng: &mut SplitMix64) -> Hash {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    Hash(b)
}

fn random_hashes(rng: &mut SplitMix64, max: u64) -> Vec<Hash> {
    (0..rng.below(max + 1)).map(|_| random_hash(rng)).collect()
}

fn random_netaddress(rng: &mut SplitMix64) -> NetAddress {
    let mut ip = [0u8; 16];
    rng.fill(&mut ip);
    NetAddress {
        timestamp: rng.next_u64() as u32,
        services: ServiceFlag(rng.below(8)),
        ip,
        port: rng.next_u64() as u16,
    }
}

fn random_tx(rng: &mut SplitMix64) -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: rng.next_u64() as u16,
        tx_in: (0..rng.below(3))
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
                signature_script: rng.bytes(40),
            })
            .collect(),
        tx_out: (0..rng.below(3))
            .map(|_| TxOut {
                value: rng.next_u64() as i64,
                version: rng.next_u64() as u16,
                pk_script: rng.bytes(40),
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

fn random_inv(rng: &mut SplitMix64) -> Vec<InvVect> {
    (0..rng.below(5))
        .map(|_| InvVect {
            inv_type: InvType(rng.below(6) as u32),
            hash: random_hash(rng),
        })
        .collect()
}

fn random_locator(rng: &mut SplitMix64) -> BlockLocator {
    BlockLocator {
        protocol_version: rng.next_u64() as u32,
        block_locator_hashes: random_hashes(rng, 4),
        hash_stop: random_hash(rng),
    }
}

fn random_cfilter_v2(rng: &mut SplitMix64) -> MsgCFilterV2 {
    MsgCFilterV2 {
        block_hash: random_hash(rng),
        data: rng.bytes(64),
        proof_index: rng.next_u64() as u32,
        proof_hashes: random_hashes(rng, 4),
    }
}

/// A printable strict-ASCII string.
fn random_ascii(rng: &mut SplitMix64, max_len: u64) -> String {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| (0x20 + rng.below(0x5f) as u8) as char)
        .collect()
}

/// Build one random instance of each message type valid at
/// [`PROTOCOL_VERSION`], plus a reject at a pre-removal version.
fn structured_messages(rng: &mut SplitMix64) -> Vec<(Message, u32)> {
    let pver = PROTOCOL_VERSION;
    let msgs = vec![
        (
            Message::Version(MsgVersion {
                protocol_version: rng.next_u64() as i32,
                services: ServiceFlag(rng.below(8)),
                timestamp: (rng.next_u64() % (1 << 40)) as i64,
                // The version form omits address timestamps on the wire, so
                // zero them for the struct round-trip comparison.
                addr_you: NetAddress {
                    timestamp: 0,
                    ..random_netaddress(rng)
                },
                addr_me: NetAddress {
                    timestamp: 0,
                    ..random_netaddress(rng)
                },
                nonce: rng.next_u64(),
                user_agent: random_ascii(rng, 40),
                last_block: rng.next_u64() as i32,
                disable_relay_tx: rng.below(2) == 0,
            }),
            pver,
        ),
        (Message::VerAck, pver),
        (Message::GetAddr, pver),
        (
            Message::Addr(MsgAddr {
                addr_list: (0..rng.below(4)).map(|_| random_netaddress(rng)).collect(),
            }),
            pver,
        ),
        (Message::GetBlocks(MsgGetBlocks(random_locator(rng))), pver),
        (
            Message::GetHeaders(MsgGetHeaders(random_locator(rng))),
            pver,
        ),
        (
            Message::Inv(MsgInv {
                inv_list: random_inv(rng),
            }),
            pver,
        ),
        (
            Message::GetData(MsgGetData {
                inv_list: random_inv(rng),
            }),
            pver,
        ),
        (
            Message::NotFound(MsgNotFound {
                inv_list: random_inv(rng),
            }),
            pver,
        ),
        (
            Message::Block(MsgBlock {
                header: random_header(rng),
                transactions: (0..rng.below(3)).map(|_| random_tx(rng)).collect(),
                stransactions: (0..rng.below(3)).map(|_| random_tx(rng)).collect(),
            }),
            pver,
        ),
        (Message::Tx(random_tx(rng)), pver),
        (
            Message::Headers(MsgHeaders {
                headers: (0..rng.below(4)).map(|_| random_header(rng)).collect(),
            }),
            pver,
        ),
        (
            Message::Ping(MsgPing {
                nonce: rng.next_u64(),
            }),
            pver,
        ),
        (
            Message::Pong(MsgPong {
                nonce: rng.next_u64(),
            }),
            pver,
        ),
        (Message::MemPool, pver),
        (
            Message::MiningState(MsgMiningState {
                version: rng.next_u64() as u32,
                height: rng.next_u64() as u32,
                block_hashes: random_hashes(rng, 8),
                vote_hashes: random_hashes(rng, 8),
            }),
            pver,
        ),
        (Message::GetMiningState, pver),
        (Message::SendHeaders, pver),
        (
            Message::FeeFilter(MsgFeeFilter {
                min_fee: rng.next_u64() as i64,
            }),
            pver,
        ),
        (
            Message::GetCFilter(MsgGetCFilter {
                block_hash: random_hash(rng),
                filter_type: rng.below(3) as u8,
            }),
            pver,
        ),
        (
            Message::GetCFHeaders(MsgGetCFHeaders {
                block_locator_hashes: random_hashes(rng, 4),
                hash_stop: random_hash(rng),
                filter_type: rng.below(3) as u8,
            }),
            pver,
        ),
        (Message::GetCFTypes, pver),
        (
            Message::CFilter(MsgCFilter {
                block_hash: random_hash(rng),
                filter_type: rng.below(3) as u8,
                data: rng.bytes(64),
            }),
            pver,
        ),
        (
            Message::CFHeaders(MsgCFHeaders {
                stop_hash: random_hash(rng),
                filter_type: rng.below(3) as u8,
                header_hashes: random_hashes(rng, 5),
            }),
            pver,
        ),
        (
            Message::CFTypes(MsgCFTypes {
                supported_filters: rng.bytes(4),
            }),
            pver,
        ),
        (
            Message::GetCFilterV2(MsgGetCFilterV2 {
                block_hash: random_hash(rng),
            }),
            pver,
        ),
        (Message::CFilterV2(random_cfilter_v2(rng)), pver),
        (
            Message::GetInitState(MsgGetInitState {
                types: (0..rng.below(4)).map(|_| random_ascii(rng, 32)).collect(),
            }),
            pver,
        ),
        (
            Message::InitState(MsgInitState {
                block_hashes: random_hashes(rng, 8),
                vote_hashes: random_hashes(rng, 8),
                tspend_hashes: random_hashes(rng, 7),
            }),
            pver,
        ),
        (
            Message::GetCFsV2(MsgGetCFsV2 {
                start_hash: random_hash(rng),
                end_hash: random_hash(rng),
            }),
            pver,
        ),
        (
            Message::CFiltersV2(MsgCFiltersV2 {
                cfilters: (0..rng.below(3)).map(|_| random_cfilter_v2(rng)).collect(),
            }),
            pver,
        ),
    ];

    msgs
}

fn oracle_frame(
    oracle: &mut Oracle,
    pver: u32,
    net: CurrencyNet,
    frame: &[u8],
) -> serde_json::Value {
    let mut req = Vec::with_capacity(8 + frame.len());
    req.extend_from_slice(&pver.to_be_bytes());
    req.extend_from_slice(&net.0.to_be_bytes());
    req.extend_from_slice(frame);
    oracle.call("wire_msg", &req)
}

#[test]
fn frames_round_trip_against_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("wire frame structured differential");

    for round in 0..30 {
        let net = [
            CurrencyNet::MAIN_NET,
            CurrencyNet::TEST_NET3,
            CurrencyNet::SIM_NET,
            CurrencyNet::REG_NET,
        ][rng.below(4) as usize];

        for (msg, pver) in structured_messages(&mut rng) {
            let frame = write_message(&msg, pver, net).expect("structured messages encode cleanly");

            // Our decoder round-trips.
            let (decoded, consumed) = read_message(&frame, pver, net).expect("own frame decodes");
            assert_eq!(consumed, frame.len(), "consumed whole frame");
            assert_eq!(decoded, msg, "round {round}: {} round trip", msg.command());

            // dcrd decodes the same frame and re-encodes it byte-identically.
            let resp = oracle_frame(&mut oracle, pver, net, &frame);
            assert!(
                resp.get("error").is_none(),
                "round {round}: oracle rejected {} frame: {resp} ({})",
                msg.command(),
                hex(&frame)
            );
            assert_eq!(
                resp["compressed"].as_str().expect("command"),
                msg.command(),
                "round {round}: command"
            );
            let reencoded = unhex(resp["result"].as_str().expect("result"));
            assert_eq!(
                frame,
                reencoded,
                "round {round}: {} re-encoding",
                msg.command()
            );
        }
    }
}

#[test]
fn corrupted_frames_match_dcrd_verdicts() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("wire frame mutation differential");
    let net = CurrencyNet::MAIN_NET;

    for i in 0..1_500 {
        let msgs = structured_messages(&mut rng);
        let (msg, pver) = &msgs[rng.below(msgs.len() as u64) as usize];
        let mut frame = write_message(msg, *pver, net).expect("encode");

        match rng.below(4) {
            // Corrupt a random byte anywhere (header or payload).
            0 => {
                let pos = rng.below(frame.len() as u64) as usize;
                frame[pos] ^= (rng.next_u64() as u8) | 1;
            }
            // Truncate.
            1 => {
                let cut = rng.below(frame.len() as u64 + 1) as usize;
                frame.truncate(cut);
            }
            // Wrong network magic.
            2 => {
                frame[..4].copy_from_slice(&CurrencyNet::SIM_NET.0.to_le_bytes());
            }
            // Inflate the declared length without adding payload.
            _ => {
                let bogus = (rng.next_u64() as u32) | 1;
                frame[16..20].copy_from_slice(&bogus.to_le_bytes());
            }
        }

        let ours = read_message(&frame, *pver, net);
        let resp = oracle_frame(&mut oracle, *pver, net, &frame);
        match (&ours, resp.get("error").and_then(|e| e.as_str())) {
            (Ok((decoded, _)), None) => {
                // Mutation landed in ignored trailing space or produced an
                // equally valid frame; both accept — compare the results.
                let reencoded = unhex(resp["result"].as_str().expect("result"));
                let ours_reencoded = write_message(decoded, *pver, net).expect("re-encode");
                assert_eq!(ours_reencoded, reencoded, "case {i}: mutual accept");
            }
            (Err(err), Some(_)) => {
                let oracle_kind = resp.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                // dcrd surfaces raw io errors (empty kind) for short reads;
                // our UnexpectedEof maps to the same empty kind.
                assert_eq!(
                    err.kind_name(),
                    oracle_kind,
                    "case {i}: error kind for {} (ours {err:?})",
                    hex(&frame)
                );
            }
            (ours, oracle_err) => panic!(
                "case {i}: verdict mismatch: ours {ours:?}, oracle {oracle_err:?} for {}",
                hex(&frame)
            ),
        }
    }
}

#[test]
fn reject_frames_are_unknown_to_readers() {
    // Quirk QK-0001: dcrd can still *write* reject below
    // REMOVE_REJECT_VERSION, but its read path has no dispatch case for it,
    // so both implementations must reject the frame as an unknown command.
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let pver = REMOVE_REJECT_VERSION - 1;
    let net = CurrencyNet::MAIN_NET;
    let msg = Message::Reject(MsgReject {
        cmd: "tx".to_owned(),
        code: 0x10,
        reason: "duplicate".to_owned(),
        hash: Hash([7u8; 32]),
    });
    let frame = write_message(&msg, pver, net).expect("reject encodes below removal version");

    let ours = read_message(&frame, pver, net);
    assert!(
        matches!(ours, Err(dcroxide_wire::WireError::UnknownCmd)),
        "ours: {ours:?}"
    );
    let resp = oracle_frame(&mut oracle, pver, net, &frame);
    assert_eq!(
        resp.get("kind").and_then(|k| k.as_str()),
        Some("ErrUnknownCmd"),
        "oracle: {resp}"
    );
}
