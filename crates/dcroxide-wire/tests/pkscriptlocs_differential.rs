// SPDX-License-Identifier: ISC
//! `MsgTx::pk_script_locs` against dcrd's `MsgTx.PkScriptLocs`
//! (`wire/msgtx.go:1119-1157`) through the oracle's `msgtx_pkscriptlocs`.
//!
//! Each transaction is asked about twice: sent in its full serialization
//! with its own serialization type set after dcrd decodes it, which
//! reaches a witness-only transaction that holds outputs (QK-0038), and
//! sent in its own serialization and left as decoded.  Both sides must
//! give the same offsets, serialize the same bytes under that type, and
//! agree on whether each script lies at its offset in them.
//!
//! Three parts: generated transactions, mostly small, their scripts'
//! lengths biased to the varint edges and now and then as long as
//! txscript's 16,384-byte limit or past 0x10000; a sweep of input counts,
//! output counts and script lengths over every varint edge a decodable
//! transaction can reach, in every serialization type, with the largest
//! script one request line can carry; and a frozen battery of dcrd's
//! answers (`data/pkscriptlocs_vectors.txt`, line count and BLAKE-256
//! digest pinned) that needs no Go.

// Test-harness arithmetic over bounded generator values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};
use dcroxide_wire::{MAX_MESSAGE_PAYLOAD, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// The committed battery.
const COMMITTED: &str = include_str!("data/pkscriptlocs_vectors.txt");

/// The number of cases in the battery.
const COMMITTED_CASES: usize = 240;

/// The battery's BLAKE-256 digest; regenerate it with the file through
/// `committed_pkscriptlocs_vectors_regenerate`.
const COMMITTED_DIGEST: &str = "0154dde6957e9887df83dd62580532399a3b702e2d268b061dad8b03025051ce";

/// The request byte that leaves the decoded transaction's serialization
/// type as its bytes gave it.
const KEEP: u8 = 0xff;

/// txscript's `MaxScriptSize`, the longest script consensus executes.
const MAX_SCRIPT_SIZE: usize = 16_384;

/// The varint edges: the last one-byte value, the first three-byte value
/// and its successor, the last three-byte value, and the first five-byte
/// value.
const EDGES: [usize; 5] = [0xfc, 0xfd, 0xfe, 0xffff, 0x10000];

/// The three serialization types.
const SER_TYPES: [TxSerializeType; 3] = [
    TxSerializeType::Full,
    TxSerializeType::NoWitness,
    TxSerializeType::OnlyWitness,
];

/// The answer to one request, as the oracle renders it: the offsets in
/// decimal joined by `,`, or `nil`, and whether every script lies at its
/// offset in the serialization under the type asked about.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    locs: String,
    len: usize,
    digest: String,
    located: bool,
}

/// The offsets as dcrd's oracle renders them; dcrd returns nil exactly
/// when there are no outputs, which is when the port's list is empty.
fn render(locs: &[usize]) -> String {
    if locs.is_empty() {
        return "nil".to_owned();
    }
    locs.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether each output's script is found at its offset in `bytes`, as the
/// oracle decides it.
fn located(tx: &MsgTx, bytes: &[u8], locs: &[usize]) -> bool {
    locs.len() == tx.tx_out.len()
        && locs
            .iter()
            .zip(&tx.tx_out)
            .all(|(&loc, out)| bytes.get(loc..loc + out.pk_script.len()) == Some(&out.pk_script))
}

/// The port's answer for `tx`, whose serialization is `bytes`, with the
/// BLAKE-256 digest `digest`.
fn answer(tx: &MsgTx, bytes: &[u8], digest: &str) -> Answer {
    let locs = tx.pk_script_locs();
    assert_eq!(
        tx.pk_script_locs_iter().collect::<Vec<_>>(),
        locs,
        "the iterator yields the list"
    );
    Answer {
        locs: render(&locs),
        len: bytes.len(),
        digest: digest.to_owned(),
        located: located(tx, bytes, &locs),
    }
}

/// The BLAKE-256 digest of `bytes` in hex.
fn digest(bytes: &[u8]) -> String {
    hex(&blake256::sum256(bytes))
}

/// The two requests for `tx`: its full serialization with its own type
/// to be set after the decode, and its own serialization kept as decoded.
fn requests(tx: &MsgTx) -> [Vec<u8>; 2] {
    let mut full = tx.clone();
    full.ser_type = TxSerializeType::Full;
    let mut set = vec![tx.ser_type.to_u16() as u8];
    set.extend_from_slice(&full.serialize());
    let mut kept = vec![KEEP];
    kept.extend_from_slice(&tx.serialize());
    [set, kept]
}

/// The transaction a request carries, decoded, its type set as the
/// request says.
fn decode_request(req: &[u8]) -> MsgTx {
    let (mut tx, consumed) = MsgTx::from_bytes(&req[1..]).expect("the request's tx decodes");
    assert_eq!(consumed, req.len() - 1, "the request's tx is all of it");
    if req[0] != KEEP {
        tx.ser_type = TxSerializeType::from_u16(u16::from(req[0])).expect("a known type");
    }
    tx
}

/// dcrd's answer to a request.
fn theirs(oracle: &mut Oracle, req: &[u8]) -> Answer {
    let resp = oracle.call("msgtx_pkscriptlocs", req);
    if let Some(err) = resp.get("error") {
        panic!("msgtx_pkscriptlocs: {err}");
    }
    let detail = &resp["detail"];
    Answer {
        locs: resp["result"].as_str().expect("result").to_owned(),
        len: detail["len"].as_u64().expect("len") as usize,
        digest: detail["blake256"].as_str().expect("blake256").to_owned(),
        located: detail["located"].as_bool().expect("located"),
    }
}

/// Both requests for `tx` get the same answer from both sides, and the
/// answer for `tx` as it is holds the port's law: in a serialization that
/// carries outputs, each script lies at its offset.
///
/// Both requests decode to transactions that serialize as `tx` does (the
/// witness-only decode, without outputs, included), so the serialization
/// is hashed once.
fn check(oracle: &mut Oracle, tx: &MsgTx, ctx: &str) {
    let bytes = tx.serialize();
    let digest = digest(&bytes);
    let mine = answer(tx, &bytes, &digest);
    if tx.ser_type != TxSerializeType::OnlyWitness || tx.tx_out.is_empty() {
        assert!(mine.located, "{ctx}: a script is not at its offset");
    }
    let [set, kept] = requests(tx);
    let from_set = decode_request(&set);
    assert!(
        from_set.serialize() == bytes,
        "{ctx}: the type set after decoding"
    );
    assert_eq!(
        answer(&from_set, &bytes, &digest),
        mine,
        "{ctx}: the type set after decoding"
    );
    assert_eq!(
        theirs(oracle, &set),
        mine,
        "{ctx}: the type set after decoding"
    );
    let from_kept = decode_request(&kept);
    assert!(from_kept.serialize() == bytes, "{ctx}: kept as decoded");
    let decoded = answer(&from_kept, &bytes, &digest);
    assert_eq!(theirs(oracle, &kept), decoded, "{ctx}: kept as decoded");
    if tx.ser_type == TxSerializeType::OnlyWitness {
        assert_eq!(decoded.locs, "nil", "{ctx}: a witness-only decode");
    } else {
        assert_eq!(decoded, mine, "{ctx}: kept as decoded");
    }
}

fn random_hash(rng: &mut SplitMix64) -> dcroxide_chainhash::Hash {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    dcroxide_chainhash::Hash(b)
}

fn random_input(rng: &mut SplitMix64) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: random_hash(rng),
            index: rng.next_u64() as u32,
            tree: rng.below(128) as i8,
        },
        sequence: rng.next_u64() as u32,
        value_in: rng.next_u64() as i64,
        block_height: rng.next_u64() as u32,
        block_index: rng.next_u64() as u32,
        signature_script: rng.bytes(40),
    }
}

/// An output whose script is `len` random bytes.
fn output(rng: &mut SplitMix64, len: usize) -> TxOut {
    let mut pk_script = vec![0u8; len];
    rng.fill(&mut pk_script);
    TxOut {
        value: rng.next_u64() as i64,
        version: rng.next_u64() as u16,
        pk_script,
    }
}

/// A script length: short, at a one-byte edge, or rarely long enough to
/// take a three- or five-byte varint, up to and past txscript's limit.
fn script_len(rng: &mut SplitMix64) -> usize {
    match rng.below(50) {
        0 => [0xffff, 0x10000, MAX_SCRIPT_SIZE, MAX_SCRIPT_SIZE + 1][rng.below(4) as usize],
        1..=10 => [0, 1, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x100][rng.below(8) as usize],
        _ => rng.below(80) as usize,
    }
}

/// A transaction of a random serialization type, mostly of a few inputs
/// and outputs.
fn random_tx(rng: &mut SplitMix64) -> MsgTx {
    let ser_type = SER_TYPES[rng.below(3) as usize];
    let n_in = rng.below(6) as usize;
    let n_out = match rng.below(20) {
        0 => [0xfc, 0xfd][rng.below(2) as usize],
        _ => rng.below(10) as usize,
    };
    let tx_in = (0..n_in).map(|_| random_input(rng)).collect();
    let tx_out = (0..n_out)
        .map(|_| {
            let len = if n_out > 16 {
                rng.below(4) as usize
            } else {
                script_len(rng)
            };
            output(rng, len)
        })
        .collect();
    MsgTx {
        ser_type,
        version: rng.next_u64() as u16,
        tx_in,
        tx_out,
        lock_time: rng.next_u64() as u32,
        expiry: rng.next_u64() as u32,
    }
}

/// Generated transactions get dcrd's offsets.
#[test]
fn generated_transactions_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("pkscriptlocs differential");
    let (mut without_outputs, mut stray) = (0, 0);
    for case in 0..5_000 {
        let tx = random_tx(&mut rng);
        check(&mut oracle, &tx, &format!("case {case}"));
        if tx.tx_out.is_empty() {
            without_outputs += 1;
        } else if tx.ser_type == TxSerializeType::OnlyWitness {
            stray += 1;
        }
    }
    assert!(
        without_outputs > 200 && stray > 1_000,
        "{without_outputs} without outputs, {stray} witness-only with outputs"
    );
}

/// The sweep: for each edge, a transaction of that many inputs, one of
/// that many outputs, and one with a script of that length between two
/// short ones, each in every serialization type; with the counts and
/// lengths 0 and 1 as well.
fn edge_cases(rng: &mut SplitMix64, edges: &[usize]) -> Vec<MsgTx> {
    let mut cases = Vec::new();
    for &n in [0, 1].iter().chain(edges) {
        let shapes = [
            MsgTx {
                tx_in: (0..n).map(|_| random_input(rng)).collect(),
                tx_out: vec![output(rng, 25), output(rng, 0)],
                ..MsgTx::default()
            },
            MsgTx {
                tx_in: vec![random_input(rng)],
                tx_out: (0..n)
                    .map(|i| output(rng, [0, 1, 2, 0xfd][i % 4]))
                    .collect(),
                ..MsgTx::default()
            },
            MsgTx {
                tx_in: vec![random_input(rng), random_input(rng)],
                tx_out: vec![output(rng, 1), output(rng, n), output(rng, 2)],
                ..MsgTx::default()
            },
        ];
        for shape in shapes {
            for ser_type in SER_TYPES {
                cases.push(MsgTx {
                    ser_type,
                    ..shape.clone()
                });
            }
        }
    }
    cases
}

/// Every varint edge in every serialization type gets dcrd's offsets.
#[test]
fn varint_edges_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64(0x6564_6765_7377_6565);
    for (i, tx) in edge_cases(&mut rng, &EDGES).iter().enumerate() {
        let ctx = format!(
            "edge case {i}: {:?}, {} inputs, {} outputs",
            tx.ser_type,
            tx.tx_in.len(),
            tx.tx_out.len()
        );
        check(&mut oracle, tx, &ctx);
    }
}

/// txscript's longest script gets dcrd's offsets, and so does the longest
/// script one request line carries, which the decoder accepts.
#[test]
fn long_scripts_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64(0x6c6f_6e67_7363_7270);
    // The oracle reads lines of up to 64 MiB, which is 32 MiB of request
    // bytes; the decoder accepts a script of MAX_MESSAGE_PAYLOAD (32 MiB),
    // which `msgtx.rs` checks without the oracle.  This one leaves 4 KiB
    // for the rest of the line.
    let longest = MAX_MESSAGE_PAYLOAD as usize - 4096;
    for len in [MAX_SCRIPT_SIZE, longest] {
        let tx = MsgTx {
            ser_type: TxSerializeType::NoWitness,
            tx_in: vec![random_input(&mut rng)],
            tx_out: vec![output(&mut rng, 7), output(&mut rng, len)],
            ..MsgTx::default()
        };
        check(&mut oracle, &tx, &format!("a script of {len} bytes"));
    }
}

/// The battery's cases: the edge sweep with output counts kept below
/// 0xffff so each line stays short, then generated transactions, both
/// from fixed seeds; each case is a request.
fn battery() -> Vec<Vec<u8>> {
    let mut cases = Vec::new();
    let mut rng = SplitMix64(0x706b_7363_7269_7074);
    for tx in edge_cases(&mut rng, &EDGES) {
        if tx.tx_out.len() >= 0xffff {
            continue;
        }
        let [set, kept] = requests(&tx);
        cases.push(set);
        cases.push(kept);
    }
    while cases.len() < COMMITTED_CASES {
        let tx = random_tx(&mut rng);
        let [set, kept] = requests(&tx);
        cases.push(set);
        cases.push(kept);
    }
    cases.truncate(COMMITTED_CASES);
    cases
}

/// One battery line: the request's type byte, its transaction's length
/// and BLAKE-256 digest `tx_digest`, which bind the line to the case the
/// battery builds, and the answer.
fn line(req: &[u8], tx_digest: &str, answer: &Answer) -> String {
    format!(
        "{:02x}|{}|{tx_digest}|{}|{}|{}|{}",
        req[0],
        req.len() - 1,
        answer.locs,
        answer.len,
        answer.digest,
        answer.located
    )
}

/// Every committed answer is dcroxide's, and the file is the one pinned.
#[test]
fn committed_pkscriptlocs_vectors_hold() {
    assert_eq!(
        hex(&blake256::sum256(COMMITTED.as_bytes())),
        COMMITTED_DIGEST,
        "data/pkscriptlocs_vectors.txt is not the committed battery"
    );
    let lines: Vec<&str> = COMMITTED.lines().filter(|l| !l.starts_with('#')).collect();
    let cases = battery();
    assert_eq!(lines.len(), COMMITTED_CASES);
    assert_eq!(cases.len(), COMMITTED_CASES);
    let (mut nil, mut stray) = (0, 0);
    for (l, req) in lines.iter().zip(&cases) {
        // Hash a serialization that is the request's own bytes once.
        let tx_digest = digest(&req[1..]);
        let tx = decode_request(req);
        let bytes = tx.serialize();
        let ser_digest = if bytes == req[1..] {
            tx_digest.clone()
        } else {
            digest(&bytes)
        };
        let answer = answer(&tx, &bytes, &ser_digest);
        assert_eq!(line(req, &tx_digest, &answer), *l);
        nil += usize::from(answer.locs == "nil");
        stray += usize::from(!answer.located);
    }
    assert!(nil >= 30 && stray >= 20, "{nil} nil, {stray} not located");
}

/// The committed file is the battery with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_PKSCRIPTLOCS_VECTORS=<path>` set, a differing text
/// is written there, never into the source tree, and the test still fails.
#[test]
fn committed_pkscriptlocs_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut text = String::from(
        "# dcrd wire MsgTx.PkScriptLocs at the parity pin 46e9df48 (wire v1.8.0),\n\
         # through tools/oracle's msgtx_pkscriptlocs: the edge sweep of\n\
         # tests/pkscriptlocs_differential.rs with fewer than 0xffff outputs,\n\
         # then generated transactions, from fixed seeds, each asked about with\n\
         # its type set after the decode (type 00, 01 or 02) and as decoded (ff).\n\
         # committed_pkscriptlocs_vectors_regenerate rebuilds this file and fails\n\
         # on any difference; committed_pkscriptlocs_vectors_hold checks it\n\
         # without Go.\n\
         #\n\
         # <type>|<request tx length>|<request tx BLAKE-256>|<offsets or nil>|\n\
         # <serialization length>|<serialization BLAKE-256>|<scripts at offsets>\n",
    );
    for req in battery() {
        text.push_str(&line(&req, &digest(&req[1..]), &theirs(&mut oracle, &req)));
        text.push('\n');
    }
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_PKSCRIPTLOCS_VECTORS") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/pkscriptlocs_vectors.txt differs from its construction");
    }
}
