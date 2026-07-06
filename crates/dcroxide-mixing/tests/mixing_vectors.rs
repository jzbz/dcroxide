// SPDX-License-Identifier: ISC
//! Replay of dcrd's mixing primitive behavior generated inside
//! dcrd's mixing package (`data/mixing_vectors.txt`): the identity
//! hashes and signed-data digests of all eight mix messages, message
//! signing byte for byte with verification and a tampering rejection,
//! pair request session sorting with the derived session ID, key
//! exchange session validation across its error cases, the
//! exponential and XOR DC-net math over a full honest 4-peer run
//! (pads, mixes, power sums, polynomial coefficients, and root
//! checks), field membership, the run PRNG keystream, UTXO ownership
//! proofs, and the pair request expiry across networks.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::{mainnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_crypto::blake256;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    ChaCha20Prng, F, FieldInt, MSIZE, MixError, MixMessage, Secp256k1KeyPair, Vect, add_vectors,
    coefficients, dc_mix, dc_mix_pads, in_field_be_bytes, int_vectors_from_bytes,
    int_vectors_to_bytes, is_root, max_expiry, rand_vec, sign_message, sort_prs_for_session,
    sr_mix, sr_mix_pads, validate_session, verify_signed_message, xor_vectors,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::{
    MIX_VERSION, Message, MsgMixKeyExchange, MsgMixPairReq, decode_message_payload,
};

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ints_hex(ints: &[FieldInt]) -> String {
    ints.iter()
        .map(|x| {
            let bytes = x.to_be_bytes();
            if bytes.is_empty() {
                "-".to_string()
            } else {
                raw_hex(&bytes)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn vect_hex(v: &Vect) -> String {
    v.iter().map(|m| raw_hex(m)).collect::<Vec<_>>().join(",")
}

/// Decode a mix message payload into a boxed [`MixMessage`].
fn decode_mix(cmd: &str, payload: &[u8]) -> Box<dyn MixMessage> {
    match decode_message_payload(cmd, payload, MIX_VERSION).expect("decode") {
        Message::MixPairReq(m) => Box::new(m),
        Message::MixKeyExchange(m) => m,
        Message::MixCiphertexts(m) => Box::new(m),
        Message::MixSlotReserve(m) => Box::new(m),
        Message::MixFactoredPoly(m) => Box::new(m),
        Message::MixDCNet(m) => Box::new(m),
        Message::MixConfirm(m) => Box::new(m),
        Message::MixSecrets(m) => Box::new(m),
        _ => panic!("not a mix message"),
    }
}

/// The deterministic pairwise shared secret of the dump's SR run.
fn shared(i: usize, j: usize) -> Vec<u8> {
    let (lo, hi) = if i <= j { (i, j) } else { (j, i) };
    blake256::sum256(format!("shared-{lo}-{hi}").as_bytes()).to_vec()
}

/// The deterministic peer message of the dump's SR run.
fn peer_message(p: usize) -> FieldInt {
    let digest = blake256::sum256(format!("message-{p}").as_bytes());
    FieldInt::from_be_bytes(&digest[..16])
}

const N: usize = 4;

#[test]
fn mixing_vectors() {
    let data = include_str!("data/mixing_vectors.txt");
    let mut counts = [0usize; 8];

    let sign_priv = PrivateKey::from_bytes(&[0x77; 32]).expect("priv");

    let mut prs: Vec<MsgMixPairReq> = Vec::new();
    let mut sorted_hashes: Vec<Hash> = Vec::new();
    let mut session_sid = [0u8; 32];
    let mut session_epoch = 0u64;
    let mut sr_mixes: Vec<Vec<FieldInt>> = Vec::new();
    let mut sr_coeffs: Vec<FieldInt> = Vec::new();
    let mut dc_mixes: Vec<Vect> = Vec::new();
    let mut utxo_pub: Vec<u8> = Vec::new();
    let mut utxo_proof: Vec<u8> = Vec::new();

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "msg" => {
                let payload = unhex(f[2]);
                let msg = decode_mix(f[1], &payload);
                let hash = msg.mix_hash().expect("mix hash");
                assert_eq!(format!("{hash}"), f[3], "{}: identity hash", f[1]);
                let sdd = blake256::sum256(&msg.signed_data().expect("signed data"));
                assert_eq!(raw_hex(&sdd), f[4], "{}: signed data digest", f[1]);
                counts[0] += 1;
            }
            "signed" => {
                let payload = unhex(f[2]);
                let mut msg = decode_mix(f[1], &payload);
                assert!(verify_signed_message(&*msg), "{}: must verify", f[1]);
                // Re-sign from scratch; the RFC6979 signature is
                // deterministic and must match dcrd's byte for byte.
                msg.set_sig([0u8; 64]);
                sign_message(&mut *msg, &sign_priv).expect("sign");
                assert_eq!(raw_hex(&msg.sig()), f[3], "{}: signature", f[1]);
                assert!(verify_signed_message(&*msg), "{}: re-verify", f[1]);
                counts[1] += 1;
            }
            "tampered" => {
                let payload = unhex(f[2]);
                let msg = decode_mix(f[1], &payload);
                let want: bool = f[3].parse().expect("bool");
                assert_eq!(verify_signed_message(&*msg), want, "{}: tampered", f[1]);
            }
            "pr" => {
                let payload = unhex(f[2]);
                match decode_message_payload("mixpairreq", &payload, MIX_VERSION).expect("pr") {
                    Message::MixPairReq(m) => prs.push(m),
                    _ => unreachable!(),
                }
            }
            "sortprs" => {
                session_epoch = f[1].parse().expect("epoch");
                let sid = sort_prs_for_session(&mut prs, session_epoch);
                assert_eq!(raw_hex(&sid), f[2], "session id");
                let order: Vec<String> = prs
                    .iter()
                    .map(|p| format!("{}", p.mix_hash().expect("hash")))
                    .collect();
                assert_eq!(order.join(","), f[3], "session order");
                session_sid = sid;
                sorted_hashes = prs.iter().map(|p| p.mix_hash().expect("hash")).collect();
                counts[2] += 1;
            }
            "validsess" => {
                let mut ke = MsgMixKeyExchange {
                    signature: [0; 64],
                    identity: [0; 33],
                    session_id: session_sid,
                    epoch: session_epoch,
                    run: 0,
                    pos: 0,
                    ecdh: [0; 33],
                    pqpk: [0; 1218],
                    commitment: [0; 32],
                    seen_prs: sorted_hashes.clone(),
                };
                match f[1] {
                    "run0ok" => {}
                    "run1ok" => ke.run = 1,
                    "badorder" => ke.seen_prs.swap(0, 1),
                    "badsid" => ke.epoch += 1,
                    other => panic!("unknown session case {other}"),
                }
                let got = match validate_session(&ke) {
                    Ok(()) => "ok",
                    Err(MixError::InvalidPROrder) => "order",
                    Err(MixError::InvalidSessionID) => "sid",
                    Err(err) => panic!("unexpected session error {err}"),
                };
                assert_eq!(got, f[2], "{line}");
                counts[3] += 1;
            }
            "srpads" => {
                let p: usize = f[1].parse().expect("peer");
                let kp: Vec<Vec<u8>> = (0..N).map(|i| shared(p, i)).collect();
                let pads = sr_mix_pads(&kp, p as u32);
                assert_eq!(ints_hex(&pads), f[2], "{line}");
                let mix = sr_mix(&peer_message(p), &pads);
                sr_mixes.push(mix);
                counts[4] += 1;
            }
            "srmix" => {
                let p: usize = f[1].parse().expect("peer");
                let m = peer_message(p);
                assert_eq!(ints_hex(&[m]), f[2], "{line}: message");
                assert_eq!(ints_hex(&sr_mixes[p]), f[3], "{line}: mix");
            }
            "addvec" => {
                let sums = add_vectors(&sr_mixes);
                assert_eq!(ints_hex(&sums), f[1], "{line}");
                sr_coeffs = coefficients(&sums);
            }
            "coeffs" => {
                assert_eq!(ints_hex(&sr_coeffs), f[1], "{line}");
            }
            "isroot" => {
                let m = FieldInt::from_be_bytes(&unhex(f[1]));
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(is_root(&m, &sr_coeffs), want, "{line}");
                counts[5] += 1;
            }
            "introundtrip" => {
                let bytes_vecs = int_vectors_to_bytes(&sr_mixes);
                let round_trip = int_vectors_from_bytes(&bytes_vecs);
                assert_eq!(round_trip, sr_mixes, "{line}");
            }
            "infield" => {
                let want: bool = f[2].parse().expect("bool");
                let got = match f[1] {
                    "zero" => in_field_be_bytes(&[]),
                    "one" => in_field_be_bytes(&[1]),
                    "fminus1" => in_field_be_bytes(&(F - 1).to_be_bytes()),
                    "f" => in_field_be_bytes(&F.to_be_bytes()),
                    "2pow127" => in_field_be_bytes(&(1u128 << 127).to_be_bytes()),
                    // Negative values have no unsigned encoding; dcrd
                    // rejects them by sign.
                    "neg" => false,
                    other => panic!("unknown infield case {other}"),
                };
                assert_eq!(got, want, "{line}");
            }
            "dcpads" => {
                let p: usize = f[1].parse().expect("peer");
                let kp: Vec<Vect> = (0..N)
                    .map(|i| {
                        let (lo, hi) = if p <= i { (p, i) } else { (i, p) };
                        let seed = blake256::sum256(format!("kp-{lo}-{hi}").as_bytes());
                        let mut prng = ChaCha20Prng::new(&seed, 0);
                        rand_vec(N as u32, &mut prng)
                    })
                    .collect();
                let pads = dc_mix_pads(&kp, p as u32);
                assert_eq!(vect_hex(&pads), f[2], "{line}");
                let digest = blake256::sum256(format!("dcmsg-{p}").as_bytes());
                dc_mixes.push(dc_mix(&pads, &digest[..MSIZE], p as u32));
                counts[6] += 1;
            }
            "dcmix" => {
                let p: usize = f[1].parse().expect("peer");
                let digest = blake256::sum256(format!("dcmsg-{p}").as_bytes());
                assert_eq!(raw_hex(&digest[..MSIZE]), f[2], "{line}: message");
                assert_eq!(vect_hex(&dc_mixes[p]), f[3], "{line}: mix");
            }
            "xorvec" => {
                let recovered = xor_vectors(&dc_mixes);
                assert_eq!(vect_hex(&recovered), f[1], "{line}");
            }
            "prng" => {
                let seed = unhex(f[1]);
                let run: u32 = f[2].parse().expect("run");
                let mut prng = ChaCha20Prng::new(&seed, run);
                assert_eq!(raw_hex(&prng.next_bytes(16)), f[3], "{line}: first");
                let mut second = [0u8; 32];
                prng.read(&mut second);
                assert_eq!(raw_hex(&second), f[4], "{line}: second");
                assert_eq!(raw_hex(&prng.next_bytes(7)), f[5], "{line}: third");
                counts[7] += 1;
            }
            "utxoproof" => {
                let expires: u32 = f[2].parse().expect("expires");
                let priv_key = PrivateKey::from_bytes(&[0x88; 32]).expect("priv");
                let keypair = Secp256k1KeyPair {
                    pub_key: unhex(f[1]),
                    priv_key,
                };
                let proof = keypair.sign_utxo_proof(expires).expect("proof");
                assert_eq!(raw_hex(&proof), f[3], "{line}");
                utxo_pub = keypair.pub_key;
                utxo_proof = proof;
            }
            "utxovalid" => {
                let expires: u32 = f[1].parse().expect("expires");
                let want: bool = f[2].parse().expect("bool");
                let got =
                    dcroxide_mixing::validate_secp256k1_p2pkh(&utxo_pub, &utxo_proof, expires);
                assert_eq!(got, want, "{line}");
            }
            "maxexpiry" => {
                let params = match f[1] {
                    "mainnet" => mainnet_params(),
                    "testnet3" => testnet3_params(),
                    "simnet" => simnet_params(),
                    other => panic!("unknown network {other}"),
                };
                let tip: u32 = f[2].parse().expect("tip");
                let want: u32 = f[3].parse().expect("expiry");
                assert_eq!(max_expiry(tip, &params), want, "{line}");
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [8, 8, 1, 4, 4, 5, 4, 3], "row counts");
}
