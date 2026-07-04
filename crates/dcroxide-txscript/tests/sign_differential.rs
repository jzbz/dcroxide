// SPDX-License-Identifier: ISC
//! Differential tests for the sign module against dcrd through the
//! oracle: raw input signatures across all three suites (deterministic,
//! so byte-comparable), full `SignTxOutput` flows over every signable
//! script shape — P2PK/P2PKH across suites, bare and P2SH-wrapped
//! multisig with partial signing and merging, stake-tagged outputs with
//! and without the treasury flag — plus treasury spend signing. Fully
//! signed results are additionally executed through our engine.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};
use dcroxide_txscript::sign::{
    SignError, SignatureType, raw_tx_in_signature, sign_tx_output, tspend_signature_script,
};
use dcroxide_txscript::stdaddr::{self, Address};
use dcroxide_txscript::{Engine, ScriptFlags, SigHashType};
use dcroxide_wire::MsgTx;

mod common;
use common::create_spending_tx;

fn networks() -> [(&'static str, Params); 4] {
    [
        ("mainnet", mainnet_params()),
        ("testnet3", testnet3_params()),
        ("simnet", simnet_params()),
        ("regnet", regnet_params()),
    ]
}

fn sig_type_byte(sig_type: SignatureType) -> u8 {
    match sig_type {
        SignatureType::EcdsaSecp256k1 => 0,
        SignatureType::Ed25519 => 1,
        SignatureType::SchnorrSecp256k1 => 2,
    }
}

/// A key ring entry: the serialized private key (32 bytes for secp256k1,
/// the 64-byte `seed ‖ pubkey` form for Ed25519, matching dcrd), its type,
/// and compressedness.
#[derive(Clone)]
struct KeyEntry {
    key: Vec<u8>,
    sig_type: SignatureType,
    compressed: bool,
}

impl KeyEntry {
    /// The underlying 32-byte secp256k1 scalar (only for secp entries).
    fn secp_scalar(&self) -> [u8; 32] {
        self.key[..32].try_into().expect("32 bytes")
    }
}

/// A random valid secp256k1 private key.
fn random_secp_key(rng: &mut SplitMix64) -> [u8; 32] {
    loop {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        if dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&key).is_some() {
            return key;
        }
    }
}

/// A random secp256k1 key entry.
fn random_secp_entry(rng: &mut SplitMix64, compressed: bool) -> KeyEntry {
    KeyEntry {
        key: random_secp_key(rng).to_vec(),
        sig_type: SignatureType::EcdsaSecp256k1,
        compressed,
    }
}

/// A random Ed25519 key entry in dcrd's 64-byte `seed ‖ pubkey` form.
fn random_ed25519_entry(rng: &mut SplitMix64) -> KeyEntry {
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    let pub_bytes = dcroxide_dcrec::edwards::SecretKey::from_seed(seed)
        .public_key()
        .serialize();
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&seed);
    key.extend_from_slice(&pub_bytes);
    KeyEntry {
        key,
        sig_type: SignatureType::Ed25519,
        compressed: true,
    }
}

fn secp_pub(key: &[u8; 32]) -> dcroxide_dcrec::secp256k1::PublicKey {
    dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(key)
        .expect("valid key")
        .public_key()
}

/// Build the address for a key entry per the requested shape.
fn key_address(entry: &KeyEntry, p2pkh: bool, params: &Params) -> Address {
    match entry.sig_type {
        SignatureType::EcdsaSecp256k1 => {
            let pk = secp_pub(&entry.secp_scalar());
            if p2pkh {
                let serialized: Vec<u8> = if entry.compressed {
                    pk.serialize_compressed().to_vec()
                } else {
                    pk.serialize_uncompressed().to_vec()
                };
                let hash = stdaddr::hash160(&serialized);
                stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, params)
                    .expect("20 bytes")
            } else {
                stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(pk.serialize_compressed(), params)
            }
        }
        SignatureType::Ed25519 => {
            // The embedded (canonical) public key is the trailing 32 bytes.
            let pk: [u8; 32] = entry.key[32..64].try_into().expect("32 bytes");
            if p2pkh {
                let hash = stdaddr::hash160(&pk);
                stdaddr::new_address_pub_key_hash_ed25519_v0(&hash, params).expect("20 bytes")
            } else {
                stdaddr::new_address_pub_key_ed25519_v0_raw(&pk, params).expect("valid key")
            }
        }
        SignatureType::SchnorrSecp256k1 => {
            let pk = secp_pub(&entry.secp_scalar()).serialize_compressed();
            if p2pkh {
                let hash = stdaddr::hash160(&pk);
                stdaddr::new_address_pub_key_hash_schnorr_secp256k1_v0(&hash, params)
                    .expect("20 bytes")
            } else {
                stdaddr::new_address_pub_key_schnorr_secp256k1_v0_raw(&pk, params)
                    .expect("valid key")
            }
        }
    }
}

type KeyMap = HashMap<String, KeyEntry>;
type ScriptMap = HashMap<String, Vec<u8>>;

/// Run our SignTxOutput with map-backed databases.
#[allow(clippy::too_many_arguments)]
fn ours_sign(
    params: &Params,
    tx: &MsgTx,
    pk_script: &[u8],
    hash_type: SigHashType,
    keys: &KeyMap,
    scripts: &ScriptMap,
    prev_script: &[u8],
    treasury: bool,
) -> Result<Vec<u8>, SignError> {
    let mut kdb = |addr: &Address| -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        match keys.get(&addr.encode()) {
            Some(entry) => Ok((entry.key.clone(), entry.sig_type, entry.compressed)),
            None => Err(SignError(format!("no key for {}", addr.encode()))),
        }
    };
    let mut sdb = |addr: &Address| -> Result<Vec<u8>, SignError> {
        match scripts.get(&addr.encode()) {
            Some(script) => Ok(script.clone()),
            None => Err(SignError(format!("no script for {}", addr.encode()))),
        }
    };
    sign_tx_output(
        params,
        tx,
        0,
        pk_script,
        hash_type,
        &mut kdb,
        &mut sdb,
        prev_script,
        treasury,
    )
}

/// Run dcrd's SignTxOutput through the oracle; Ok(script hex) or Err.
#[allow(clippy::too_many_arguments)]
fn theirs_sign(
    oracle: &mut Oracle,
    net: &str,
    tx: &MsgTx,
    pk_script: &[u8],
    hash_type: SigHashType,
    keys: &KeyMap,
    scripts: &ScriptMap,
    prev_script: &[u8],
    treasury: bool,
) -> Result<String, String> {
    let mut req = Vec::new();
    req.push(net.len() as u8);
    req.extend_from_slice(net.as_bytes());
    req.push(hash_type.0);
    req.push(u8::from(treasury));
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&(pk_script.len() as u32).to_be_bytes());
    req.extend_from_slice(pk_script);
    req.extend_from_slice(&(prev_script.len() as u32).to_be_bytes());
    req.extend_from_slice(prev_script);
    req.push(keys.len() as u8);
    for (addr, entry) in keys {
        req.push(addr.len() as u8);
        req.extend_from_slice(addr.as_bytes());
        req.push(sig_type_byte(entry.sig_type));
        req.push(u8::from(entry.compressed));
        req.push(entry.key.len() as u8);
        req.extend_from_slice(&entry.key);
    }
    req.push(scripts.len() as u8);
    for (addr, script) in scripts {
        req.push(addr.len() as u8);
        req.extend_from_slice(addr.as_bytes());
        req.extend_from_slice(&(script.len() as u16).to_be_bytes());
        req.extend_from_slice(script);
    }
    req.extend_from_slice(&tx.serialize());

    let resp = oracle.call("sign_tx_output", &req);
    if let Some(result) = resp["result"].as_str() {
        Ok(result.to_string())
    } else if let Some(err) = resp["error"].as_str() {
        Err(err.to_string())
    } else {
        // An empty signature script is omitted from the response.
        Ok(String::new())
    }
}

/// Compare our SignTxOutput against dcrd's and return our result when both
/// agree.
#[allow(clippy::too_many_arguments)]
fn compare_sign(
    oracle: &mut Oracle,
    net: &str,
    params: &Params,
    tx: &MsgTx,
    pk_script: &[u8],
    hash_type: SigHashType,
    keys: &KeyMap,
    scripts: &ScriptMap,
    prev_script: &[u8],
    treasury: bool,
    context: &str,
) -> Option<Vec<u8>> {
    let ours = ours_sign(
        params,
        tx,
        pk_script,
        hash_type,
        keys,
        scripts,
        prev_script,
        treasury,
    );
    let theirs = theirs_sign(
        oracle,
        net,
        tx,
        pk_script,
        hash_type,
        keys,
        scripts,
        prev_script,
        treasury,
    );
    match (&ours, &theirs) {
        (Ok(our_script), Ok(their_hex)) => {
            assert_eq!(
                &hex(our_script),
                their_hex,
                "{net}/{context}: signature script divergence for pk={}",
                hex(pk_script)
            );
            Some(our_script.clone())
        }
        (Err(_), Err(_)) => None, // Both errored; messages differ by design.
        (ours, theirs) => panic!(
            "{net}/{context}: verdict divergence for pk={}: ours={ours:?} theirs={theirs:?}",
            hex(pk_script)
        ),
    }
}

/// Execute the signed input through our engine and require success.
fn engine_verify(pk_script: &[u8], tx: &MsgTx, sig_script: Vec<u8>, treasury: bool, context: &str) {
    let mut tx = tx.clone();
    tx.tx_in[0].signature_script = sig_script;
    let flags = if treasury {
        ScriptFlags::VERIFY_TREASURY
    } else {
        ScriptFlags::default()
    };
    Engine::new(pk_script, &tx, 0, flags, 0)
        .and_then(|mut vm| vm.execute())
        .unwrap_or_else(|e| panic!("{context}: signed input failed to verify: {e}"));
}

#[test]
fn sign_tx_output_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sign-differential");

    const ROUNDS: usize = 40;
    for round in 0..ROUNDS {
        for (net, params) in networks() {
            let hash_type = match rng.below(4) {
                0 => SigHashType(0x01), // All
                1 => SigHashType(0x02), // None
                2 => SigHashType(0x03), // Single (idx 0 < 1 output)
                _ => SigHashType(0x81), // All | AnyOneCanPay
            };
            let treasury = rng.below(2) == 0;

            // --- P2PK and P2PKH across all suites and compressedness ---
            for sig_type in [
                SignatureType::EcdsaSecp256k1,
                SignatureType::Ed25519,
                SignatureType::SchnorrSecp256k1,
            ] {
                let compressed = sig_type != SignatureType::EcdsaSecp256k1 || rng.below(2) == 0;
                let base_entry = match sig_type {
                    SignatureType::Ed25519 => random_ed25519_entry(&mut rng),
                    _ => random_secp_entry(&mut rng, compressed),
                };
                for p2pkh in [false, true] {
                    // Uncompressed P2PK addresses are not a thing; the
                    // address always uses the compressed form.
                    let entry = if !p2pkh {
                        KeyEntry {
                            compressed: true,
                            ..base_entry.clone()
                        }
                    } else {
                        base_entry.clone()
                    };
                    let addr = key_address(&entry, p2pkh, &params);
                    let (_, pk_script) = addr.payment_script();
                    let tx = create_spending_tx(&[], &pk_script);
                    let mut keys = KeyMap::new();
                    keys.insert(addr.encode(), entry);
                    let scripts = ScriptMap::new();
                    let ctx = format!("round {round} p2pkh={p2pkh} {sig_type:?}");
                    if let Some(sig_script) = compare_sign(
                        &mut oracle,
                        net,
                        &params,
                        &tx,
                        &pk_script,
                        hash_type,
                        &keys,
                        &scripts,
                        &[],
                        treasury,
                        &ctx,
                    ) {
                        engine_verify(&pk_script, &tx, sig_script, treasury, &ctx);
                    }
                }
            }

            // --- Stake-tagged P2PKH outputs (incl. treasury gen) ---
            {
                let entry = random_secp_entry(&mut rng, true);
                let addr = key_address(&entry, true, &params);
                let tagged = [
                    addr.voting_rights_script(),
                    addr.stake_change_script(),
                    addr.pay_vote_commitment_script(),
                    addr.pay_revoke_commitment_script(),
                    addr.pay_from_treasury_script(),
                ];
                let mut keys = KeyMap::new();
                keys.insert(addr.encode(), entry);
                let scripts = ScriptMap::new();
                for (i, tagged_script) in tagged.into_iter().enumerate() {
                    let (_, pk_script) = tagged_script.expect("stake address");
                    let tx = create_spending_tx(&[], &pk_script);
                    let ctx = format!("round {round} stake-p2pkh tag {i} treasury={treasury}");
                    if let Some(sig_script) = compare_sign(
                        &mut oracle,
                        net,
                        &params,
                        &tx,
                        &pk_script,
                        hash_type,
                        &keys,
                        &scripts,
                        &[],
                        treasury,
                        &ctx,
                    ) {
                        // Treasury-gen outputs only verify with the flag.
                        let is_tgen = i == 4;
                        if !is_tgen || treasury {
                            engine_verify(&pk_script, &tx, sig_script, treasury || is_tgen, &ctx);
                        }
                    }
                }
            }

            // --- Bare multisig with partial signing and merge ---
            {
                let n = 3usize;
                let entries: Vec<KeyEntry> =
                    (0..n).map(|_| random_secp_entry(&mut rng, true)).collect();
                let pub_keys: Vec<[u8; 33]> = entries
                    .iter()
                    .map(|e| secp_pub(&e.secp_scalar()).serialize_compressed())
                    .collect();
                let key_refs: Vec<&[u8]> = pub_keys.iter().map(|k| k.as_slice()).collect();
                let pk_script = dcroxide_txscript::stdscript::multi_sig_script_v0(2, &key_refs)
                    .expect("valid multisig");
                let tx = create_spending_tx(&[], &pk_script);

                let addr_of = |e: &KeyEntry| key_address(e, false, &params).encode();

                // Step 1: sign with only the second key.
                let mut keys1 = KeyMap::new();
                keys1.insert(addr_of(&entries[1]), entries[1].clone());
                let scripts = ScriptMap::new();
                let ctx1 = format!("round {round} multisig partial");
                let partial = compare_sign(
                    &mut oracle,
                    net,
                    &params,
                    &tx,
                    &pk_script,
                    hash_type,
                    &keys1,
                    &scripts,
                    &[],
                    treasury,
                    &ctx1,
                )
                .expect("partial multisig signing succeeds");

                // Step 2: sign with the remaining keys and merge the
                // partial result.
                let mut keys2 = KeyMap::new();
                keys2.insert(addr_of(&entries[0]), entries[0].clone());
                keys2.insert(addr_of(&entries[2]), entries[2].clone());
                let ctx2 = format!("round {round} multisig merge");
                if let Some(merged) = compare_sign(
                    &mut oracle,
                    net,
                    &params,
                    &tx,
                    &pk_script,
                    hash_type,
                    &keys2,
                    &scripts,
                    &partial,
                    treasury,
                    &ctx2,
                ) {
                    engine_verify(&pk_script, &tx, merged, treasury, &ctx2);
                }
            }

            // --- P2SH wrapping a P2PKH redeem and a multisig redeem ---
            {
                // P2PKH redeem inside P2SH.
                let entry = random_secp_entry(&mut rng, true);
                let inner = key_address(&entry, true, &params);
                let (_, redeem) = inner.payment_script();
                let p2sh = stdaddr::new_address_script_hash_v0(&redeem, &params).expect("hash");
                let (_, pk_script) = if rng.below(2) == 0 {
                    p2sh.payment_script()
                } else {
                    // Stake-tagged P2SH.
                    p2sh.voting_rights_script().expect("stake address")
                };
                let tx = create_spending_tx(&[], &pk_script);
                let mut keys = KeyMap::new();
                keys.insert(inner.encode(), entry);
                let mut scripts = ScriptMap::new();
                scripts.insert(p2sh.encode(), redeem.clone());
                let ctx = format!("round {round} p2sh-p2pkh");
                if let Some(sig_script) = compare_sign(
                    &mut oracle,
                    net,
                    &params,
                    &tx,
                    &pk_script,
                    hash_type,
                    &keys,
                    &scripts,
                    &[],
                    treasury,
                    &ctx,
                ) {
                    engine_verify(&pk_script, &tx, sig_script, treasury, &ctx);
                }

                // Multisig redeem inside P2SH, two-step merge.
                let entries: Vec<KeyEntry> =
                    (0..3).map(|_| random_secp_entry(&mut rng, true)).collect();
                let pub_keys: Vec<[u8; 33]> = entries
                    .iter()
                    .map(|e| secp_pub(&e.secp_scalar()).serialize_compressed())
                    .collect();
                let key_refs: Vec<&[u8]> = pub_keys.iter().map(|k| k.as_slice()).collect();
                let redeem = dcroxide_txscript::stdscript::multi_sig_script_v0(2, &key_refs)
                    .expect("valid multisig");
                let p2sh = stdaddr::new_address_script_hash_v0(&redeem, &params).expect("hash");
                let (_, pk_script) = p2sh.payment_script();
                let tx = create_spending_tx(&[], &pk_script);

                let addr_of = |e: &KeyEntry| key_address(e, false, &params).encode();
                let mut scripts = ScriptMap::new();
                scripts.insert(p2sh.encode(), redeem.clone());

                let mut keys1 = KeyMap::new();
                keys1.insert(addr_of(&entries[0]), entries[0].clone());
                let ctx1 = format!("round {round} p2sh-multisig partial");
                let partial = compare_sign(
                    &mut oracle,
                    net,
                    &params,
                    &tx,
                    &pk_script,
                    hash_type,
                    &keys1,
                    &scripts,
                    &[],
                    treasury,
                    &ctx1,
                )
                .expect("partial p2sh multisig signing succeeds");

                let mut keys2 = KeyMap::new();
                keys2.insert(addr_of(&entries[1]), entries[1].clone());
                let ctx2 = format!("round {round} p2sh-multisig merge");
                if let Some(merged) = compare_sign(
                    &mut oracle,
                    net,
                    &params,
                    &tx,
                    &pk_script,
                    hash_type,
                    &keys2,
                    &scripts,
                    &partial,
                    treasury,
                    &ctx2,
                ) {
                    engine_verify(&pk_script, &tx, merged, treasury, &ctx2);
                }
            }
        }
    }
}

#[test]
fn raw_signature_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("raw-sig-differential");

    const ROUNDS: usize = 500;
    for round in 0..ROUNDS {
        let sig_type = match rng.below(3) {
            0 => SignatureType::EcdsaSecp256k1,
            1 => SignatureType::Ed25519,
            _ => SignatureType::SchnorrSecp256k1,
        };
        let entry = match sig_type {
            SignatureType::Ed25519 => random_ed25519_entry(&mut rng),
            _ => random_secp_entry(&mut rng, true),
        };
        let key = entry.key.clone();
        let hash_type = SigHashType(rng.next_u64() as u8);
        let sub_script = match rng.below(3) {
            0 => vec![0x51],       // OP_1
            1 => rng.bytes(24),    // random (may fail to parse)
            _ => vec![0x76, 0xa9], // DUP HASH160 fragment
        };
        let tx = create_spending_tx(&[], &[0x51]);

        let ours = raw_tx_in_signature(&tx, 0, &sub_script, hash_type, &key, sig_type);

        let mut req = Vec::new();
        req.push(sig_type_byte(sig_type));
        req.push(hash_type.0);
        req.extend_from_slice(&0u32.to_be_bytes());
        req.push(key.len() as u8);
        req.extend_from_slice(&key);
        req.extend_from_slice(&(sub_script.len() as u32).to_be_bytes());
        req.extend_from_slice(&sub_script);
        req.extend_from_slice(&tx.serialize());
        let resp = oracle.call("raw_txin_sig", &req);
        let theirs: Result<String, String> = if let Some(result) = resp["result"].as_str() {
            Ok(result.to_string())
        } else {
            Err(resp["error"].as_str().unwrap_or("").to_string())
        };

        match (&ours, &theirs) {
            (Ok(our_sig), Ok(their_hex)) => assert_eq!(
                &hex(our_sig),
                their_hex,
                "raw sig divergence at round {round}: {sig_type:?} ht={:#x} sub={}",
                hash_type.0,
                hex(&sub_script)
            ),
            (Err(_), Err(_)) => {}
            _ => panic!(
                "raw sig verdict divergence at round {round}: {sig_type:?} ht={:#x} sub={} \
                 ours={ours:?} theirs={theirs:?}",
                hash_type.0,
                hex(&sub_script)
            ),
        }
    }
}

#[test]
fn tspend_signature_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("tspend-sig-differential");

    const ROUNDS: usize = 300;
    for round in 0..ROUNDS {
        let key = random_secp_key(&mut rng);
        let tx = create_spending_tx(&rng.bytes(16), &rng.bytes(24));

        let ours = tspend_signature_script(&tx, &key).expect("tspend signs");

        let mut req = Vec::with_capacity(32 + 256);
        req.extend_from_slice(&key);
        req.extend_from_slice(&tx.serialize());
        let theirs = oracle.call_ok("tspend_sig", &req);
        assert_eq!(hex(&ours), theirs, "tspend divergence at round {round}");
    }
}
