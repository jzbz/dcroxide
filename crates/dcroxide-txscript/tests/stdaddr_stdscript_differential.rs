// SPDX-License-Identifier: ISC
//! Differential tests for the stdaddr and stdscript modules against dcrd
//! through the oracle: every address kind is generated, dumped across its
//! full observable surface (string encoding, payment and stake scripts,
//! hashes), and compared byte-for-byte; decode error kinds are compared
//! over corrupted and random strings, over every address decoded on the
//! other networks, and over valid-checksum payloads of assorted lengths
//! under each address ID; and script classification/address extraction
//! verdicts are compared over every standard template (each constructor
//! over each address kind), mutations, and structured random scripts across
//! all four networks.  Both halves check they were not vacuous: the decode
//! comparisons must reach each rejection behind the checksum, and the
//! templates must be classified as all 21 script types.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_txscript::stdaddr::{self, AddrError, Address};
use dcroxide_txscript::stdscript;

fn networks() -> [(&'static str, Params); 4] {
    [
        ("mainnet", mainnet_params()),
        ("testnet3", testnet3_params()),
        ("simnet", simnet_params()),
        ("regnet", regnet_params()),
    ]
}

/// Mirror of the oracle's `dumpStdAddr`: must stay byte-identical.
fn dump_addr(addr: &Address, amount: i64, vote_fee: i64, revoke_fee: i64) -> String {
    let mut w = String::new();
    w.push_str(&format!("type={}\n", addr.go_type_name()));
    w.push_str(&format!("string={}\n", addr.encode()));
    let (ver, script) = addr.payment_script();
    w.push_str(&format!("payment={ver}:{}\n", hex(&script)));
    if let Some(spk) = addr.serialized_pub_key() {
        w.push_str(&format!("serializedpubkey={}\n", hex(spk)));
    }
    if let Some(pkh) = addr.address_pub_key_hash() {
        w.push_str(&format!("pkh={}\n", pkh.encode()));
    }
    if let Some(h160) = addr.hash160() {
        w.push_str(&format!("hash160={}\n", hex(h160)));
    }
    if let Some((ver, script)) = addr.voting_rights_script() {
        w.push_str(&format!("votingrights={ver}:{}\n", hex(&script)));
        let (ver, script) = addr
            .reward_commitment_script(amount, vote_fee, revoke_fee)
            .expect("stake address");
        w.push_str(&format!("rewardcommitment={ver}:{}\n", hex(&script)));
        let (ver, script) = addr.stake_change_script().expect("stake address");
        w.push_str(&format!("stakechange={ver}:{}\n", hex(&script)));
        let (ver, script) = addr.pay_vote_commitment_script().expect("stake address");
        w.push_str(&format!("payvote={ver}:{}\n", hex(&script)));
        let (ver, script) = addr.pay_revoke_commitment_script().expect("stake address");
        w.push_str(&format!("payrevoke={ver}:{}\n", hex(&script)));
        let (ver, script) = addr.pay_from_treasury_script().expect("stake address");
        w.push_str(&format!("payfromtreasury={ver}:{}\n", hex(&script)));
    }
    w
}

/// Ask the oracle to decode and dump an address; Ok(dump) or Err(kind).
fn oracle_decode(
    oracle: &mut Oracle,
    net: &str,
    addr: &str,
    amount: i64,
    vote_fee: i64,
    revoke_fee: i64,
) -> Result<String, String> {
    let mut req = Vec::new();
    req.push(net.len() as u8);
    req.extend_from_slice(net.as_bytes());
    req.extend_from_slice(&(amount as u64).to_be_bytes());
    req.extend_from_slice(&(vote_fee as u64).to_be_bytes());
    req.extend_from_slice(&(revoke_fee as u64).to_be_bytes());
    req.extend_from_slice(addr.as_bytes());
    let resp = oracle.call("stdaddr_decode", &req);
    if let Some(result) = resp["result"].as_str() {
        Ok(String::from_utf8(unhex(result)).expect("dump is UTF-8"))
    } else if let Some(kind) = resp["kind"].as_str() {
        Err(kind.to_string())
    } else {
        panic!("oracle stdaddr_decode unexpected response: {resp}");
    }
}

/// Decode `s` on both sides: `ok:<encoding>` or the error kind name.
fn decode_both(oracle: &mut Oracle, net: &str, params: &Params, s: &str) -> (String, String) {
    let ours = match stdaddr::decode_address(s, params) {
        Ok(addr) => format!("ok:{}", addr.encode()),
        Err(AddrError { kind, .. }) => kind.kind_name().to_string(),
    };
    let theirs = match oracle_decode(oracle, net, s, 0, 0, 0) {
        Ok(dump) => {
            let string_line = dump
                .lines()
                .find_map(|l| l.strip_prefix("string="))
                .expect("dump has string line");
            format!("ok:{string_line}")
        }
        Err(kind) => kind,
    };
    (ours, theirs)
}

/// The five version-0 address IDs a network defines.
fn addr_ids(params: &Params) -> [[u8; 2]; 5] {
    [
        params.pub_key_addr_id,
        params.pub_key_hash_addr_id,
        params.pkh_edwards_addr_id,
        params.pkh_schnorr_addr_id,
        params.script_hash_addr_id,
    ]
}

/// One payload with a valid checksum under each of the network's address
/// IDs.  The length is usually 20 or 33 bytes, whose encodings can have the
/// 35 or 53 characters `DecodeAddress` hands on to `DecodeAddressV0` (its
/// shape check rejects any other length as unsupported), so a hash-length
/// or pubkey-length mismatch reaches the constructor: a 33-byte hash, or a
/// 20-byte pubkey (which only mainnet's pubkey prefix encodes in 35
/// characters).  Otherwise it is any length up to 40 bytes.  Under the
/// pubkey ID the first byte is usually a signature type, known (0 to 2) or
/// not (3), with or without the odd-Y flag, and the 32 random bytes after
/// it are a valid key about half the time.
fn checked_payloads(rng: &mut SplitMix64, params: &Params) -> Vec<String> {
    addr_ids(params)
        .into_iter()
        .map(|id| {
            let len = match rng.below(8) {
                0..=2 => 20,
                3..=5 => 33,
                _ => rng.below(41) as usize,
            };
            let mut payload = vec![0u8; len];
            rng.fill(&mut payload);
            if id == params.pub_key_addr_id && !payload.is_empty() && rng.below(4) != 0 {
                payload[0] = rng.below(4) as u8 | if rng.below(2) == 0 { 0x80 } else { 0 };
            }
            dcroxide_base58::check_encode(&payload, id)
        })
        .collect()
}

/// The kind name in a [`decode_both`] verdict, with every accepted string
/// collapsed to `ok`.
fn verdict_kind(verdict: &str) -> String {
    verdict.split(':').next().unwrap_or_default().to_string()
}

/// A boundary-biased fee limit for the log2-based commitment encoding.
fn edgy_fee_limit(rng: &mut SplitMix64) -> i64 {
    match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => 1i64 << rng.below(40),
        3 => (1i64 << rng.below(40)) + 1,
        4 => (1i64 << (rng.below(39) + 1)) - 1,
        _ => rng.below(1 << 40) as i64,
    }
}

/// A random valid secp256k1 compressed public key.
fn random_secp_pub_key(rng: &mut SplitMix64) -> [u8; 33] {
    loop {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        if let Some(priv_key) = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&seed) {
            return priv_key.public_key().serialize_compressed();
        }
    }
}

/// A random valid ed25519 public key serialization.
fn random_ed25519_pub_key(rng: &mut SplitMix64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    dcroxide_dcrec::edwards::SecretKey::from_seed(seed)
        .public_key()
        .serialize()
}

/// Generate one random address of every kind for the given network.
fn generate_addresses(rng: &mut SplitMix64, params: &Params) -> Vec<Address> {
    let mut hash = [0u8; 20];
    rng.fill(&mut hash);
    let secp_pk = random_secp_pub_key(rng);
    let ed_pk = random_ed25519_pub_key(rng);
    let redeem = rng.bytes(64);

    vec![
        stdaddr::new_address_pub_key_ecdsa_secp256k1_v0_raw(&secp_pk, params).expect("valid key"),
        stdaddr::new_address_pub_key_ed25519_v0_raw(&ed_pk, params).expect("valid key"),
        stdaddr::new_address_pub_key_schnorr_secp256k1_v0_raw(&secp_pk, params).expect("valid key"),
        stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, params).expect("20 bytes"),
        stdaddr::new_address_pub_key_hash_ed25519_v0(&hash, params).expect("20 bytes"),
        stdaddr::new_address_pub_key_hash_schnorr_secp256k1_v0(&hash, params).expect("20 bytes"),
        stdaddr::new_address_script_hash_v0(&redeem, params).expect("hash"),
    ]
}

#[test]
fn stdaddr_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stdaddr-differential");

    const ROUNDS: usize = 150;
    let mut kinds = BTreeSet::new();
    // Built once: a network's parameters are expensive to construct.
    let foreign = networks();
    for round in 0..ROUNDS {
        for (net, params) in networks() {
            let amount = rng.below(1 << 62) as i64;
            let vote_fee = edgy_fee_limit(&mut rng);
            let revoke_fee = edgy_fee_limit(&mut rng);

            for addr in generate_addresses(&mut rng, &params) {
                // Round-trip our encoding through our decoder first.
                let encoded = addr.encode();
                let decoded = stdaddr::decode_address(&encoded, &params)
                    .unwrap_or_else(|e| panic!("{net}: our decode of {encoded} failed: {e}"));
                assert_eq!(decoded, addr, "{net}: decode round trip for {encoded}");

                // Full-surface dump parity with dcrd.
                let ours = dump_addr(&addr, amount, vote_fee, revoke_fee);
                let theirs =
                    oracle_decode(&mut oracle, net, &encoded, amount, vote_fee, revoke_fee)
                        .unwrap_or_else(|kind| {
                            panic!("{net}: dcrd rejected {encoded} with {kind} at round {round}")
                        });
                assert_eq!(
                    ours, theirs,
                    "{net}: address dump divergence for {encoded} at round {round} \
                     (amount={amount} votefee={vote_fee} revokefee={revoke_fee})"
                );

                // Corrupt one character and compare the error kinds (or,
                // rarely, both accepting when the corruption hits the
                // payload of a kind without further validation).
                let mut corrupted = encoded.clone().into_bytes();
                let idx = rng.below(corrupted.len() as u64) as usize;
                let orig = corrupted[idx];
                corrupted[idx] = if orig == b'4' { b'5' } else { b'4' };
                let corrupted = String::from_utf8(corrupted).expect("ascii");
                let (ours, theirs) = decode_both(&mut oracle, net, &params, &corrupted);
                assert_eq!(
                    ours, theirs,
                    "{net}: corrupted decode divergence for {corrupted} at round {round}"
                );
                kinds.insert(verdict_kind(&theirs));

                // The intact address on another network: a valid checksum
                // under a prefix this network does not define.
                let (other, other_params) = foreign
                    .iter()
                    .filter(|(other, _)| *other != net)
                    .nth(rng.below(3) as usize)
                    .expect("three other networks");
                let (ours, theirs) = decode_both(&mut oracle, other, other_params, &encoded);
                assert_eq!(
                    ours, theirs,
                    "{other}: foreign {net} address divergence for {encoded} at round {round}"
                );
                kinds.insert(verdict_kind(&theirs));
            }

            // Valid-checksum payloads of assorted lengths under this
            // network's own IDs, reaching the checks behind the checksum.
            for s in checked_payloads(&mut rng, &params) {
                let (ours, theirs) = decode_both(&mut oracle, net, &params, &s);
                assert_eq!(
                    ours, theirs,
                    "{net}: checked payload divergence for {s} at round {round}"
                );
                kinds.insert(verdict_kind(&theirs));
            }

            // Random strings in the version-0 shape and out of it.
            let len = if rng.below(2) == 0 { 35 } else { 53 };
            let mut s = String::new();
            for _ in 0..len {
                let alphabet = dcroxide_base58::ALPHABET;
                s.push(alphabet[rng.below(58) as usize] as char);
            }
            let (ours, theirs) = decode_both(&mut oracle, net, &params, &s);
            assert_eq!(ours, theirs, "{net}: random string divergence for {s}");
            kinds.insert(verdict_kind(&theirs));
        }
    }

    // Not vacuous: the comparisons reached the rejections behind the
    // checksum, not only the checksum failure a corrupted string hits.
    // (`ErrMalformedAddress` needs a string `DecodeAddress`'s 35-or-53
    // shape check never passes on; `review_addr_quote.rs` pins it.)
    for kind in [
        "ErrBadAddressChecksum",
        "ErrUnsupportedAddress",
        "ErrMalformedAddressData",
        "ErrInvalidHashLen",
        "ErrInvalidPubKey",
    ] {
        assert!(kinds.contains(kind), "no decode reached {kind}: {kinds:?}");
    }
}

/// Mirror of the oracle's `stdscript_analyze` dump for our side.
fn analyze_ours(version: u16, script: &[u8], params: &Params) -> String {
    let mut w = String::new();
    let (script_type, addrs) = stdscript::extract_addrs(version, script, params);
    w.push_str(&format!("type={}\n", script_type.name()));
    w.push_str(&format!(
        "determined={}\n",
        stdscript::determine_script_type(version, script).name()
    ));
    w.push_str(&format!(
        "reqsigs={}\n",
        stdscript::determine_required_sigs(version, script)
    ));
    for addr in &addrs {
        w.push_str(&format!("addr={} {}\n", addr.go_type_name(), addr.encode()));
    }
    if version == 0
        && let Some(pushes) = stdscript::extract_atomic_swap_data_pushes_v0(script)
    {
        w.push_str(&format!(
            "atomicswap={} {} {} {} {}\n",
            hex(&pushes.recipient_hash160),
            hex(&pushes.refund_hash160),
            hex(&pushes.secret_hash),
            pushes.secret_size,
            pushes.lock_time
        ));
    }
    w
}

fn analyze_theirs(oracle: &mut Oracle, net: &str, version: u16, script: &[u8]) -> String {
    let mut req = Vec::new();
    req.push(net.len() as u8);
    req.extend_from_slice(net.as_bytes());
    req.extend_from_slice(&version.to_be_bytes());
    req.extend_from_slice(script);
    let result = oracle.call_ok("stdscript_analyze", &req);
    String::from_utf8(unhex(&result)).expect("dump is UTF-8")
}

/// The script from one of an address's six stake and treasury
/// constructors (`which` modulo 6: OP_SSTX, OP_SSTXCHANGE, OP_SSGEN,
/// OP_SSRTX and OP_TGEN tagged, then the reward commitment), or its
/// payment script for a kind that has none.
fn stake_script(rng: &mut SplitMix64, addr: &Address, which: u64) -> Vec<u8> {
    let tagged = match which % 6 {
        0 => addr.voting_rights_script(),
        1 => addr.stake_change_script(),
        2 => addr.pay_vote_commitment_script(),
        3 => addr.pay_revoke_commitment_script(),
        4 => addr.pay_from_treasury_script(),
        _ => addr.reward_commitment_script(
            rng.below(1 << 62) as i64,
            edgy_fee_limit(rng),
            edgy_fee_limit(rng),
        ),
    };
    tagged.map_or_else(|| addr.payment_script().1, |(_, script)| script)
}

/// Every standard template for a network: each address kind's payment
/// script and each stake constructor over it, a multisig, a null data
/// script, a bare treasury add, and a nonstandard script.
fn standard_templates(rng: &mut SplitMix64, params: &Params) -> Vec<Vec<u8>> {
    let mut scripts = Vec::new();
    for addr in generate_addresses(rng, params) {
        scripts.push(addr.payment_script().1);
        for which in 0..6 {
            scripts.push(stake_script(rng, &addr, which));
        }
    }
    let key = random_secp_pub_key(rng);
    scripts.push(stdscript::multi_sig_script_v0(1, &[key.as_slice()]).expect("1-of-1"));
    scripts.push(stdscript::provably_pruneable_script_v0(&rng.bytes(40)).expect("40 bytes"));
    scripts.push(vec![0xc1]); // OP_TADD
    scripts.push(vec![0x00, 0x87]); // OP_0 OP_EQUAL
    scripts
}

/// A structured random script biased toward near-standard shapes.
fn near_standard_script(rng: &mut SplitMix64, params: &Params) -> Vec<u8> {
    let addr_pool = generate_addresses(rng, params);
    let base = match rng.below(8) {
        // A standard payment script of a random kind.
        0 | 1 => {
            addr_pool[rng.below(addr_pool.len() as u64) as usize]
                .payment_script()
                .1
        }
        // A script from any of the stake and treasury constructors, mostly
        // over the two kinds that have them (P2PKH-ecdsa-secp256k1 at index
        // 3, P2SH at 6).
        2 => {
            let idx = match rng.below(3) {
                0 => 3,
                1 => 6,
                _ => rng.below(addr_pool.len() as u64) as usize,
            };
            let which = rng.below(6);
            stake_script(rng, &addr_pool[idx], which)
        }
        // A multisig script from 1-4 keys with a random threshold.
        3 => {
            let n = rng.below(4) as usize + 1;
            let keys: Vec<[u8; 33]> = (0..n).map(|_| random_secp_pub_key(rng)).collect();
            let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
            let threshold = rng.below(n as u64 + 1) as i64;
            stdscript::multi_sig_script_v0(threshold, &key_refs).unwrap_or_default()
        }
        // Null data of assorted sizes, canonical or not.
        4 => {
            let data = rng.bytes(80);
            stdscript::provably_pruneable_script_v0(&data).unwrap_or_default()
        }
        // Treasury add / bare tags.
        5 => vec![0xc1],
        // An atomic swap contract with boundary-biased ints.
        6 => {
            // IF SIZE <32> EQUALVERIFY SHA256 DATA_32
            let mut s = vec![0x63, 0x82, 0x01, 32, 0x88, 0xc0, 0x20];
            let mut secret_hash = [0u8; 32];
            rng.fill(&mut secret_hash);
            s.extend_from_slice(&secret_hash);
            s.push(0x88); // EQUALVERIFY
            s.push(0x76); // DUP
            s.push(0xa9); // HASH160
            s.push(0x14); // DATA_20
            s.extend(core::iter::repeat_n(rng.next_u64() as u8, 20));
            s.push(0x67); // ELSE
            s.push(0x04); // DATA_4 locktime
            s.extend((rng.next_u64() as u32 & 0x7fff_ffff).to_le_bytes());
            s.push(0xb1); // CHECKLOCKTIMEVERIFY
            s.push(0x75); // DROP
            s.push(0x76); // DUP
            s.push(0xa9); // HASH160
            s.push(0x14); // DATA_20
            s.extend(core::iter::repeat_n(rng.next_u64() as u8, 20));
            s.push(0x68); // ENDIF
            s.push(0x88); // EQUALVERIFY
            s.push(0xac); // CHECKSIG
            s
        }
        // Pure random bytes.
        _ => rng.bytes(64),
    };

    // Sometimes mutate the base script.
    let mut script = base;
    if !script.is_empty() && rng.below(3) == 0 {
        match rng.below(3) {
            0 => {
                let idx = rng.below(script.len() as u64) as usize;
                script[idx] ^= 1 << rng.below(8);
            }
            1 => {
                let cut = rng.below(script.len() as u64) as usize;
                script.truncate(cut);
            }
            _ => script.push(rng.next_u64() as u8),
        }
    }
    script
}

#[test]
fn stdscript_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stdscript-differential");

    // Every standard template, once per network, before the random rounds.
    let mut types = BTreeSet::new();
    for (net, params) in networks() {
        for script in standard_templates(&mut rng, &params) {
            let ours = analyze_ours(0, &script, &params);
            let theirs = analyze_theirs(&mut oracle, net, 0, &script);
            assert_eq!(
                ours,
                theirs,
                "{net}: stdscript divergence on template {}",
                hex(&script)
            );
            types.extend(
                theirs
                    .lines()
                    .filter_map(|l| l.strip_prefix("type="))
                    .map(str::to_owned),
            );
        }
    }
    // Not vacuous: every script type dcrd defines was classified.
    for name in [
        "nonstandard",
        "pubkey",
        "pubkey-ed25519",
        "pubkey-schnorr-secp256k1",
        "pubkeyhash",
        "pubkeyhash-ed25519",
        "pubkeyhash-schnorr-secp256k1",
        "scripthash",
        "multisig",
        "nulldata",
        "stakesubmission-pubkeyhash",
        "stakesubmission-scripthash",
        "stakegen-pubkeyhash",
        "stakegen-scripthash",
        "stakerevoke-pubkeyhash",
        "stakerevoke-scripthash",
        "stakechange-pubkeyhash",
        "stakechange-scripthash",
        "treasuryadd",
        "treasurygen-pubkeyhash",
        "treasurygen-scripthash",
    ] {
        assert!(
            types.contains(name),
            "no template classified as {name}: {types:?}"
        );
    }

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        for (net, params) in networks() {
            let script = near_standard_script(&mut rng, &params);
            // Mostly version 0, occasionally others.
            let version = if rng.below(8) == 0 {
                rng.below(3) as u16 + 1
            } else {
                0
            };

            let ours = analyze_ours(version, &script, &params);
            let theirs = analyze_theirs(&mut oracle, net, version, &script);
            assert_eq!(
                ours,
                theirs,
                "{net}: stdscript divergence at round {round} version {version}: {}",
                hex(&script)
            );
        }
    }
}
