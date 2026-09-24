// SPDX-License-Identifier: ISC
//! Address fuzz target: base58, base58check and version 0 address
//! decoding, on all four networks.
//!
//! These parse strings a user or an RPC client supplies (`getaddressinfo`,
//! `validateaddress`, the mining address options).  Beyond not panicking,
//! anything accepted must re-encode to the text it came from: base58 is a
//! bijection once its leading ones are counted as zero bytes, and an
//! address that decodes for a network names exactly the payload its
//! string form encodes (dcrd `DecodeAddress` and `Address.String`), with
//! one exception dcrd has too: an Ed25519 public key address accepts the
//! secp256k1 odd-Y flag in its identifier byte and prints without it.
//!
//! The first byte picks one of two modes.  Raw text exercises the base58
//! and base58check layers, but mutation cannot satisfy base58check's
//! BLAKE-256 checksum, which base58 smears across the whole string, so
//! raw text almost never reaches the address decoder behind it.  The
//! other mode builds a well-formed string instead: a byte picks a network
//! and one of its five address IDs, the rest is the payload, and the
//! target check-encodes them, so every input reaches `DecodeAddressV0`'s
//! dispatch on the ID and the payload checks after it.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;

use dcroxide_chaincfg::Params;
use dcroxide_txscript::stdaddr::decode_address;

static NETS: LazyLock<[Params; 4]> = LazyLock::new(|| {
    [
        dcroxide_chaincfg::mainnet_params(),
        dcroxide_chaincfg::testnet3_params(),
        dcroxide_chaincfg::simnet_params(),
        dcroxide_chaincfg::regnet_params(),
    ]
});

/// A network's version 0 address IDs, in the order `DecodeAddressV0`
/// tests them; the first four take a 20-byte hash.
fn address_ids(params: &Params) -> [[u8; 2]; 5] {
    [
        params.script_hash_addr_id,
        params.pub_key_hash_addr_id,
        params.pkh_schnorr_addr_id,
        params.pkh_edwards_addr_id,
        params.pub_key_addr_id,
    ]
}

/// The string an address decoded from `text` prints as: `text` itself,
/// unless it is an Ed25519 public key address whose identifier byte
/// carries the secp256k1 odd-Y flag.  `DecodeAddressV0` masks that flag
/// off before testing the signature type, and the key's `String` writes
/// the bare type, `STEd25519` (dcrd does the same; QUIRKS.md).
fn printed_as(text: &str, params: &Params) -> String {
    if let Ok((mut payload, id)) = dcroxide_base58::check_decode(text)
        && id == params.pub_key_addr_id
        && payload.first() == Some(&0x81)
    {
        payload[0] = 0x01;
        return dcroxide_base58::check_encode(&payload, id);
    }
    text.to_string()
}

/// Decode `text` on every network: whatever decodes must print as `text`
/// (see [`printed_as`]) and build each of its scripts without panicking.
fn decode_on_every_network(text: &str) {
    for params in NETS.iter() {
        if let Ok(addr) = decode_address(text, params) {
            assert_eq!(
                addr.to_string(),
                printed_as(text, params),
                "{} address round trip",
                params.name
            );
            let _ = addr.payment_script();
            let _ = addr.voting_rights_script();
            let _ = addr.stake_change_script();
            let _ = addr.pay_vote_commitment_script();
            let _ = addr.pay_revoke_commitment_script();
            let _ = addr.pay_from_treasury_script();
        }
    }
}

fn raw_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // An empty result is dcrd's answer for text outside the alphabet.
    let decoded = dcroxide_base58::decode(text);
    if !decoded.is_empty() {
        assert_eq!(dcroxide_base58::encode(&decoded), text, "base58 round trip");
    }
    if let Ok((payload, version)) = dcroxide_base58::check_decode(text) {
        assert_eq!(
            dcroxide_base58::check_encode(&payload, version),
            text,
            "base58check round trip"
        );
    }

    decode_on_every_network(text);
}

fn built(data: &[u8]) {
    let Some((&pick, payload)) = data.split_first() else {
        return;
    };
    let params = &NETS[usize::from(pick & 3)];
    let kind = usize::from(pick >> 2) % 5;
    let text = dcroxide_base58::check_encode(payload, address_ids(params)[kind]);

    decode_on_every_network(&text);

    // Any 20 bytes are a hash, so under a hash ID they are an address on
    // that ID's network.
    if kind < 4 && payload.len() == 20 {
        assert!(
            decode_address(&text, params).is_ok(),
            "{} hash address {text} refused",
            params.name
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        raw_text(rest);
    } else {
        built(rest);
    }
});
