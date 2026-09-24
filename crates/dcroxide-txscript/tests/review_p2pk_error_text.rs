// SPDX-License-Identifier: ISC
//! A P2PK address whose key does not parse fails with dcrd's text: stdaddr
//! wraps the dcrec error with `failed to parse public key: %v`
//! (txscript/stdaddr/addressv0.go), and the RPC handlers that decode
//! addresses return that to clients.  The port printed the Rust variant
//! name through `{:?}` instead (`...: PubKeyNotOnCurve`).

use dcroxide_chaincfg::mainnet_params;
use dcroxide_testutil::{oracle_or_skip, unhex};
use dcroxide_txscript::stdaddr::{self, AddressParamsV0};

/// A version 0 P2PK address string for the signature type and x
/// coordinate (dcrd's encoding: the type byte, with the y-oddness flag in
/// its high bit, then the 32-byte x).
fn p2pk_address(sig_type: u8, odd_y: bool, x: &[u8]) -> String {
    let params = mainnet_params();
    let mut data = vec![sig_type | if odd_y { 0x80 } else { 0 }];
    data.extend_from_slice(x);
    dcroxide_base58::check_encode(&data, params.addr_id_pub_key_v0())
}

/// x coordinates that fail secp256k1 parsing: one with no curve point and
/// one at the field prime.
const OFF_CURVE_X: &str = "ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4c";
const PRIME_X: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

fn cases() -> Vec<(String, String)> {
    let mut out = Vec::new();
    // ECDSA (type 0) and Schnorr (type 2), both oddness flags.
    for sig_type in [0u8, 2] {
        for odd_y in [false, true] {
            out.push((
                p2pk_address(sig_type, odd_y, &unhex(OFF_CURVE_X)),
                format!(
                    "failed to parse public key: invalid public key: x coordinate {OFF_CURVE_X} \
                     is not on the secp256k1 curve"
                ),
            ));
            out.push((
                p2pk_address(sig_type, odd_y, &unhex(PRIME_X)),
                "failed to parse public key: invalid public key: x >= field prime".to_string(),
            ));
        }
    }
    out
}

#[test]
fn p2pk_parse_failures_carry_dcrds_text() {
    let params = mainnet_params();
    for (addr, want) in cases() {
        let err = stdaddr::decode_address(&addr, &params).expect_err(&addr);
        assert_eq!(err.kind.kind_name(), "ErrInvalidPubKey", "{addr}");
        assert_eq!(err.to_string(), want, "{addr}");
    }
}

#[test]
fn p2pk_parse_failure_text_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let params = mainnet_params();
    for (addr, _) in cases() {
        let ours = stdaddr::decode_address(&addr, &params).expect_err(&addr);
        let net = "mainnet";
        let mut req = Vec::new();
        req.push(net.len() as u8);
        req.extend_from_slice(net.as_bytes());
        req.extend_from_slice(&[0u8; 24]);
        req.extend_from_slice(addr.as_bytes());
        let resp = oracle.call("stdaddr_decode", &req);
        assert_eq!(
            resp["error"].as_str(),
            Some(ours.to_string().as_str()),
            "{addr}"
        );
        assert_eq!(resp["kind"].as_str(), Some(ours.kind.kind_name()), "{addr}");
    }
}
