// SPDX-License-Identifier: ISC
//! stdaddr echoes an address it cannot decode with Go's `%q`
//! (txscript/stdaddr/address.go `DecodeAddress`, addressv0.go
//! `DecodeAddressV0`), and the RPC handlers that decode addresses return
//! that text to clients.  The port formatted it with Rust's `{:?}`, which
//! spells a control character `\u{1}` where Go writes `\x01`, and cut the
//! over-long prefix at 54 characters where dcrd cuts 54 bytes.

use dcroxide_chaincfg::mainnet_params;
use dcroxide_testutil::oracle_or_skip;
use dcroxide_txscript::stdaddr;

/// Inputs and dcrd's `%q` of each (from running Go), none of them shaped
/// like a base58 address, so each fails as an unsupported address.  The
/// runes avoid any whose printability moved between Unicode versions.
const QUOTED: &[(&str, &str)] = &[
    ("abc\u{1}", "\"abc\\x01\""),
    ("a\u{7f}b", "\"a\\x7fb\""),
    ("zero\u{200b}width", "\"zero\\u200bwidth\""),
    ("nb\u{a0}sp", "\"nb\\u00a0sp\""),
    ("tab\there", "\"tab\\there\""),
    ("q\"b\\s", "\"q\\\"b\\\\s\""),
    ("h\u{e9}llo \u{1f600}", "\"h\u{e9}llo \u{1f600}\""),
    ("\u{e000}", "\"\\ue000\""),
    ("", "\"\""),
    ("\0\u{7}\u{8}\u{c}\n\r\u{b}", "\"\\x00\\a\\b\\f\\n\\r\\v\""),
];

#[test]
fn unsupported_address_is_quoted_like_go() {
    let params = mainnet_params();
    for (addr, quoted) in QUOTED {
        let err = stdaddr::decode_address(addr, &params).expect_err(addr);
        assert_eq!(err.kind.kind_name(), "ErrUnsupportedAddress", "{addr:?}");
        assert_eq!(
            err.to_string(),
            format!("address {quoted} is not a supported type"),
            "{addr:?}"
        );
    }
}

/// dcrd slices the first 54 bytes of an over-long address, which here
/// splits the two-byte `é`, and `%q` spells the stray lead byte `\xc3`.
#[test]
fn over_long_address_prefix_is_cut_by_bytes_like_go() {
    let params = mainnet_params();
    let addr = format!("{}\u{e9}", "x".repeat(53));
    assert_eq!(addr.len(), 55);
    let err = stdaddr::decode_address_v0(&addr, &params).expect_err("too long");
    assert_eq!(err.kind.kind_name(), "ErrMalformedAddress");
    assert_eq!(
        err.to_string(),
        format!(
            "failed to decode address \"{}\\xc3\"...: len 55 exceeds max allowed 54",
            "x".repeat(53)
        )
    );
}

#[test]
fn unsupported_address_text_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let params = mainnet_params();
    for (addr, _) in QUOTED {
        let ours = stdaddr::decode_address(addr, &params).expect_err(addr);
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
            "{addr:?}"
        );
        assert_eq!(
            resp["kind"].as_str(),
            Some(ours.kind.kind_name()),
            "{addr:?}"
        );
    }
}
