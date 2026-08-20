// SPDX-License-Identifier: ISC
//! The JSON-RPC envelope's field matching follows Go's (RVW-060,
//! RVW-061).
//!
//! Go unmarshals a JSON object key *before* matching it to a struct
//! field, and matches with `foldName` rather than an ASCII comparison.
//! The port took the key as raw text with its escapes undecoded and
//! compared ASCII-insensitively, so two shapes dcrd honours were
//! ignored -- and ignoring the `method` member does not fail loudly, it
//! runs a different command, or none.

use dcroxide_rpc::dispatch::RPC_ASK_WALLET;
use dcroxide_rpc::http::unmarshal_request;

/// `m` is `m`: the same key, spelled so a raw comparison misses it.
#[test]
fn an_escaped_method_key_still_names_the_method() {
    // The JSON text carries a \u escape, which decodes to `method`.
    let req =
        unmarshal_request(r#"{"\u006dethod":"getblockcount","id":1}"#).expect("a valid request");
    assert_eq!(
        req.method, "getblockcount",
        "Go decodes the key before matching, so this names `method`",
    );
}

/// U+017F and U+212A are the only runes whose Unicode fold reaches
/// ASCII, which is what makes them the whole of Go's `foldName` for
/// ASCII field names.
#[test]
fn the_two_folding_runes_name_their_ascii_fields() {
    let req = unmarshal_request("{\"j\u{017f}onrpc\":\"2.0\",\"method\":\"x\"}")
        .expect("a valid request");
    assert_eq!(req.jsonrpc, "2.0", "U+017F folds to 's' in Go");

    let req = unmarshal_request("{\"method\":\"getbloc\u{212a}count\",\"i\u{212a}\":1}")
        .expect("a valid request");
    assert_eq!(
        req.method, "getbloc\u{212a}count",
        "the folding applies to the key, never to the value",
    );
}

/// An ordinary non-ASCII key must still not match, or the fold above
/// would be indiscriminate.
#[test]
fn an_unrelated_non_ascii_key_is_ignored() {
    let req = unmarshal_request(r#"{"méthod":"getblockcount","method":"getinfo"}"#)
        .expect("a valid request");
    assert_eq!(req.method, "getinfo", "only the real key may bind");
}

/// Go keeps the last duplicate, which decides which command runs.
#[test]
fn the_last_duplicate_method_wins() {
    let req = unmarshal_request(r#"{"method":"getinfo","method":"getblockcount"}"#)
        .expect("a valid request");
    assert_eq!(req.method, "getblockcount");
}

/// dcrd's `rpcAskWallet` decides whether an unregistered method answers
/// "this is a wallet command" or "unknown method", so drift in it flips
/// the error code a caller sees.
#[test]
fn the_wallet_method_list_matches_dcrds() {
    // dcrd `internal/rpcserver/rpcserver.go:257-334`, verbatim.
    const DCRD: &[&str] = &[
        "abandontransaction",
        "accountaddressindex",
        "accountsyncaddressindex",
        "addmultisigaddress",
        "addticket",
        "addtransaction",
        "auditreuse",
        "consolidate",
        "createmultisig",
        "createnewaccount",
        "createsignature",
        "discoverusage",
        "dumpprivkey",
        "fundrawtransaction",
        "generatevote",
        "getaccount",
        "getaccountaddress",
        "getaddressesbyaccount",
        "getbalance",
        "getcoinjoinsbyacct",
        "getmasterpubkey",
        "getmultisigoutinfo",
        "getnewaddress",
        "getrawchangeaddress",
        "getreceivedbyaccount",
        "getreceivedbyaddress",
        "getstakeinfo",
        "gettickets",
        "gettransaction",
        "getunconfirmedbalance",
        "getvotechoices",
        "getwalletfee",
        "importcfiltersv2",
        "importprivkey",
        "importscript",
        "importxpub",
        "listaccounts",
        "listaddresstransactions",
        "listalltransactions",
        "listlockunspent",
        "listreceivedbyaccount",
        "listreceivedbyaddress",
        "listsinceblock",
        "listtransactions",
        "listunspent",
        "lockunspent",
        "mixoutput",
        "purchaseticket",
        "redeemmultisigout",
        "redeemmultisigouts",
        "renameaccount",
        "rescanwallet",
        "revoketickets",
        "sendfrom",
        "sendfromtreasury",
        "sendmany",
        "sendtoaddress",
        "sendtomultisig",
        "sendtotreasury",
        "setticketfee",
        "settxfee",
        "setvotechoice",
        "signmessage",
        "signrawtransaction",
        "signrawtransactions",
        "sweepaccount",
        "ticketinfo",
        "validatepredcp0005cf",
        "verifymessage",
        "walletinfo",
        "walletislocked",
        "walletlock",
        "walletpassphrase",
        "walletpassphrasechange",
        "walletpubpassphrasechange",
    ];

    let mut ours: Vec<&str> = RPC_ASK_WALLET.to_vec();
    ours.sort_unstable();
    let mut theirs: Vec<&str> = DCRD.to_vec();
    theirs.sort_unstable();

    let extra: Vec<&&str> = ours.iter().filter(|m| !theirs.contains(m)).collect();
    let missing: Vec<&&str> = theirs.iter().filter(|m| !ours.contains(m)).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "wallet method list drifted from dcrd's -- extra: {extra:?}, missing: {missing:?}",
    );
}
