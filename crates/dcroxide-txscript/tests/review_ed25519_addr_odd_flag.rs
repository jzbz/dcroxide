// SPDX-License-Identifier: ISC
//! dcrd's `DecodeAddressV0` masks the secp256k1 odd-Y flag (`0x80`) off a
//! public key address's identifier byte before it tests the signature
//! type, so an Ed25519 key, which has no Y oddness, decodes from an
//! identifier of `0x81` as well as `0x01`, and `String` always writes
//! `0x01`.  One address, two strings: the first does not round-trip.
//! Found by the `address_decode` fuzz target's round-trip check.  Both
//! strings and the decoded form are dcrd's, from `stdaddr` at the pin.

use dcroxide_txscript::stdaddr::decode_address;

#[test]
fn ed25519_pubkey_address_ignores_the_odd_flag() {
    let params = dcroxide_chaincfg::mainnet_params();
    // Identifier byte 0x81, then the 32-byte key.
    let flagged = "DkRMEdMtVspm5cmGymZTiCzfVEmqom8XuQgEeZoBPhoQ8xAvBaCCi";
    // The same payload with identifier byte 0x01.
    let canonical = "DkM4RLnD3nkJWdWGbVXGGJuck7ZEyqvQ3KxRana1LxZXHK1PfSUgx";
    for text in [flagged, canonical] {
        let addr = decode_address(text, &params).expect("dcrd decodes it");
        assert_eq!(addr.to_string(), canonical, "{text}");
    }
}
