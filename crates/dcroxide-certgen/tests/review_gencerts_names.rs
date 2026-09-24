// SPDX-License-Identifier: ISC
//! gencerts authorities against Go's, byte for byte.
//!
//! The expected certificates come from dcrd `cmd/gencerts`'
//! `newTemplate` and `generateAuthority` at b9634e01, run line for line
//! as a Go 1.25 main module (dcrd's root module's `go` line) with the
//! clock, serial and Ed25519 seed pinned to this file's.  Ed25519
//! signatures are deterministic, so the whole certificate compares.
//!
//! Each row exercises what the port used to get wrong on this path: the
//! SubjectKeyIdentifier (SHA-1 where Go 1.25 writes truncated SHA-256),
//! `*` and `&` in a name (PrintableString where Go's marshaller writes
//! UTF8String), IDNA (UTS-46 lowercasing where Go's `idna.ToASCII`
//! keeps case), and an empty CommonName (written where Go leaves it out).

use dcroxide_certgen::gentool::{GenEnv, ToolKeyPair, generate_authority};
use dcroxide_testutil::unhex;

/// `-H '*.example.com' -H 'Bücher.Example' -H 127.0.0.1 -o 'Smith & Co'`.
const NAMES: &str = "3082019130820143a00302010202100101010101010101010101010101010130\
     0506032b6570302d31133011060355040a0c0a536d697468202620436f311630\
     1406035504030c0d2a2e6578616d706c652e636f6d301e170d32353037303731\
     38343030305a170d3335303730363138343030305a302d31133011060355040a\
     0c0a536d697468202620436f3116301406035504030c0d2a2e6578616d706c65\
     2e636f6d302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7\
     901f853ae695bed7e0e3910bad049664a3793077300e0603551d0f0101ff0404\
     03020284300f0603551d130101ff040530030101ff301d0603551d0e04160414\
     65b60673d6ed884bf01c2c222d82ada0740f29ac30350603551d11042e302c82\
     0d2a2e6578616d706c652e636f6d8215786e2d2d42636865722d6b76612e4578\
     616d706c6587047f000001300506032b657003410099cf0902a907c7a5b70533\
     db2ffda7ad6e29d3e52a345ea53af4374a79a7c87fff2c53665f106cff265b2b\
     b8ba5c32aef9acebd85fd65f643d7747a82bedb00e";

/// `-o ''` with no hosts.
const EMPTY: &str = "308201153081c8a0030201020210010101010101010101010101010101013005\
     06032b6570300b31093007060355040a1300301e170d32353037303731383430\
     30305a170d3335303730363138343030305a300b31093007060355040a130030\
     2a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae6\
     95bed7e0e3910bad049664a3423040300e0603551d0f0101ff04040302028430\
     0f0603551d130101ff040530030101ff301d0603551d0e0416041465b60673d6\
     ed884bf01c2c222d82ada0740f29ac300506032b65700341000c4a839d229d50\
     051dd3569ed638e05c2e30d24000e133be45838d4191fe781b9fdba8391f30c1\
     d55a4c7f09a5f5a59788184915b8df3e7f19f595ec3fdef40b";

/// The clock and serial the Go dump pinned.
struct FixedEnv;

impl GenEnv for FixedEnv {
    fn now_unix(&mut self) -> i64 {
        1_752_000_000
    }

    fn serial_bytes(&mut self) -> Vec<u8> {
        vec![1; 16]
    }
}

fn seed_key() -> ToolKeyPair {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    ToolKeyPair::Ed25519(seed)
}

#[test]
fn an_authority_matches_go_byte_for_byte() {
    let hosts: Vec<String> = ["*.example.com", "Bücher.Example", "127.0.0.1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let ca = generate_authority(&mut FixedEnv, &seed_key(), &hosts, "Smith & Co", 10, true)
        .expect("authority");
    assert_eq!(ca.der, unhex(NAMES));
}

#[test]
fn an_empty_common_name_is_left_out() {
    let ca = generate_authority(&mut FixedEnv, &seed_key(), &[], "", 10, true).expect("authority");
    assert_eq!(ca.der, unhex(EMPTY));
}
