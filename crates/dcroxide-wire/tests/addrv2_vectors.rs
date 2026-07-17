// SPDX-License-Identifier: ISC
// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]
//! The `addrv2` message against dcrd's own behavior: every row in
//! `data/addrv2_vectors.txt` was dumped mechanically inside dcrd at
//! master commit 452c1a6c (the 2.2 pre-release parity target) by
//! driving the real `MsgAddrV2` encode/decode over a case sweep —
//! all address types, wrong lengths, unknown discriminators, count
//! and timestamp bounds, and the protocol version gates, including
//! the partial bytes dcrd leaves behind when an encode errors
//! mid-address.

use dcroxide_wire::{
    Cursor, MsgAddr, MsgAddrV2, NetAddressType, NetAddressV2, ServiceFlag, WireError,
};

/// Rebuild the exporter's synthetic address: `n` bytes of 1..=n.
fn mk_addr(addr_type: NetAddressType, n: usize, port: u16) -> NetAddressV2 {
    let encoded: Vec<u8> = (1..=n as u8).collect();
    NetAddressV2::new(addr_type, encoded, port, 0x495f_ab29, ServiceFlag(1))
}

fn err_name(err: &WireError) -> &'static str {
    err.kind_name()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn addrv2_vectors() {
    let data = include_str!("data/addrv2_vectors.txt");
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "encode" => {
                let (name, pver, want_err, want_hex) =
                    (f[1], f[2].parse::<u32>().expect("pver"), f[3], f[4]);
                let addrs: Vec<NetAddressV2> = match name {
                    "ipv4" => vec![mk_addr(NetAddressType::IPV4, 4, 8333)],
                    "ipv6" => vec![mk_addr(NetAddressType::IPV6, 16, 9108)],
                    "torv3" => vec![mk_addr(NetAddressType::TOR_V3, 32, 9108)],
                    "torv3-port0" => vec![mk_addr(NetAddressType::TOR_V3, 32, 0)],
                    "multi" => vec![
                        mk_addr(NetAddressType::IPV4, 4, 1),
                        mk_addr(NetAddressType::IPV6, 16, 2),
                        mk_addr(NetAddressType::TOR_V3, 32, 3),
                    ],
                    "ipv4-wronglen" => vec![mk_addr(NetAddressType::IPV4, 5, 8333)],
                    "ipv6-wronglen" => vec![mk_addr(NetAddressType::IPV6, 4, 8333)],
                    "torv3-wronglen" => vec![mk_addr(NetAddressType::TOR_V3, 16, 8333)],
                    "unknown-type" => vec![mk_addr(NetAddressType::UNKNOWN, 4, 8333)],
                    "type-9" => vec![mk_addr(NetAddressType(9), 4, 8333)],
                    "empty" => Vec::new(),
                    "old-pver" => vec![mk_addr(NetAddressType::IPV4, 4, 8333)],
                    "zero-ts" => vec![NetAddressV2::new(
                        NetAddressType::IPV4,
                        vec![1, 2, 3, 4],
                        80,
                        0,
                        ServiceFlag(0),
                    )],
                    "max-services" => vec![NetAddressV2::new(
                        NetAddressType::IPV6,
                        vec![0xaa; 16],
                        0xffff,
                        1 << 33,
                        ServiceFlag(u64::MAX),
                    )],
                    "full-1000" => (0..1000u16)
                        .map(|i| mk_addr(NetAddressType::IPV4, 4, i))
                        .collect(),
                    "over-1001" => (0..1001u32)
                        .map(|i| mk_addr(NetAddressType::IPV4, 4, (i % 1001).min(1000) as u16))
                        .collect(),
                    other => panic!("unknown encode case {other}"),
                };
                // The over-1001 exporter appended port 1000 as the
                // final entry after ports 0..999.
                let addrs = if name == "over-1001" {
                    (0..1000u16)
                        .map(|i| mk_addr(NetAddressType::IPV4, 4, i))
                        .chain(std::iter::once(mk_addr(NetAddressType::IPV4, 4, 1000)))
                        .collect()
                } else {
                    addrs
                };
                let msg = MsgAddrV2 { addr_list: addrs };
                let mut w = Vec::new();
                let result = msg.encode(&mut w, pver);
                let got_err = match &result {
                    Ok(()) => "ok".to_string(),
                    Err(e) => err_name(e).to_string(),
                };
                assert_eq!(got_err, want_err, "encode {name}: error mismatch");
                assert_eq!(
                    hex::encode_str(&w),
                    want_hex,
                    "encode {name}: byte mismatch"
                );
            }
            "decode" => {
                let (name, pver, want_err, want_count) = (
                    f[1],
                    f[2].parse::<u32>().expect("pver"),
                    f[3],
                    f[4].parse::<usize>().expect("count"),
                );
                let payloads: &[(&str, &str)] = &[
                    ("count0", "00"),
                    ("count-over", "fde903"),
                    (
                        "bad-type",
                        "0129ab5f490000000001000000000000000401020304a501",
                    ),
                    (
                        "ts-overflow",
                        "01ffffffffffffffff01000000000000000101020304a501",
                    ),
                    (
                        "truncated-addr",
                        "0129ab5f4900000000010000000000000002010203",
                    ),
                    (
                        "old-pver",
                        "0129ab5f490000000001000000000000000101020304a501",
                    ),
                    (
                        "max-ts-ok",
                        "01000000000000000001000000000000000101020304a501",
                    ),
                ];
                let payload = payloads
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, p)| unhex(p))
                    .unwrap_or_else(|| panic!("unknown decode case {name}"));
                let mut r = Cursor::new(&payload);
                match MsgAddrV2::decode(&mut r, pver) {
                    Ok(msg) => {
                        assert_eq!("ok", want_err, "decode {name}: expected error");
                        assert_eq!(msg.addr_list.len(), want_count, "decode {name}: count");
                    }
                    Err(e) => {
                        // dcrd reports short reads as plain io errors.
                        let got = match e {
                            WireError::UnexpectedEof => "io",
                            ref other => err_name(other),
                        };
                        assert_eq!(got, want_err, "decode {name}: error kind");
                    }
                }
            }
            "maxpayload" => {
                let (which, pver, want) = (
                    f[1],
                    f[2].parse::<u32>().expect("pver"),
                    f[3].parse::<u32>().expect("len"),
                );
                let got = match which {
                    "addrv2" => MsgAddrV2::max_payload_length(pver),
                    "addr" => MsgAddr::max_payload_length(pver),
                    other => panic!("unknown maxpayload case {other}"),
                };
                assert_eq!(got, want, "maxpayload {which} pver {pver}");
            }
            other => panic!("unknown row kind {other}"),
        }
    }
}

/// Local hex encoding to avoid a dev-dependency.
mod hex {
    pub fn encode_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
