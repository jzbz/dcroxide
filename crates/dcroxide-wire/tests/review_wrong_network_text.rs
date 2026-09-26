// SPDX-License-Identifier: ISC
//! The text of `ReadMessage`'s wrong-network check, against dcrd's own
//! `err.Error()` over the same frame.
//!
//! dcrd builds it as `messageError("ReadMessage", ErrWrongNetwork,
//! fmt.Sprintf("message from other network [%v]", magic))`
//! (`wire/message.go:418-421`), and `%v` on a `CurrencyNet` is its
//! `String` method: the network's name, or `Unknown CurrencyNet (<n>)`
//! with the magic in decimal.  A node reached by another network's
//! peer logs this text after "Can't read message from <peer>: ", and
//! the port used to print the bare magic in hex without the `Func`.
//! The frame differential's corruption test compares only the kind,
//! which says nothing about the description.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_testutil::{SplitMix64, oracle_or_skip};
use dcroxide_wire::{CurrencyNet, Message, MsgPing, PROTOCOL_VERSION, read_message, write_message};

const NETS: [CurrencyNet; 4] = [
    CurrencyNet::MAIN_NET,
    CurrencyNet::TEST_NET3,
    CurrencyNet::REG_NET,
    CurrencyNet::SIM_NET,
];

#[test]
fn wrong_network_text_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("wrong network text differential");
    let msg = Message::Ping(MsgPing { nonce: 7 });

    // Every other known network's magic, and some that are no network.
    let mut magics: Vec<u32> = NETS.iter().map(|n| n.0).collect();
    magics.extend([0, 1, u32::MAX]);
    magics.extend((0..8).map(|_| rng.next_u64() as u32));

    let mut compared = 0;
    for local in NETS {
        for &magic in &magics {
            if magic == local.0 {
                continue;
            }
            let frame = write_message(&msg, PROTOCOL_VERSION, CurrencyNet(magic)).expect("frame");
            let ours = read_message(&frame, PROTOCOL_VERSION, local)
                .expect_err("another network's frame is refused");

            let mut req = Vec::with_capacity(8 + frame.len());
            req.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            req.extend_from_slice(&local.0.to_be_bytes());
            req.extend_from_slice(&frame);
            let resp = oracle.call("wire_msg", &req);
            let theirs = resp["error"].as_str().expect("dcrd refuses the frame");
            assert_eq!(resp["kind"].as_str(), Some("ErrWrongNetwork"), "{resp}");
            assert_eq!(ours.kind_name(), "ErrWrongNetwork");
            assert_eq!(
                ours.to_string(),
                theirs,
                "magic {magic:#010x} read on {local}"
            );
            compared += 1;
        }
    }
    assert!(compared > 40, "only {compared} frames compared");
}
