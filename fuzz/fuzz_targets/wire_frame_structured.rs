// SPDX-License-Identifier: ISC
//! Structured message-frame fuzz target: reaches every message body's
//! decoder instead of dying on the frame's integrity checks.
//!
//! `wire_frame_decode` feeds raw bytes to `read_message`, which validates
//! the network magic and a BLAKE-256 payload checksum before it dispatches
//! on the command.  libFuzzer cannot forge that checksum, so effectively
//! every input is rejected at the header and the forty-one typed decoders
//! behind it are never exercised — the target proves the frame parser
//! rejects garbage and almost nothing else.
//!
//! This target takes a command and a payload, then *builds a valid frame
//! around them*: correct magic, the command padded to twelve bytes, the
//! real length, and a computed checksum.  Every byte libFuzzer controls
//! therefore lands in the payload, where the typed decoder will read it.
//! Cuprate solved the same problem for Monero's levin framing by pinning
//! the protocol signature with `#[arbitrary(value = ...)]`; the checksum
//! here has to be computed rather than pinned, but the intent matches.
//!
//! The assertion is the same canonical-form stability `wire_frame_decode`
//! checks, and deliberately not a strict round-trip against the input:
//! optional trailing fields (`MsgVersion`) and non-canonical but accepted
//! encodings both make that false, matching dcrd.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use dcroxide_wire::{
    COMMAND_SIZE, CurrencyNet, MAX_MESSAGE_PAYLOAD, PROTOCOL_VERSION, read_message, write_message,
};

/// Every command the port frames, so the fuzzer picks a real decoder
/// rather than spending its budget inventing command strings that
/// dispatch nowhere.
const COMMANDS: [&str; 41] = [
    "version",
    "verack",
    "getaddr",
    "addr",
    "addrv2",
    "getblocks",
    "inv",
    "getdata",
    "notfound",
    "block",
    "tx",
    "getheaders",
    "headers",
    "ping",
    "pong",
    "mempool",
    "miningstate",
    "getminings",
    "reject",
    "sendheaders",
    "feefilter",
    "getcfilter",
    "getcfheaders",
    "getcftypes",
    "cfilter",
    "cfheaders",
    "cftypes",
    "getcfilterv2",
    "cfilterv2",
    "getinitstate",
    "initstate",
    "getcfsv2",
    "cfiltersv2",
    "mixpairreq",
    "mixkeyxchg",
    "mixcphrtxt",
    "mixslotres",
    "mixfactpoly",
    "mixdcnet",
    "mixconfirm",
    "mixsecrets",
];

/// A command selector plus the payload bytes to hand its decoder.
#[derive(Arbitrary, Debug)]
struct StructuredFrame {
    /// Reduced modulo the table above, so every draw names a command.
    command_index: u8,
    payload: Vec<u8>,
}

fuzz_target!(|input: StructuredFrame| {
    let command = COMMANDS[usize::from(input.command_index) % COMMANDS.len()];
    if input.payload.len() as u64 > MAX_MESSAGE_PAYLOAD {
        return;
    }

    let net = CurrencyNet::MAIN_NET;
    let checksum = dcroxide_chainhash::hash_b(&input.payload);
    let mut frame = Vec::with_capacity(24 + input.payload.len());
    frame.extend_from_slice(&net.0.to_le_bytes());
    let mut command_field = [0u8; COMMAND_SIZE];
    command_field[..command.len()].copy_from_slice(command.as_bytes());
    frame.extend_from_slice(&command_field);
    frame.extend_from_slice(&(input.payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&checksum[..4]);
    frame.extend_from_slice(&input.payload);

    if let Ok((msg, _consumed)) = read_message(&frame, PROTOCOL_VERSION, net) {
        // A decoded message need not be encodable -- see QK-0010.  This
        // target found that asymmetry within seconds of first running,
        // on a `mixdcnet` frame declaring zero mix vectors.
        let Ok(reencoded) = write_message(&msg, PROTOCOL_VERSION, net) else {
            return;
        };
        let (roundtripped, consumed_again) =
            read_message(&reencoded, PROTOCOL_VERSION, net).expect("re-encoded message decodes");
        assert_eq!(roundtripped, msg, "re-encoding changed the message");
        assert_eq!(
            consumed_again,
            reencoded.len(),
            "re-encoded frame has trailing bytes"
        );
    }
});
