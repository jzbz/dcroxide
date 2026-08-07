// SPDX-License-Identifier: ISC
//! Property tests for the codec laws (project brief §7 layer 2):
//! `encode(decode(bytes)) == consumed prefix` and decode-never-panics for
//! arbitrary input, plus varint round-trips. These run without the oracle,
//! so they hold on machines without a Go toolchain too.

use proptest::prelude::*;

use dcroxide_wire::{
    BlockHeader, Cursor, MsgTx, read_var_int, var_int_serialize_size, write_var_int,
};

proptest! {
    #[test]
    fn varint_round_trip(val in any::<u64>()) {
        let mut buf = Vec::new();
        write_var_int(&mut buf, val);
        prop_assert_eq!(buf.len(), var_int_serialize_size(val));
        let mut r = Cursor::new(&buf);
        prop_assert_eq!(read_var_int(&mut r), Ok(val));
        prop_assert_eq!(r.position(), buf.len());
    }

    #[test]
    fn varint_decode_encode_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..10)) {
        let mut r = Cursor::new(&bytes);
        if let Ok(val) = read_var_int(&mut r) {
            let mut buf = Vec::new();
            write_var_int(&mut buf, val);
            // Canonical enforcement means the consumed bytes are exactly the
            // canonical encoding.
            prop_assert_eq!(buf.as_slice(), &bytes[..r.position()]);
        }
    }

    #[test]
    fn msgtx_decode_reencode_is_identity(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok((tx, consumed)) = MsgTx::from_bytes(&bytes) {
            let reencoded = tx.serialize();
            prop_assert_eq!(reencoded.as_slice(), &bytes[..consumed]);
            prop_assert_eq!(tx.serialize_size(), consumed);
            // Hash computation must not panic on any decodable transaction.
            let _ = tx.tx_hash_full();
        }
    }

    #[test]
    fn blockheader_decode_reencode_is_identity(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok((header, consumed)) = BlockHeader::from_bytes(&bytes) {
            prop_assert_eq!(consumed, 180);
            let reencoded = header.serialize();
            prop_assert_eq!(&reencoded[..], &bytes[..consumed]);
            let _ = header.block_hash();
        }
    }
}

/// QK-0010: a `mixdcnet` frame declaring zero mix vectors decodes, and the
/// message it produces cannot be re-encoded.
///
/// `readMixVects` returns with no vectors and no error the moment the outer
/// dimension reads zero, never reaching the inner dimensions or any minimum
/// check, while `writeMessageNoSignature` rejects `mcount == 0` outright.
/// Both directions are observable to a peer — the decoder decides whether
/// the sender is banned, the encoder whether the node relays — so the
/// asymmetry is reproduced rather than smoothed over, and pinned here so it
/// cannot silently change in either direction.
#[test]
fn qk_0010_empty_mixdcnet_decodes_but_does_not_reencode() {
    use dcroxide_wire::{CurrencyNet, PROTOCOL_VERSION, write_message};

    // signature(64) + identity(33) + session id(32) + run(4), then a
    // single-byte varint 0 for the mix-vector count, then a varint 0 for
    // the seen-slot-reserve count.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0u8; 64]);
    payload.extend_from_slice(&[0u8; 33]);
    payload.extend_from_slice(&[0u8; 32]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0); // mix vector count
    payload.push(0); // seen slot reserves count

    let net = CurrencyNet::MAIN_NET;
    let checksum = dcroxide_chainhash::hash_b(&payload);
    let mut frame = Vec::new();
    frame.extend_from_slice(&net.0.to_le_bytes());
    let mut command = [0u8; 12];
    command[.."mixdcnet".len()].copy_from_slice(b"mixdcnet");
    frame.extend_from_slice(&command);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&checksum[..4]);
    frame.extend_from_slice(&payload);

    let (msg, consumed) = dcroxide_wire::read_message(&frame, PROTOCOL_VERSION, net)
        .expect("dcrd's readMixVects accepts a zero outer dimension");
    assert_eq!(consumed, frame.len());

    let dcnet = match &msg {
        dcroxide_wire::Message::MixDCNet(m) => m,
        other => panic!("expected a mixdcnet message, got {other:?}"),
    };
    assert!(
        dcnet.dc_net.is_empty(),
        "the decoder must produce an empty DC-net, not reject the frame"
    );

    let err = write_message(&msg, PROTOCOL_VERSION, net)
        .expect_err("dcrd's writeMessageNoSignature rejects mcount == 0");
    assert!(
        matches!(err, dcroxide_wire::WireError::InvalidMsg),
        "expected dcrd's ErrInvalidMsg identity, got {err:?}"
    );
}
