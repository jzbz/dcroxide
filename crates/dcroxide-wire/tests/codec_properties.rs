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
