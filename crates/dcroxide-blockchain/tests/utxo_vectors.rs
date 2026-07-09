// SPDX-License-Identifier: ISC
//! dcrd's UTXO serialization test vectors, extracted mechanically from
//! internal/blockchain `compress_test.go` and `utxoio_test.go` at the
//! pinned tag (dcrd keeps these in an internal package the oracle
//! cannot import), plus randomized round-trip property tests.

use core::str::FromStr;

use dcroxide_blockchain::{UtxoEntry, UtxoSetState, compress};
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::{SplitMix64, hex, unhex};
use dcroxide_wire::OutPoint;

fn opt_bytes(field: &str) -> Vec<u8> {
    if field == "-" {
        Vec::new()
    } else {
        unhex(field)
    }
}

fn tx_type_from(raw: u8) -> TxType {
    match raw {
        0 => TxType::Regular,
        1 => TxType::SStx,
        2 => TxType::SSGen,
        3 => TxType::SSRtx,
        4 => TxType::TAdd,
        5 => TxType::TSpend,
        _ => TxType::TreasuryBase,
    }
}

/// dcrd TestVLQ, TestAmountCompression, TestScriptCompression, and
/// TestCompressedTxOut, replayed from the extracted tables.
#[test]
fn compress_vectors() {
    let data = include_str!("data/compress_vectors.txt");
    let mut counts = [0usize; 4];
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "vlq" => {
                let val: u64 = f[1].parse().expect("val");
                let serialized = unhex(f[2]);
                assert_eq!(
                    compress::serialize_size_vlq(val),
                    serialized.len(),
                    "{line}: size"
                );
                let mut buf = vec![0u8; serialized.len()];
                assert_eq!(compress::put_vlq(&mut buf, val), serialized.len(), "{line}");
                assert_eq!(buf, serialized, "{line}: encode");
                let (got, read) = compress::deserialize_vlq(&serialized);
                assert_eq!((got, read), (val, serialized.len()), "{line}: decode");
                counts[0] += 1;
            }
            "amount" => {
                let uncompressed: u64 = f[1].parse().expect("unc");
                let compressed: u64 = f[2].parse().expect("comp");
                assert_eq!(
                    compress::compress_tx_out_amount(uncompressed),
                    compressed,
                    "{line}: compress"
                );
                assert_eq!(
                    compress::decompress_tx_out_amount(compressed),
                    uncompressed,
                    "{line}: decompress"
                );
                counts[1] += 1;
            }
            "script" => {
                let version: u16 = f[1].parse().expect("ver");
                let uncompressed = opt_bytes(f[2]);
                let compressed = unhex(f[3]);
                assert_eq!(
                    compress::compressed_script_size(version, &uncompressed),
                    compressed.len(),
                    "{line}: size"
                );
                let mut buf = vec![0u8; compressed.len()];
                let written = compress::put_compressed_script(&mut buf, version, &uncompressed);
                assert_eq!(written, compressed.len(), "{line}: written");
                assert_eq!(buf, compressed, "{line}: compress");
                assert_eq!(
                    compress::decode_compressed_script_size(&compressed),
                    compressed.len() as i64,
                    "{line}: decoded size"
                );
                assert_eq!(
                    compress::decompress_script(&compressed),
                    uncompressed,
                    "{line}: decompress"
                );
                counts[2] += 1;
            }
            "txout" => {
                let amount: u64 = f[1].parse().expect("amount");
                let version: u16 = f[2].parse().expect("ver");
                let pk_script = opt_bytes(f[3]);
                let compressed = unhex(f[4]);
                let has_amount: bool = f[5].parse().expect("bool");
                assert_eq!(
                    compress::compressed_tx_out_size(amount, version, &pk_script, has_amount),
                    compressed.len(),
                    "{line}: size"
                );
                let mut buf = vec![0u8; compressed.len()];
                let written = compress::put_compressed_tx_out(
                    &mut buf, amount, version, &pk_script, has_amount,
                );
                assert_eq!(written, compressed.len(), "{line}: written");
                assert_eq!(buf, compressed, "{line}: compress");
                let (got_amount, got_version, got_script, read) =
                    compress::decode_compressed_tx_out(&compressed, has_amount)
                        .expect("decode succeeds");
                assert_eq!(read, compressed.len(), "{line}: read");
                let want_amount = if has_amount { amount as i64 } else { 0 };
                assert_eq!(got_amount, want_amount, "{line}: amount");
                assert_eq!(got_version, version, "{line}: version");
                assert_eq!(got_script, pk_script, "{line}: script");
                counts[3] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [21, 9, 11, 5], "expected all extracted rows");
}

/// dcrd TestUtxoSerialization, TestOutpointKey, and
/// TestUtxoSetStateSerialization, replayed from the extracted tables.
#[test]
fn utxoio_vectors() {
    let data = include_str!("data/utxoio_vectors.txt");
    let mut counts = [0usize; 3];
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "entry" => {
                let amount: i64 = f[1].parse().expect("amount");
                let pk_script = opt_bytes(f[2]);
                let min_outs = if f[3] == "-" { None } else { Some(unhex(f[3])) };
                let block_height: u32 = f[4].parse().expect("height");
                let block_index: u32 = f[5].parse().expect("index");
                let script_version: u16 = f[6].parse().expect("ver");
                let coinbase = f[7] == "1";
                let has_expiry = f[8] == "1";
                let tx_type = tx_type_from(f[9].parse().expect("type"));
                let spent = f[10] == "1";
                let serialized = if f[11] == "-" {
                    None
                } else {
                    Some(unhex(f[11]))
                };
                let tx_out_index: u32 = f[12].parse().expect("txOutIndex");

                let mut entry = UtxoEntry::new(
                    amount,
                    pk_script,
                    block_height,
                    block_index,
                    script_version,
                    coinbase,
                    has_expiry,
                    tx_type,
                    min_outs,
                );
                if spent {
                    entry.spend();
                }

                assert_eq!(
                    dcroxide_blockchain::serialize_utxo_entry(&entry),
                    serialized,
                    "{line}: serialize"
                );

                if let Some(serialized) = serialized {
                    let got =
                        dcroxide_blockchain::deserialize_utxo_entry(&serialized, tx_out_index)
                            .expect("deserialize succeeds");
                    assert_eq!(got, entry, "{line}: deserialize");
                }
                counts[0] += 1;
            }
            "outpoint" => {
                let hash = Hash::from_str(f[1]).expect("hash");
                let index: u32 = f[2].parse().expect("index");
                let tree: i8 = f[3].parse().expect("tree");
                let serialized = unhex(f[4]);
                let outpoint = OutPoint { hash, index, tree };
                assert_eq!(
                    hex(&dcroxide_blockchain::outpoint_key(&outpoint)),
                    hex(&serialized),
                    "{line}: key"
                );
                assert_eq!(
                    dcroxide_blockchain::decode_outpoint_key(&serialized).expect("decode"),
                    outpoint,
                    "{line}: decode"
                );
                counts[1] += 1;
            }
            "state" => {
                let state = UtxoSetState {
                    last_flush_height: f[1].parse().expect("height"),
                    last_flush_hash: Hash::from_str(f[2]).expect("hash"),
                };
                let serialized = unhex(f[3]);
                assert_eq!(
                    dcroxide_blockchain::serialize_utxo_set_state(&state),
                    serialized,
                    "{line}: serialize"
                );
                assert_eq!(
                    dcroxide_blockchain::deserialize_utxo_set_state(&serialized)
                        .expect("deserialize"),
                    state,
                    "{line}: deserialize"
                );
                counts[2] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [7, 2, 2], "expected all extracted rows");
}

/// Randomized round trips over the whole serialization surface.
/// A corrupt compressed script size below the special-script count
/// wraps negative exactly like dcrd's unsigned subtraction and `int`
/// conversion, and the txout decoder rejects it with dcrd's "negative
/// script size" error instead of panicking.
#[test]
fn corrupt_script_size_discriminants_wrap_negative() {
    // VLQ 10 is above the special encodings (0-5) but below the
    // NUM_SPECIAL_SCRIPTS bias of 64: 10 - 64 + 1 byte read = -53.
    assert_eq!(compress::decode_compressed_script_size(&[10]), -53);

    // Script version 0 followed by the corrupt size discriminant.
    let err = compress::decode_compressed_tx_out(&[0x00, 10], false)
        .expect_err("a negative script size must be rejected");
    assert_eq!(err.to_string(), "deserialize error: negative script size");
}

#[test]
fn round_trip_properties() {
    let mut rng = SplitMix64::from_entropy("utxo-round-trips");

    for _ in 0..2000 {
        // VLQ.
        let val = match rng.below(4) {
            0 => rng.below(1 << 8),
            1 => rng.below(1 << 21),
            2 => rng.below(1 << 42),
            _ => rng.next_u64(),
        };
        let mut buf = vec![0u8; compress::serialize_size_vlq(val)];
        compress::put_vlq(&mut buf, val);
        assert_eq!(compress::deserialize_vlq(&buf), (val, buf.len()));

        // Amounts (biased toward round numbers like real outputs).
        let amount = match rng.below(3) {
            0 => rng.below(1 << 16) * 100_000_000,
            1 => rng.below(1 << 30) * 1000,
            _ => rng.below(1 << 44),
        };
        assert_eq!(
            compress::decompress_tx_out_amount(compress::compress_tx_out_amount(amount)),
            amount
        );

        // Generic scripts round-trip through compression.
        let script = rng.bytes(64);
        let size = compress::compressed_script_size(0, &script);
        let mut buf = vec![0u8; size];
        compress::put_compressed_script(&mut buf, 0, &script);
        assert_eq!(compress::decode_compressed_script_size(&buf), size as i64);
        assert_eq!(compress::decompress_script(&buf), script);

        // Outpoint keys.
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        let outpoint = OutPoint {
            hash: Hash(hash),
            index: rng.next_u64() as u32,
            tree: (rng.below(3) as i8) - 1,
        };
        let key = dcroxide_blockchain::outpoint_key(&outpoint);
        assert_eq!(
            dcroxide_blockchain::decode_outpoint_key(&key).expect("decode"),
            outpoint
        );
    }
}
