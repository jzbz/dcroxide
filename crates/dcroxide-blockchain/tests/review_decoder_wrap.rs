// SPDX-License-Identifier: ISC
//! Stored-row decoders whose Go arithmetic wraps on corrupt input.
//!
//! dcrd's `deserializeTreasuryState` negates a debit's int64 amount, which
//! wraps on a corrupt row rather than failing.  The port's release build
//! wrapped the same way, but debug, test and fuzz builds panicked on the
//! plain operator, which the `db_record_decode` fuzz target hit within
//! seconds.  The expected value is Go's, from dcrd's function over the
//! same input.  (The target's other two wrap sites, in `deserializeVLQ`
//! and `decompressTxOutAmount`, are fixed and pinned in `compress.rs`.)

use dcroxide_blockchain::compress::put_vlq;
use dcroxide_blockchain::treasurydb::deserialize_treasury_state;

#[test]
fn treasury_debit_of_min_int64_wraps_like_go() {
    // Balance 0, one value: a treasury spend (flag 0x04) stored as 2^63,
    // which Go reads as MinInt64 and negates back to MinInt64.
    let mut row = [0u8; 16];
    let mut n = put_vlq(&mut row, 0);
    n += put_vlq(&mut row[n..], 1);
    n += put_vlq(&mut row[n..], 0x04);
    n += put_vlq(&mut row[n..], 1 << 63);
    let ts = deserialize_treasury_state(&row[..n]).expect("decodes");
    assert_eq!(ts.values.len(), 1);
    assert_eq!(ts.values[0].amount, i64::MIN);
}
