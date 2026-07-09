// SPDX-License-Identifier: ISC
//! Hostile-parameter behavior for the GCS filters, pinned against real
//! dcrd `gcs/v4` runs.  Go's uint64 arithmetic wraps silently where the
//! port previously overflowed: the zero-entry largest difference in
//! `MaxFilterV2Size`, its final byte rounding, oversized shift counts
//! (Go yields zero), and a hostile serialized entry count feeding the
//! `FromBytesV2` modulus.

use dcroxide_gcs::{FilterV2, max_filter_v2_size};

/// Values pinned against `gcs.MaxFilterV2Size`, including the N == 0
/// wrap with the real blockcf2 parameters, the B == 0 rounding wrap,
/// and a shift count of 64.
#[test]
fn max_filter_v2_size_matches_go_on_wrapping_inputs() {
    assert_eq!(max_filter_v2_size(19, 784_931, 0), 4_398_046_511_105);
    assert_eq!(max_filter_v2_size(19, 784_931, 1), 4);
    assert_eq!(max_filter_v2_size(0, 1, 0), 1);
    assert_eq!(max_filter_v2_size(64, 1, 0), 1);
}

/// A serialized filter claiming 2^64 - 1 entries deserializes without
/// panicking: Go truncates the count to uint32 for `N`, wraps the
/// modulus, and matches return false against the empty filter data.
#[test]
fn from_bytes_v2_accepts_a_hostile_entry_count_like_go() {
    // wire varint: 0xFF discriminant + 8 bytes = u64::MAX entries.
    let hostile = [0xFFu8; 9];
    let filter = FilterV2::from_bytes(19, 784_931, &hostile).expect("Go accepts this input");
    assert_eq!(filter.n(), u32::MAX);
    assert!(!filter.matches([0u8; 16], b"x"));
}
