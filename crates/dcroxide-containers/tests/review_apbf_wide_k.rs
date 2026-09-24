// SPDX-License-Identifier: ISC
//! dcrd's false positive rate recursion computes the slice fill ratio as
//! `float64(i+1) / float64(2*k)` with `k` a uint8 (`container/apbf`
//! `filter.go:61`), so the doubling wraps for k >= 128: k == 128 divides
//! by zero and yields a NaN rate, and k == 200 divides by 144.  The
//! frozen vector corpus stops at k == 12, so these rows pin the wrap.
//!
//! Every constant below was produced by dcrd's own package at the parity
//! pin (b9634e01) through `CalcFPRate`, `NewFilter` and `NewFilterKL`,
//! with the float64 results recorded as IEEE-754 bit patterns.  NaN rows
//! are asserted with `is_nan` rather than by bits, since the NaN payload
//! an `Inf * 0` produces is the host FPU's choice.

use dcroxide_containers::apbf::{calc_fp_rate, new_filter, new_filter_kl};

/// The expected rate as bits, or `None` for dcrd's NaN.
fn check_rate(got: f64, want: Option<u64>, what: &str) {
    match want {
        None => assert!(got.is_nan(), "{what}: want NaN, got {got:e}"),
        Some(bits) => assert_eq!(
            got.to_bits(),
            bits,
            "{what}: want {:e}, got {got:e}",
            f64::from_bits(bits)
        ),
    }
}

#[test]
fn apbf_fp_rate_wraps_two_k_like_dcrd() {
    const ROWS: [(u8, u8, Option<u64>); 18] = [
        (127, 1, Some(0x2d4822d70a4997ef)),
        (127, 2, Some(0x2da80afce475a389)),
        (127, 3, Some(0x2dffef5aba7336e6)),
        (128, 1, None),
        (128, 2, None),
        (128, 3, None),
        (129, 1, Some(0x651b0e814125157e)),
        (129, 2, Some(0x651b0e814125157e)),
        (129, 3, Some(0x65198db2f66a2285)),
        (130, 1, Some(0x5d66e646ba780d84)),
        (130, 2, Some(0x5d700797e8eda310)),
        (130, 3, Some(0x5d718e696cd381d5)),
        (200, 1, Some(0x3487d77a5cdd4ea8)),
        (200, 2, Some(0x34db03152bf8bfcc)),
        (200, 3, Some(0x352467d798535d35)),
        (255, 1, Some(0x29cd5d8b0dd7955f)),
        (255, 2, Some(0x2a2d4085f3dbf98b)),
        (255, 3, Some(0x2a836d4f7d432e79)),
    ];
    for (k, l, want) in ROWS {
        check_rate(calc_fp_rate(k, l), want, &format!("CalcFPRate({k}, {l})"));
    }
}

#[test]
fn apbf_filters_with_wide_k_match_dcrd() {
    // NewFilterKL(100, k, l): FPRate, Capacity, Size.
    const KL: [(u8, u8, Option<u64>, u32, usize); 3] = [
        (128, 2, None, 102, 102104),
        (200, 3, Some(0x352467d798535d35), 100, 183126),
        (255, 1, Some(0x29cd5d8b0dd7955f), 100, 588710),
    ];
    for (k, l, want_rate, want_cap, want_size) in KL {
        let filter = new_filter_kl(100, k, l);
        let what = format!("NewFilterKL(100, {k}, {l})");
        check_rate(filter.fp_rate(), want_rate, &what);
        assert_eq!(filter.capacity(), want_cap, "{what}: capacity");
        assert_eq!(filter.size(), want_size, "{what}: size");
    }

    // NewFilter(100, fp): the chosen K and L follow from the rate
    // recursion, so a wrong rate picks a different L.  At k == 128 every
    // rate is NaN, `NaN > fp` never holds, and dcrd runs L to its cap of
    // 100; widened arithmetic stops at 0 instead.
    const NEW: [(u64, u8, u8, Option<u64>, u32, usize); 4] = [
        (0x37f0000000000000, 128, 100, None, 101, 5343),
        (
            0x3730000000000000,
            140,
            0,
            Some(0x49e15f9c64511988),
            100,
            353535,
        ),
        (
            0x3379b604aaaca626,
            200,
            0,
            Some(0x34250be5d66405e0),
            100,
            721420,
        ),
        (
            0x3696d601ad376ab9,
            150,
            0,
            Some(0x434ecc480914aeac),
            100,
            405839,
        ),
    ];
    for (fp_bits, want_k, want_l, want_rate, want_cap, want_size) in NEW {
        let fp = f64::from_bits(fp_bits);
        let filter = new_filter(100, fp);
        let what = format!("NewFilter(100, {fp:e})");
        assert_eq!((filter.k(), filter.l()), (want_k, want_l), "{what}: K, L");
        check_rate(filter.fp_rate(), want_rate, &what);
        assert_eq!(filter.capacity(), want_cap, "{what}: capacity");
        assert_eq!(filter.size(), want_size, "{what}: size");
    }
}
