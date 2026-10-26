// SPDX-License-Identifier: ISC
//! sigdiff's own secp256k1 constants against dcroxide-dcrec's, and every
//! secp256k1 number the design's appendix A states, re-derived from
//! `k256`.  This is an integration test so that no module under `src/`
//! other than the adapter names the code under test, not even under
//! `#[cfg(test)]`.

use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES};
use dcroxide_sigdiff::arith::{
    HALF_N, N, P, P_MINUS_N, TWO_256_MINUS_N, TWO_256_MINUS_P, add_be, be_from_u64, sub_be,
};
use dcroxide_sigdiff::r#gen::decompress;
use dcroxide_sigdiff::r#gen::kwrap_points::KWRAP_POINTS;
use dcroxide_testutil::unhex;

/// A hex number as a 32-byte big-endian value.
fn number(hex: &str) -> [u8; 32] {
    let digits = format!("{hex:0>64}");
    unhex(&digits).try_into().expect("at most 64 hex digits")
}

/// A big-endian value mod a small `m`.
fn small_rem(v: &[u8; 32], m: u64) -> u64 {
    v.iter().fold(0u64, |rem, &b| {
        rem.checked_mul(256)
            .and_then(|r| r.checked_add(u64::from(b)))
            .and_then(|r| r.checked_rem(m))
            .expect("a small modulus")
    })
}

#[test]
fn the_constants_are_dcrecs() {
    assert_eq!(P, FIELD_PRIME_BYTES);
    assert_eq!(N, GROUP_ORDER_BYTES);
    assert_eq!(
        sub_be(&FIELD_PRIME_BYTES, &GROUP_ORDER_BYTES),
        (P_MINUS_N, false)
    );
    let (twice, carry) = add_be(&HALF_N, &HALF_N);
    assert!(!carry);
    assert_eq!(add_be(&twice, &be_from_u64(1)), (GROUP_ORDER_BYTES, false));
    assert_eq!(
        add_be(&FIELD_PRIME_BYTES, &TWO_256_MINUS_P),
        ([0; 32], true)
    );
    assert_eq!(
        add_be(&GROUP_ORDER_BYTES, &TWO_256_MINUS_N),
        ([0; 32], true)
    );
}

/// Appendix A's secp256k1 numbers, each as the appendix writes it.  (Its
/// Ed25519 numbers belong to the Ed25519 classes and are checked with
/// them.)
#[test]
fn appendix_a_holds() {
    // The differences.
    assert_eq!(P_MINUS_N, number("14551231950b75fc4402da1722fc9baee"));
    assert_eq!(TWO_256_MINUS_P, number("1000003d1"));
    assert_eq!(TWO_256_MINUS_P, be_from_u64(4_294_968_273));
    assert_eq!(TWO_256_MINUS_N, number("14551231950b75fc4402da1732fc9bebf"));
    assert_eq!(
        N,
        number("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    );

    // P ≡ 1 (mod 3), so a third of the residues have cube roots, and
    // P ≡ 3 (mod 4), so decompression takes one exponentiation.
    assert_eq!(small_rem(&P, 3), 1);
    assert_eq!(small_rem(&P, 4), 3);

    // 7 and 6 are no squares mod P: x = 0 (x³ + 7 = 7) and x = P − 1
    // ((−1)³ + 7 = 6) do not decompress.  P − 1 is N + (P − N − 1), the x
    // of dcrd's r = P − N − 1 overflow row.
    let p_minus_1 = sub_be(&P, &be_from_u64(1)).0;
    assert_eq!(
        add_be(&N, &sub_be(&P_MINUS_N, &be_from_u64(1)).0).0,
        p_minus_1
    );
    for odd in [false, true] {
        assert_eq!(decompress(&[0; 32], odd), None);
        assert_eq!(decompress(&p_minus_1, odd), None);
    }

    // 488 of the x in 0..=1024 decompress, the first of them 1, 2 and 3.
    let small: Vec<u64> = (0..=1024u64)
        .filter(|&x| decompress(&be_from_u64(x), false).is_some())
        .collect();
    assert_eq!(small.len(), 488);
    assert_eq!(small[..3], [1, 2, 3]);

    // EV-rEdge: 1, 2, N − 3 and N − 2 are x coordinates, N − 1 is not, and
    // 2N − 1 is above P (above 2^256, even), so no point has x = N − 1 + N.
    let n_minus = |k: u64| sub_be(&N, &be_from_u64(k)).0;
    for x in [be_from_u64(1), be_from_u64(2), n_minus(3), n_minus(2)] {
        assert!(decompress(&x, false).is_some());
    }
    assert_eq!(decompress(&n_minus(1), false), None);
    assert!(add_be(&N, &n_minus(1)).1, "2N - 1 overflows 2^256 > P");
}

/// The first twelve K-wrap points as the appendix lists them.
#[test]
fn the_kwrap_table_starts_as_listed() {
    let listed = [
        (
            "146d3b65add9f54ccca28533c88e2cbc63f7443e1658783ab41f8ef97c2a10b5",
            1,
        ),
        (
            "1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507",
            1,
        ),
        (
            "cbb0deab125754f1fdb2038b0434ed9cb3fb53ab735391129994a535d925f673",
            1,
        ),
        (
            "911a99bd99d05b1707461fe091eb849299ef589b8056db3bab0a84328b24437e",
            6,
        ),
        (
            "a630d360efc9eb029a6fcdd90c336b2e4b24aa9c35cc4b74de6c9eda2ae4bfee",
            6,
        ),
        (
            "c8b492e17665b9e65e4a124661e1103f1aebfcc849dcd94f7688dcf149f6f4f2",
            6,
        ),
        (
            "a95c7e1d4c5db1863b7c6fb26ac231479ff552c18707b69a9ac6bf9c3676f31b",
            11,
        ),
        (
            "aa054108a816a0d84cc7cb39cce350a93d831203d67dd7ed2cbd403945db360b",
            11,
        ),
        (
            "ac9e40da0b8bada177bbc513c85a7e0f22879b3aa27a7178387c002883adcf38",
            11,
        ),
        (
            "9ced63fec8fa012a06e9f55ef3613729e40e04fda6054cc83342105b748e1134",
            13,
        ),
        (
            "a05a4e324093debc5efd9a3c66494f0b47d7c7bc9d041be7e91c9c8ffff01d1a",
            13,
        ),
        (
            "c2b84dcef67220199a187064a65579cad41a3345bcf6974fe3a153128b81ca10",
            13,
        ),
    ];
    for (point, (x, y)) in KWRAP_POINTS.iter().zip(listed) {
        assert_eq!(point.x_bytes(), number(x));
        assert_eq!(point.y, y);
    }
    assert_eq!(KWRAP_POINTS.len(), 192);
}
