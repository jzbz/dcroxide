// SPDX-License-Identifier: ISC
//! dcrd's decompression vectors, copied from
//! github.com/decred/dcrd/dcrec/secp256k1/v4 curve_test.go (`TestDecompressY`,
//! :1128-1228, vectors :1135-1171, at the parity pin 3360ae4d; ISC,
//! Copyright (c) 2015-2024 The Decred developers, 2013-2016 The btcsuite
//! developers).  Hex strings exactly as in dcrd; an empty y means dcrd
//! expects no point.

/// (name, x, valid, odd y, even y).
pub(crate) const DECOMPRESS_Y: [(&str, &str, bool, &str, &str); 6] = [
    ("x = 0 -- not a point on the curve", "0", false, "", ""),
    (
        "x = 1",
        "1",
        true,
        "bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441",
        "4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee",
    ),
    (
        "x = secp256k1 prime (aka 0) -- not a point on the curve",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        false,
        "",
        "",
    ),
    (
        "x = secp256k1 prime - 1 -- not a point on the curve",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        false,
        "",
        "",
    ),
    (
        "x = secp256k1 group order",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        true,
        "670999be34f51e8894b9c14211c28801d9a70fde24b71d3753854b35d07c9a11",
        "98f66641cb0ae1776b463ebdee3d77fe2658f021db48e2c8ac7ab4c92f83621e",
    ),
    (
        "x = secp256k1 group order - 1 -- not a point on the curve",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        false,
        "",
        "",
    ),
];
