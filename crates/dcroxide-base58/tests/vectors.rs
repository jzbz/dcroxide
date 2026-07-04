// SPDX-License-Identifier: ISC
//! decred/base58 test vectors ported from `base58_test.go` and
//! `base58check_test.go` at v1.0.6.

use dcroxide_base58::{CheckError, check_decode, check_encode, decode, encode};
use dcroxide_testutil::unhex;

#[test]
fn base58_coding() {
    let string_cases: &[(&[u8], &str)] = &[
        (b"", ""),
        (b" ", "Z"),
        (b"-", "n"),
        (b"0", "q"),
        (b"1", "r"),
        (b"-1", "4SU"),
        (b"11", "4k8"),
        (b"abc", "ZiCa"),
        (b"1234598760", "3mJr7AoUXx2Wqd"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
        ),
        (
            b"00000000000000000000000000000000000000000000000000000000000000",
            "3sN2THZeE9Eh9eYrwkvZqNstbHGvrxSAM7gXUXvyFQP8XvQLUqNCS27icwUeDT7ckHm4FUHM2mTVh1vbLmk7y",
        ),
    ];
    for (decoded, encoded) in string_cases {
        assert_eq!(encode(decoded), *encoded, "encode {decoded:?}");
        assert_eq!(decode(encoded), *decoded, "decode {encoded}");
    }

    // The 200-zero-characters vector.
    let two_hundred = vec![b'0'; 200];
    let want = concat!(
        "KdhzWGVLoe2Z7u7v8kU6dSjNhdK8HNqQbVswpifqRXqmC5a6eFUoTLjhu41kZtTc",
        "6Am7Dzp8FcpoMubGyeiAinFQzGavztm4nnAm65i72UDh3FsTLbkoJf5oVNvx",
        "VALvaqWzugRNxNEs75g75wyubjXGhFxk4etvhvfdxu7JiwhXk1cWwnLUPjMY",
        "DGMFi2BEd8qMkB2wE8ACUHwdk3hHYuwaYKbEpFzjVQZwsRQo8JoFYozwdrFB",
        "Ys1F5NW6AtTVKMefQ6MGpGCxcjsWw",
    );
    assert_eq!(encode(&two_hundred), want);
    assert_eq!(decode(want), two_hundred);

    let hex_cases: &[(&str, &str)] = &[
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("0000000002060730", "111141111"),
        ("00", "1"),
        ("0000", "11"),
        ("000000", "111"),
        ("00000000", "1111"),
        ("0000000000", "11111"),
        ("00000000000000000000", "1111111111"),
        ("0000000000000000000000", "11111111111"),
        ("000000000000000000000000", "111111111111"),
        ("00000000000000000000000000", "1111111111111"),
        ("0000000000000000000000000000", "11111111111111"),
    ];
    for (decoded_hex, encoded) in hex_cases {
        let decoded = unhex(decoded_hex);
        assert_eq!(encode(&decoded), *encoded, "encode {decoded_hex}");
        assert_eq!(decode(encoded), decoded, "decode {encoded}");
    }

    // The long mixed vector.
    let decoded = unhex(concat!(
        "426018fe18ee72f798faacf8ed1efcd786577ad07f33124120fc9",
        "537ba97fbe5c5dbd46b66ebd88d11b650b06662914b12aa80ca90110d9b5",
        "7337c45ee224cf6ba1d9a3aaf92a232dfebc251c78753fe9f9215bfe7c43",
        "744"
    ));
    let want = concat!(
        "XyJrepxxsECdexAWReSjewTiyL6Ekj5W22bSqxjZfCUsns6QpSHD8bKw33z1YrDZ",
        "yD3S1H4iQawvXMTfxfjm8SdyCo8W989jvzEj4qUdZwzjgkMaz7Jx2fCw",
    );
    assert_eq!(encode(&decoded), want);
    assert_eq!(decode(want), decoded);
}

/// Invalid encodings decode to an empty vector, not an error (the Go
/// behavior).
#[test]
fn base58_decode_invalid() {
    for invalid in [
        "0",
        "O",
        "I",
        "l",
        "3mJr0",
        "O3yxU",
        "3sNI",
        "4kl8",
        "0OIl",
        "!@#$%^&*()-_=+~`",
    ] {
        assert!(decode(invalid).is_empty(), "decode {invalid:?}");
    }
}

#[test]
fn base58check() {
    // Round trip across versions and payloads.
    let cases: &[(&[u8], [u8; 2])] = &[
        (b"", [0x00, 0x00]),
        (b" ", [0x07, 0x3f]),
        (b"-", [0x13, 0x86]),
        (b"test payload", [0x22, 0xde]),
        (&[0u8; 20], [0x07, 0x3f]),
    ];
    for (payload, version) in cases {
        let encoded = check_encode(payload, *version);
        let (got_payload, got_version) = check_decode(&encoded).expect("round trip");
        assert_eq!(got_payload, *payload);
        assert_eq!(got_version, *version);
    }

    // Too short: fewer than the 6 bytes needed for version + checksum.
    assert_eq!(check_decode(""), Err(CheckError::InvalidFormat));
    assert_eq!(check_decode("3MNQE1X"), Err(CheckError::InvalidFormat));

    // Corrupted checksum: flip the last character of a valid encoding to a
    // different valid base58 character.
    let encoded = check_encode(b"test payload", [0x07, 0x3f]);
    let mut corrupted = encoded.into_bytes();
    let last = corrupted.last_mut().expect("nonempty");
    *last = if *last == b'2' { b'3' } else { b'2' };
    let corrupted = String::from_utf8(corrupted).expect("ascii");
    assert_eq!(check_decode(&corrupted), Err(CheckError::Checksum));
}
