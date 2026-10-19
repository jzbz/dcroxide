// SPDX-License-Identifier: ISC
//! dcrd's serialization vectors for the gcs filters: the cases of
//! `TestFilter` in gcs/v4's `gcs_test.go` at the parity pin, each the
//! bytes and the hash of a version 1 or version 2 filter built from
//! fixed contents under the zero key.  Unlike the oracle differential
//! they need no Go toolchain.

use dcroxide_gcs::{FilterV1, FilterV2, KEY_SIZE};
use dcroxide_testutil::hex;

/// dcrd's `contents1`.
const CONTENTS1: [&[u8]; 17] = [
    b"Alex", b"Bob", b"Charlie", b"Dick", b"Ed", b"Frank", b"George", b"Harry", b"Ilya", b"John",
    b"Kevin", b"Larry", b"Michael", b"Nate", b"Owen", b"Paul", b"Quentin",
];

/// dcrd's `contents2`.
const CONTENTS2: [&[u8]; 17] = [
    b"Alice",
    b"Betty",
    b"Charmaine",
    b"Donna",
    b"Edith",
    b"Faina",
    b"Georgia",
    b"Hannah",
    b"Ilsbeth",
    b"Jennifer",
    b"Kayla",
    b"Lena",
    b"Michelle",
    b"Natalie",
    b"Ophelia",
    b"Peggy",
    b"Queenie",
];

struct Vector {
    name: &'static str,
    version: u16,
    b: u8,
    m: u64,
    contents: Vec<&'static [u8]>,
    want_bytes: &'static str,
    want_hash: &'static str,
}

fn vectors() -> Vec<Vector> {
    let with_nil = || {
        let mut c: Vec<&'static [u8]> = vec![b""];
        c.extend(CONTENTS1);
        c
    };
    vec![
        Vector {
            name: "empty filter",
            version: 1,
            b: 20,
            m: 1 << 20,
            contents: Vec::new(),
            want_bytes: "",
            want_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        Vector {
            name: "contents1 with B=20, M=1<<20",
            version: 1,
            b: 20,
            m: 1 << 20,
            contents: CONTENTS1.to_vec(),
            want_bytes: "00000011ce76b76760b54096a233d504ce55b80600fb072c74893cf306eb0c050f0b3c32e8c23436f8f5e67a986a46470790",
            want_hash: "a802fbe6f06991877cde8f3d770d8da8cf195816f04874cab045ffccaddd880d",
        },
        Vector {
            name: "contents1 with B=19, M=1<<19",
            version: 1,
            b: 19,
            m: 1 << 19,
            contents: CONTENTS1.to_vec(),
            want_bytes: "000000112375937586050f0e9e19689983a3ab9b6f8f0cbc2f204b5233d5099ca0c9fbe9ec6a1f60e76fba3ad6835a28",
            want_hash: "be9ba34f03ced957e6f5c4d583ddfd34c136b486fbec2a42b4c7588a2d7813c1",
        },
        Vector {
            name: "contents2 with B=19, M=1<<19",
            version: 1,
            b: 19,
            m: 1 << 19,
            contents: CONTENTS2.to_vec(),
            want_bytes: "000000114306259e36131a6c9bbd968a6c61dc110804d5ac91d20d6e9314a50332bffed877657c004e2366fcd34cda60",
            want_hash: "dcbaf452f6de4c82ea506fa551d75876c4979ef388f785509b130de62eeaec23",
        },
        Vector {
            name: "contents2 with B=10, M=1<<10",
            version: 1,
            b: 10,
            m: 1 << 10,
            contents: CONTENTS2.to_vec(),
            want_bytes: "000000111ca3aafb023074dc5bf2498df791b7d6e846e9f5016006d600",
            want_hash: "afa181cd5c4b08eb9c16d1c97c95df1ca7b82e5e444a396cec5e02f2804fbd1a",
        },
        Vector {
            name: "v2 empty filter",
            version: 2,
            b: 19,
            m: 784931,
            contents: Vec::new(),
            want_bytes: "",
            want_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        Vector {
            name: "v2 filter single nil item produces empty filter",
            version: 2,
            b: 19,
            m: 784931,
            contents: vec![b""],
            want_bytes: "",
            want_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        Vector {
            name: "v2 filter contents1 with nil item with B=19, M=784931",
            version: 2,
            b: 19,
            m: 784931,
            contents: with_nil(),
            want_bytes: "1189af70ad5baf9da83c64e99b18e96a06cd7295a58b324e81f09c85d093f1e33dcd6f40f18cfcbe2aeb771d8390",
            want_hash: "b616838c6090d3e732e775cc2f336ce0b836895f3e0f22d6c3ee4485a6ea5018",
        },
        Vector {
            name: "v2 filter contents1 with B=19, M=784931",
            version: 2,
            b: 19,
            m: 784931,
            contents: CONTENTS1.to_vec(),
            want_bytes: "1189af70ad5baf9da83c64e99b18e96a06cd7295a58b324e81f09c85d093f1e33dcd6f40f18cfcbe2aeb771d8390",
            want_hash: "b616838c6090d3e732e775cc2f336ce0b836895f3e0f22d6c3ee4485a6ea5018",
        },
        Vector {
            name: "v2 filter contents2 with B=19, M=784931",
            version: 2,
            b: 19,
            m: 784931,
            contents: CONTENTS2.to_vec(),
            want_bytes: "118d4be5372d2f4731c7e1681aefd23028be12306b4d90701a46b472ee80ad60f9fa86c4d6430cfb495ced604362",
            want_hash: "f3028f42909209120c8bf649fbbc5a70fb907d8997a02c2c1f2eef0e6402cb15",
        },
        Vector {
            name: "v2 filter contents1 with B=20, M=1569862",
            version: 2,
            b: 20,
            m: 1569862,
            contents: CONTENTS1.to_vec(),
            want_bytes: "1189af7056adebe769078c9e99b1774b509b35c52b4b0b324f40f83f2174227e3c33dcd67a078c33f2f855d6ef1d8390",
            want_hash: "10d6c29ba756301e42b97a103de601f604f1cd3150e44ac7cb8cdf63222d93d3",
        },
        Vector {
            name: "v2 filter contents2 with B=20, M=1569862",
            version: 2,
            b: 20,
            m: 1569862,
            contents: CONTENTS2.to_vec(),
            want_bytes: "118d4be69b968bd1cc38fc2d01aefc918142f847e0d69b9070192359fcbba015ac1f9fa86a26b1fc33ed32b9da604361",
            want_hash: "cb23a266bf136103cbfedb33041d4f4324106ed1539b9ec5d1cb4e71bc3cbdec",
        },
        Vector {
            name: "v2 filter contents2 with B=10, M=1534",
            version: 2,
            b: 10,
            m: 1534,
            contents: CONTENTS2.to_vec(),
            want_bytes: "118d5a6fbd3e3fc1aa472f983790848fcbcd6b9fb89cc34caf6048",
            want_hash: "d7c5f91d6490ec4d66e6db825ad1a628ec7367dc9a47c31bcde31eb5a6ba194b",
        },
    ]
}

/// Each of dcrd's vectors: the filter's bytes and hash, and a match
/// for every non-empty entry it was built from.
#[test]
fn dcrds_filter_vectors() {
    let key = [0u8; KEY_SIZE];
    for v in vectors() {
        let (bytes, hash, matches) = match v.version {
            1 => {
                assert_eq!(v.m, 1 << v.b, "{}: version 1 has M = 2^P", v.name);
                let f = FilterV1::new(v.b, key, &v.contents).expect(v.name);
                let matches: Vec<bool> = v.contents.iter().map(|c| f.matches(key, c)).collect();
                (f.bytes().to_vec(), f.hash(), matches)
            }
            _ => {
                let f = FilterV2::new(v.b, v.m, key, &v.contents).expect(v.name);
                let matches: Vec<bool> = v.contents.iter().map(|c| f.matches(key, c)).collect();
                (f.bytes().to_vec(), f.hash(), matches)
            }
        };
        assert_eq!(hex(&bytes), v.want_bytes, "{}: bytes", v.name);
        assert_eq!(hash.to_string(), v.want_hash, "{}: hash", v.name);
        for (c, matched) in v.contents.iter().zip(matches) {
            assert_eq!(matched, !c.is_empty(), "{}: match of {c:?}", v.name);
        }
    }
}
