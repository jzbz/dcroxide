// SPDX-License-Identifier: ISC
//! dcrd's fixed ECDSA vectors for signing, verification and compact
//! recovery, ported from dcrec/secp256k1/v4 `ecdsa/signature_test.go` at
//! the parity pin (v4.4.2-0.20261019113547-3360ae4dbef8, the version
//! `tools/oracle` pins).  They run without Go, and they pin what the
//! libsecp256k1-backed code returns today: every signature, verdict and
//! recovered key here is dcrd's.

// Test-harness arithmetic over 32-byte scalars and the one-byte compact
// signature header.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_dcrec::secp256k1::ecdsa::{
    COMPACT_SIG_COMP_PUB_KEY, COMPACT_SIG_MAGIC_OFFSET, Signature, recover_compact, sign,
};
use dcroxide_dcrec::secp256k1::nonce::nonce_rfc6979;
use dcroxide_dcrec::secp256k1::{GROUP_ORDER_BYTES, PrivateKey};
use dcroxide_testutil::{hex, unhex};

/// The public key recovery code bit for an odd R.y (dcrd
/// `pubKeyRecoveryCodeOddnessBit`).
const PUB_KEY_RECOVERY_CODE_ODDNESS_BIT: u8 = 1;

fn key(hex_key: &str) -> PrivateKey {
    let bytes: [u8; 32] = unhex(hex_key).try_into().expect("32 bytes");
    PrivateKey::from_bytes(&bytes).expect("valid key")
}

fn arr32(hex_bytes: &str) -> [u8; 32] {
    unhex(hex_bytes).try_into().expect("32 bytes")
}

/// A big-endian scalar below the group order, left-padded to 32 bytes as
/// dcrd's `mustModNScalar` reads a shorter value (one row's S has 31).
fn scalar(hex_scalar: &str) -> [u8; 32] {
    let bytes = unhex(hex_scalar);
    assert!(bytes.len() <= 32, "{hex_scalar}: longer than 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    assert!(
        out < GROUP_ORDER_BYTES,
        "{hex_scalar}: overflows a mod N scalar"
    );
    out
}

/// One row of dcrd's `signTest` table.
struct SignTest {
    name: &'static str,
    key: &'static str,
    /// The message `hash` is the BLAKE-256 of.
    msg: &'static str,
    hash: &'static str,
    nonce: &'static str,
    /// Whether `nonce` is the RFC6979 nonce, the one `sign` derives.
    rfc6979: bool,
    want_sig_r: &'static str,
    want_sig_s: &'static str,
    want_code: u8,
}

/// dcrd's `signTests` (ecdsa/signature_test.go), shared by its
/// TestSignAndVerify and TestSignAndRecoverCompact: private keys,
/// messages and nonces whose signatures were verified independently
/// with the Sage computer algebra system.
const SIGN_TESTS: &[SignTest] = &[
    SignTest {
        name: "key 0x1, blake256(0x01020304), rfc6979 nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        msg: "01020304",
        hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
        nonce: "4154324ecd4158938f1df8b5b659aeb639c7fbc36005934096e514af7d64bcc2",
        rfc6979: true,
        want_sig_r: "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
        want_sig_s: "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
        want_code: 0,
    },
    SignTest {
        name: "key 0x1, blake256(0x01020304), random nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        msg: "01020304",
        hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
        nonce: "a6df66500afeb7711d4c8e2220960855d940a5ed57260d2c98fbf6066cca283e",
        rfc6979: false,
        want_sig_r: "b073759a96a835b09b79e7b93c37fdbe48fb82b000c4a0e1404ba5d1fbc15d0a",
        want_sig_s: "7e34928a3e3832ec21e7711644d9388f7deb6340ead661d7056b0665974b87f3",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "key 0x2, blake256(0x01020304), rfc6979 nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000002",
        msg: "01020304",
        hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
        nonce: "55f96f24cf7531f527edfe3b9222eca12d575367c32a7f593a828dc3651acf49",
        rfc6979: true,
        want_sig_r: "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59",
        want_sig_s: "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "key 0x2, blake256(0x01020304), random nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000002",
        msg: "01020304",
        hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
        nonce: "679a6d36e7fe6c02d7668af86d78186e8f9ccc04371ac1c8c37939d1f5cae07a",
        rfc6979: false,
        want_sig_r: "4a090d82f48ca12d9e7aa24b5dcc187ee0db2920496f671d63e86036aaa7997e",
        want_sig_s: "261ffe8ba45007fc5fbbba6b4c6ed41beafb48b09fa8af1d6a3fbc6ccefbad",
        want_code: 0,
    },
    SignTest {
        name: "key 0x1, blake256(0x0102030405), rfc6979 nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        msg: "0102030405",
        hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
        nonce: "aa87a543c68f2568bb107c9946afa5233bf94fb6a7a063544505282621021629",
        rfc6979: true,
        want_sig_r: "dda8308cdbda2edf51ccf598b42b42b19597e102eb2ed4a04a16dd57084d3b40",
        want_sig_s: "0b6d67bab4929624e28f690407a15efc551354544fdc179970ff401eec2e5dc9",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "key 0x1, blake256(0x0102030405), random nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        msg: "0102030405",
        hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
        nonce: "65f880c892fdb6e7f74f76b18c7c942cfd037ef9cf97c39c36e08bbc36b41616",
        rfc6979: false,
        want_sig_r: "72e5666f4e9d1099447b825cf737ee32112f17a67e2ca7017ae098da31dfbb8b",
        want_sig_s: "1a7326da661a62f66358dcf53300afdc8e8407939dae1192b5b0899b0254311b",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "key 0x2, blake256(0x0102030405), rfc6979 nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000002",
        msg: "0102030405",
        hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
        nonce: "a13d652abd54b6e862548e5d12716df14dc192d93f3fa13536fdf4e56c54f233",
        rfc6979: true,
        want_sig_r: "122663fd29e41a132d3c8329cf05d61ebcca9351074cc277dcd868faba58d87d",
        want_sig_s: "353a44f2d949c04981e4e4d9c1f93a9e0644e63a5eaa188288c5ad68fd288d40",
        want_code: 0,
    },
    SignTest {
        name: "key 0x2, blake256(0x0102030405), random nonce",
        key: "0000000000000000000000000000000000000000000000000000000000000002",
        msg: "0102030405",
        hash: "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
        nonce: "026ece4cfb704733dd5eef7898e44c33bd5a0d749eb043f48705e40fa9e9afa0",
        rfc6979: false,
        want_sig_r: "3c4c5a2f217ea758113fd4e89eb756314dfad101a300f48e5bd764d3b6e0f8bf",
        want_sig_s: "6513e82442f133cb892514926ed9158328ead488ff1b027a31827603a65009df",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "random key 1, blake256(0x01), rfc6979 nonce",
        key: "a1becef2069444a9dc6331c3247e113c3ee142edda683db8643f9cb0af7cbe33",
        msg: "01",
        hash: "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d",
        nonce: "edb3a01063a0c6ccfc0d77295077cbd322cf364bfa64b7eeea3b20305135d444",
        rfc6979: true,
        want_sig_r: "ef392791d87afca8256c4c9c68d981248ee34a09069f50fa8dfc19ae34cd92ce",
        want_sig_s: "0a2b9cb69fd794f7f204c272293b8585a294916a21a11fd94ec04acae2dc6d21",
        want_code: 0,
    },
    SignTest {
        name: "random key 2, blake256(0x02), rfc6979 nonce",
        key: "59930b76d4b15767ec0e8c8e5812aa2e57db30c6af7963e2a6295ba02af5416b",
        msg: "02",
        hash: "49af37ab5270015fe25276ea5a3bb159d852943df23919522a202205fb7d175c",
        nonce: "af2a59085976494567ef0fc2ecede587b2d1d8e9898cc46e72d7f3e33156e057",
        rfc6979: true,
        want_sig_r: "886c9cccb356b3e1deafef2c276a4f8717ab73c1244c3f673cfbff5897de0e06",
        want_sig_s: "609394185495f978ae84b69be90c69947e5dd8dcb4726da604fcbd139d81fc55",
        want_code: 0,
    },
    SignTest {
        name: "random key 3, blake256(0x03), rfc6979 nonce",
        key: "c5b205c36bb7497d242e96ec19a2a4f086d8daa919135cf490d2b7c0230f0e91",
        msg: "03",
        hash: "b706d561742ad3671703c247eb927ee8a386369c79644131cdeb2c5c26bf6c5d",
        nonce: "82d82b696a386d6d7a111c4cb943bfd39de8e5f6195e7eed9d3edb40fe1419fa",
        rfc6979: true,
        want_sig_r: "6589d5950cec1fe2e7e20593b5ffa3556de20c176720a1796aa77a0cec1ec5a7",
        want_sig_s: "2a26deba3241de852e786f5b4e2b98d3efb958d91fe9773b331dbcca9e8be800",
        want_code: 0,
    },
    SignTest {
        name: "random key 4, blake256(0x04), rfc6979 nonce",
        key: "65b46d4eb001c649a86309286aaf94b18386effe62c2e1586d9b1898ccf0099b",
        msg: "04",
        hash: "4c6eb9e38415034f4c93d3304d10bef38bf0ad420eefd0f72f940f11c5857786",
        nonce: "7afd696a9e770961d2b2eaec77ab7c22c734886fa57bc4a50a9f1946168cd06f",
        rfc6979: true,
        want_sig_r: "81db1d6dca08819ad936d3284a359091e57c036648d477b96af9d8326965a7d1",
        want_sig_s: "1bdf719c4be69351ba7617a187ac246912101aea4b5a7d6dfc234478622b43c6",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "random key 5, blake256(0x05), rfc6979 nonce",
        key: "915cb9ba4675de06a182088b182abcf79fa8ac989328212c6b866fa3ec2338f9",
        msg: "05",
        hash: "bdd15db13448905791a70b68137445e607cca06cc71c7a58b9b2e84a06c54d08",
        nonce: "2a6ae70ea5cf1b932331901d640ece54551f5f33bf9484d5f95c676b5612b527",
        rfc6979: true,
        want_sig_r: "47fd51aecbc743477cb59aa29d18d11d75fb206ae1cdd044216e4f294e33d5b6",
        want_sig_s: "3d50edc03066584d50b8d19d681865a23960b37502ede5bf452bdca56744334a",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "random key 6, blake256(0x06), rfc6979 nonce",
        key: "93e9d81d818f08ba1f850c6dfb82256b035b42f7d43c1fe090804fb009aca441",
        msg: "06",
        hash: "19b7506ad9c189a9f8b063d2aee15953d335f5c88480f8515d7d848e7771c4ae",
        nonce: "0b847a0ae0cbe84dfca66621f04f04b0f2ec190dce10d43ba8c3915c0fcd90ed",
        rfc6979: true,
        want_sig_r: "c99800bc7ac7ea11afe5d7a264f4c26edd63ae9c7ecd6d0d19992980bcda1d34",
        want_sig_s: "2844d4c9020ddf9e96b86c1a04788e0f371bd562291fd17ee017db46259d04fb",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "random key 7, blake256(0x07), rfc6979 nonce",
        key: "c249bbd5f533672b7dcd514eb1256854783531c2b85fe60bf4ce6ea1f26afc2b",
        msg: "07",
        hash: "53d661e71e47a0a7e416591200175122d83f8af31be6a70af7417ad6f54d0038",
        nonce: "0f8e20694fe766d7b79e5ac141e3542f2f3c3d2cc6d0f60e0ec263a46dbe6d49",
        rfc6979: true,
        want_sig_r: "7a57a5222fb7d615eaa0041193f682262cebfa9b448f9c519d3644d0a3348521",
        want_sig_s: "574923b7b5aec66b62f1589002db29342c9f5ed56d5e80f5361c0307ff1561fa",
        want_code: 0,
    },
    SignTest {
        name: "random key 8, blake256(0x08), rfc6979 nonce",
        key: "ec0be92fcec66cf1f97b5c39f83dfd4ddcad0dad468d3685b5eec556c6290bcc",
        msg: "08",
        hash: "9bff7982eab6f7883322edf7bdc86a23c87ca1c07906fbb1584f57b197dc6253",
        nonce: "ab7df49257d18f5f1b730cc7448f46bd82eb43e6e220f521fa7d23802310e24d",
        rfc6979: true,
        want_sig_r: "64f90b09c8b1763a3eeefd156e5d312f80a98c24017811c0163b1c0b01323668",
        want_sig_s: "7d7bf4ff295ecfc9578eadc8378b0eea0c0362ad083b0fd1c9b3c06f4537f6ff",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
    SignTest {
        name: "random key 9, blake256(0x09), rfc6979 nonce",
        key: "6847b071a7cba6a85099b26a9c3e57a964e4990620e1e1c346fecc4472c4d834",
        msg: "09",
        hash: "4c2231813064f8500edae05b40195416bd543fd3e76c16d6efb10c816d92e8b6",
        nonce: "48ea6c907e1cda596048d812439ccf416eece9a7de400c8a0e40bd48eb7e613a",
        rfc6979: true,
        want_sig_r: "81fc600775d3cdcaa14f8629537299b8226a0c8bfce9320ce64a8d14e3f95bae",
        want_sig_s: "3607997d36b48bce957ae9b3d450e0969f6269554312a82bf9499efc8280ea6d",
        want_code: 0,
    },
    SignTest {
        name: "random key 10, blake256(0x0a), rfc6979 nonce",
        key: "b7548540f52fe20c161a0d623097f827608c56023f50442cc00cc50ad674f6b5",
        msg: "0a",
        hash: "e81db4f0d76e02805155441f50c861a8f86374f3ae34c7a3ff4111d3a634ecb1",
        nonce: "95c07e315cd5457e84270ca01019563c8eeaffb18ab4f23e88a44a0ff01c5f6f",
        rfc6979: true,
        want_sig_r: "0d4cbf2da84f7448b083fce9b9c4e1834b5e2e98defcec7ec87e87c739f5fe78",
        want_sig_s: "0997db60683e12b4494702347fc7ae7f599e5a95c629c146e0fc615a1a2acac5",
        want_code: PUB_KEY_RECOVERY_CODE_ODDNESS_BIT,
    },
];

/// The rows of [`SIGN_TESTS`], after the sanity checks dcrd's `signTests`
/// runs on them: each hash is the BLAKE-256 of its message, and each
/// RFC6979 nonce is the one `NonceRFC6979` derives with no extra data.
fn sign_tests() -> &'static [SignTest] {
    for test in SIGN_TESTS {
        assert_eq!(
            hex(&blake256::sum256(&unhex(test.msg))),
            test.hash,
            "{}: mismatched test hash",
            test.name
        );
        if test.rfc6979 {
            let nonce = nonce_rfc6979(&unhex(test.key), &unhex(test.hash), None, None, 0);
            assert_eq!(
                nonce,
                scalar(test.nonce),
                "{}: mismatched test nonce",
                test.name
            );
        }
    }
    SIGN_TESTS
}

/// The row's compact signature: the header byte (27 plus the recovery
/// code, plus 4 for a compressed key) and then R and S, as dcrd's
/// TestSignAndRecoverCompact builds `wantSig`.
fn compact_sig(test: &SignTest, compressed: bool) -> Vec<u8> {
    let mut recovery_code = COMPACT_SIG_MAGIC_OFFSET + test.want_code;
    if compressed {
        recovery_code += COMPACT_SIG_COMP_PUB_KEY;
    }
    let mut sig = vec![recovery_code];
    sig.extend_from_slice(&scalar(test.want_sig_r));
    sig.extend_from_slice(&scalar(test.want_sig_s));
    sig
}

/// Ported from dcrd's TestSignAndVerify (ecdsa/signature_test.go).  dcrd
/// signs every row with the row's own nonce through its unexported
/// `sign`, which has no public counterpart here, so every row's signature
/// must verify, and its recovery code, which dcrd compares with the one
/// `sign` returns, must recover the signing key.  `sign` mirrors dcrd's
/// exported `Sign`, which derives the RFC6979 nonce, so the RFC6979 rows
/// also check the signature it produces.
#[test]
fn sign_and_verify_vectors() {
    for test in sign_tests() {
        let priv_key = key(test.key);
        let pub_key = priv_key.public_key();
        let hash = arr32(test.hash);
        let want_sig = Signature::new(scalar(test.want_sig_r), scalar(test.want_sig_s))
            .expect("r and s below the group order");

        assert!(
            want_sig.verify(&hash, &pub_key),
            "{}: signature failed to verify",
            test.name
        );
        assert_eq!(
            recover_compact(&compact_sig(test, false), &hash),
            Ok((pub_key, false)),
            "{}: recovery code {} does not recover the key",
            test.name,
            test.want_code
        );

        if test.rfc6979 {
            let got = sign(&priv_key, &hash);
            assert_eq!(
                hex(&got.serialize()),
                hex(&want_sig.serialize()),
                "{}: unexpected signature",
                test.name
            );
            assert_eq!(
                *got.r_bytes(),
                scalar(test.want_sig_r),
                "{}: unexpected R component",
                test.name
            );
            assert_eq!(
                *got.s_bytes(),
                scalar(test.want_sig_s),
                "{}: unexpected S component",
                test.name
            );
            assert!(
                got.verify(&hash, &pub_key),
                "{}: signature failed to verify",
                test.name
            );
        }
    }
}

/// Ported from dcrd's TestVerifyFailures (ecdsa/signature_test.go):
/// verification edge conditions that must not verify.
#[test]
fn verify_failure_vectors() {
    struct Case {
        name: &'static str,
        key: &'static str,
        hash: &'static str,
        r: &'static str,
        s: &'static str,
    }
    let cases = [
        Case {
            name: "signature R is 0",
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            r: "0000000000000000000000000000000000000000000000000000000000000000",
            s: "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
        },
        Case {
            name: "signature S is 0",
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            r: "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
            s: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        Case {
            name: "u1G + u2Q is the point at infinity",
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            r: "3cfe45621a29fac355260a14b9adc0fe43ac2f13e918fc9ddfa117e964b61a8a",
            s: "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
        },
        Case {
            name: "signature R < P-N, but invalid",
            key: "0000000000000000000000000000000000000000000000000000000000000001",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            r: "000000000000000000000000000000014551231950b75fc4402da1722fc9baed",
            s: "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
        },
    ];

    for case in &cases {
        let pub_key = key(case.key).public_key();
        let sig =
            Signature::new(scalar(case.r), scalar(case.s)).expect("r and s below the group order");
        assert!(
            !sig.verify(&arr32(case.hash), &pub_key),
            "{}: unexpected success for invalid signature: {}",
            case.name,
            hex(&sig.serialize())
        );
    }
}

/// Ported from dcrd's TestSignAndRecoverCompact (ecdsa/signature_test.go),
/// over the RFC6979 rows of `signTests` and both key serializations.
/// dcrec has no `SignCompact` yet, so the compact signature is the one
/// the row describes: its R and S must be what `sign` produces (dcrd's
/// `SignCompact` and `Sign` both sign through `signRFC6979`), and
/// recovering it must return the signing key and the compressed flag.
#[test]
fn sign_and_recover_compact_vectors() {
    for test in sign_tests().iter().filter(|test| test.rfc6979) {
        let priv_key = key(test.key);
        let pub_key = priv_key.public_key();
        let hash = arr32(test.hash);

        let sig = sign(&priv_key, &hash);
        for compressed in [true, false] {
            let want_sig = compact_sig(test, compressed);
            assert_eq!(
                [*sig.r_bytes(), *sig.s_bytes()].concat(),
                want_sig[1..],
                "{}: unexpected signature",
                test.name
            );
            assert_eq!(
                recover_compact(&want_sig, &hash),
                Ok((pub_key, compressed)),
                "{}: compressed {compressed}",
                test.name
            );
        }
    }
}

/// Ported from dcrd's TestRecoverCompactErrors (ecdsa/signature_test.go):
/// the error paths of compact recovery, each signature otherwise valid
/// where that is possible.  `recover_compact` collapses dcrd's errors
/// into one, so only the verdict is asserted; `kind` keeps the dcrd
/// error kind of each row so that the kinds are asserted once
/// `recover_compact` reports them.
#[test]
fn recover_compact_error_vectors() {
    struct Case {
        name: &'static str,
        sig: &'static str,
        hash: &'static str,
        kind: &'static str,
    }
    let cases = [
        Case {
            name: "empty signature",
            sig: "",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigInvalidLen",
        },
        Case {
            // Signature created from private key 0x02, blake256(0x01020304).
            name: "no compact sig recovery code (otherwise valid sig)",
            sig: "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigInvalidLen",
        },
        Case {
            // Signature created from private key 0x02, blake256(0x01020304).
            name: "signature one byte too long (S padded with leading zero)",
            sig: "1f\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  0044b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigInvalidLen",
        },
        Case {
            // Signature created from private key 0x02, blake256(0x01020304).
            name: "compact sig recovery code too low (otherwise valid sig)",
            sig: "1a\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigInvalidRecoveryCode",
        },
        Case {
            // Signature created from private key 0x02, blake256(0x01020304).
            name: "compact sig recovery code too high (otherwise valid sig)",
            sig: "23\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigInvalidRecoveryCode",
        },
        Case {
            // Signature invented since finding a signature with an r value
            // that is exactly the group order prior to the modular
            // reduction is not calculable without breaking the underlying
            // crypto.
            name: "R == group order",
            sig: "1f\
                  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigRTooBig",
        },
        Case {
            // Signature invented since finding a signature with an r value
            // that would be valid modulo the group order and is still 32
            // bytes is not calculable without breaking the underlying
            // crypto.
            name: "R > group order and still 32 bytes (order + 1)",
            sig: "1f\
                  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigRTooBig",
        },
        Case {
            // Signature invented since the only way a signature could have
            // an r value of zero is if the nonce were zero which is invalid.
            name: "R == 0",
            sig: "1f\
                  0000000000000000000000000000000000000000000000000000000000000000\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigRIsZero",
        },
        Case {
            // Signature invented since finding a signature with an s value
            // that is exactly the group order prior to the modular
            // reduction is not calculable without breaking the underlying
            // crypto.
            name: "S == group order",
            sig: "1f\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigSTooBig",
        },
        Case {
            // Signature invented since finding a signature with an s value
            // that would be valid modulo the group order and is still 32
            // bytes is not calculable without breaking the underlying
            // crypto.
            name: "S > group order and still 32 bytes (order + 1)",
            sig: "1f\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigSTooBig",
        },
        Case {
            // Signature created by forcing the key/hash/nonce choices such
            // that s is zero and is therefore invalid.  The signing code
            // will not produce such a signature in practice.
            name: "S == 0",
            sig: "1f\
                  e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
                  0000000000000000000000000000000000000000000000000000000000000000",
            hash: "393bec84f1a04037751c0d6c2817f37953eaa204ac0898de7adb038c33a20438",
            kind: "ErrSigSIsZero",
        },
        Case {
            // Signature invented since finding a private key needed to
            // create a valid signature with an r value that is >= group
            // order prior to the modular reduction is not possible without
            // breaking the underlying crypto.
            name: "R >= field prime minus group order with overflow bit",
            sig: "21\
                  000000000000000000000000000000014551231950b75fc4402da1722fc9baee\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrSigOverflowsPrime",
        },
        Case {
            // Signature invented since finding a private key needed to
            // create a valid signature with an r value that is > group
            // order prior to the modular reduction is not possible without
            // breaking the underlying crypto.
            name: "R > group order with overflow bit",
            sig: "21\
                  000000000000000000000000000000014551231950b75fc4402da1722fc9baed\
                  44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrPointNotOnCurve",
        },
        Case {
            // Signature created from private key 0x01,
            // blake256(0x0102030407) over the secp256r1 curve (note the r1
            // instead of k1).
            name: "pubkey not on the curve, signature valid for secp256r1 instead",
            sig: "1f\
                  2a81d1b3facc22185267d3f8832c5104902591bc471253f1cfc5eb25f4f740f2\
                  72e65d019f9b09d769149e2be0b55de9b0224d34095bddc6a5dba90bfda33c45",
            hash: "9165e957708bc95cf62d020769c150b2d7b08e7ab7981860815b1eaabd41d695",
            kind: "ErrPointNotOnCurve",
        },
        Case {
            // Signature created from private key 0x01, blake256(0x01020304)
            // and manually setting s = -e*k^-1.
            name: "calculated pubkey point at infinity",
            sig: "1f\
                  c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09\
                  1281d8d90a5774045abd57b453c7eadbc830dbadec89ae8dd7639b9cc55641d0",
            hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
            kind: "ErrPointNotOnCurve",
        },
    ];

    for case in &cases {
        let got = recover_compact(&unhex(case.sig), &arr32(case.hash));
        assert!(
            got.is_err(),
            "{}: recovered {got:?} where dcrd fails with {}",
            case.name,
            case.kind
        );
    }
}
