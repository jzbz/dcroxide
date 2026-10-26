// SPDX-License-Identifier: ISC
//! This crate's verdicts against Go's, through the oracle (ADR-0015 T10):
//! what dcrd's `crypto/tls` would do with the same input.
//!
//! For key exchange, on all four groups: each takes and refuses the shares
//! Go's `crypto/ecdh` takes and refuses, the generated ones of
//! `kx_shares`, and agrees Go's secret over a fresh key share of its own.
//! P-521 is the group these tests matter most for, since ring has none to
//! hold it to; Wycheproof's vectors go through Go too, in the crate's
//! unit tests, where a vector's private key can be set.
//!
//! Without an oracle the tests skip, unless `DCROXIDE_REQUIRE_ORACLE` is
//! set, as in CI, where they also require the reference Go.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod kx_shares;

use std::collections::HashMap;

use curve25519_dalek::montgomery::MontgomeryPoint;
use dcroxide_testutil::{Oracle, hex, unhex};
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::crypto::SupportedKxGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};

/// A group as these tests put it beside Go's.
struct Paired {
    /// This crate's group.
    group: &'static dyn SupportedKxGroup,
    /// The curve's name in the oracle's `ecdh`.
    curve: &'static str,
    /// The fixed private key Go takes for it.
    private: Vec<u8>,
    /// That key's public key, as a key share carries it.
    public: Vec<u8>,
}

/// The four groups.  Go's fixed keys are `0x01` repeated at the field's
/// length, below each curve's order, and X25519's at 32 bytes.
fn groups() -> [Paired; 4] {
    use dcroxide_tlscrypto::kx_group;
    let p256 = p256::NonZeroScalar::from_repr(p256::FieldBytes::from([1; 32]))
        .into_option()
        .expect("below the order");
    let p384 = p384::NonZeroScalar::from_repr(p384::FieldBytes::from([1; 48]))
        .into_option()
        .expect("below the order");
    let p521 = p521::NonZeroScalar::from_repr(p521::FieldBytes::from([1; 66]))
        .into_option()
        .expect("below the order");
    [
        Paired {
            group: kx_group::X25519,
            curve: "X25519",
            private: vec![1; 32],
            public: MontgomeryPoint::mul_base_clamped([1; 32])
                .to_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP256R1,
            curve: "P-256",
            private: vec![1; 32],
            public: p256::PublicKey::from_secret_scalar(&p256)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP384R1,
            curve: "P-384",
            private: vec![1; 48],
            public: p384::PublicKey::from_secret_scalar(&p384)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP521R1,
            curve: "P-521",
            private: vec![1; 66],
            public: p521::PublicKey::from_secret_scalar(&p521)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
    ]
}

/// Go's answer to a key share: the secret `private` agrees with `public`
/// on `curve`, or `None` where Go refuses the share.
fn go_ecdh(oracle: &mut Oracle, curve: &str, private: &[u8], public: &[u8]) -> Option<Vec<u8>> {
    let request = serde_json::json!({
        "curve": curve,
        "private": hex(private),
        "public": hex(public),
    });
    let response = oracle.call("ecdh", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some(refused) if refused.starts_with("refused: ") => None,
        Some(secret) => Some(unhex(secret)),
        None => panic!("the oracle answered {response}"),
    }
}

/// Each group takes exactly the shares Go takes, and refuses the others
/// as an invalid key share.  A share's verdict depends on the share
/// alone, so this crate's fresh key and Go's fixed one judge the same
/// thing.  A few verdicts are also checked by name, so that a corpus gone
/// wrong, say with every share off the curve, cannot pass on agreement
/// alone.
#[test]
fn each_group_takes_the_shares_go_takes() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    for Paired {
        group,
        curve,
        private,
        ..
    } in groups()
    {
        let name = group.name();
        let mut verdicts = HashMap::new();
        for (label, share) in kx_shares::shares(name) {
            let go = go_ecdh(&mut oracle, curve, &private, &share).is_some();
            let ours = group.start().expect("started").complete(&share);
            if let Err(err) = &ours {
                assert_eq!(
                    *err,
                    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                    "{name:?}, {label}"
                );
            }
            assert_eq!(ours.is_ok(), go, "{name:?}, {label}");
            verdicts.insert(label, go);
        }
        let named: &[(&str, bool)] = if name == NamedGroup::X25519 {
            &[
                ("32 bytes under 0x04", true),
                ("9, the base point", true),
                ("p + 9, the base point, top bit set", true),
                ("2, on the twist", true),
                ("0, of order 2", false),
                ("of order 8, top bit set", false),
                ("p + 1, which is 1", false),
                ("31 bytes under 0x04", false),
            ]
        } else {
            &[
                ("the point at x = 0, x written as 0", true),
                ("the point at x = 0, x written as p", false),
                ("the point at x = 0, x written as p + 1", false),
                ("the generator with a bit of y flipped", false),
                ("the generator's x with y written as p", false),
                ("1 bytes under 0x00", false),
            ]
        };
        for (label, taken) in named {
            assert_eq!(verdicts.get(*label), Some(taken), "{name:?}, {label}");
        }
        let taken = verdicts.values().filter(|&&taken| taken).count();
        let refused = verdicts.len() - taken;
        assert!(
            taken >= 2 && refused > 900,
            "{name:?}: {taken} taken, {refused} refused"
        );
    }
}

/// Each group agrees Go's secret: this crate's exchange completed with
/// the public key of Go's fixed private key gives what Go agrees with the
/// exchange's own key share.
#[test]
fn each_group_agrees_gos_secret() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    for Paired {
        group,
        curve,
        private,
        public,
    } in groups()
    {
        for _ in 0..8 {
            let ours = group.start().expect("started");
            let go = go_ecdh(&mut oracle, curve, &private, ours.pub_key())
                .unwrap_or_else(|| panic!("{curve}: Go refused a fresh key share"));
            let agreed = ours.complete(&public).expect("Go's public key taken");
            assert_eq!(agreed.secret_bytes(), go, "{curve}");
        }
    }
}
