// SPDX-License-Identifier: ISC
//! The adapter: dcroxide's answer to an oracle request, computed by decoding
//! the request's bytes with the oracle's own layout and calling
//! `dcroxide_dcrec` the way the oracle calls dcrd.
//!
//! This is the only module that names the code under test, and only the
//! run loop (and the canaries, which stand in for it) call into it
//! (`tests/independence.rs`).  It is outside the generator fingerprint:
//! dcrec's later API (a compact signer, typed recovery errors, an ECDSA
//! verify that reports its deciding step) is reached by changing this file
//! alone, which changes no input, no answer as compared and no digest.
//!
//! A request whose layout this cannot decode is a bug in a generator, so it
//! panics, and the run records the case as `ours-panicked`.

use dcroxide_dcrec::edwards;
use dcroxide_dcrec::secp256k1::{PrivateKey, PublicKey, ecdsa, schnorr};

use crate::answer::{Answer, Detail, Kind, OursAnswer};
use crate::cmd::Cmd;

/// dcroxide's answer to `cmd` with argument bytes `data`.
pub fn answer(cmd: Cmd, data: &[u8]) -> OursAnswer {
    match cmd {
        Cmd::EcdsaParseDer => OursAnswer::plain(match ecdsa::parse_der_signature(data) {
            Ok(sig) => value([sig.r_bytes().as_slice(), sig.s_bytes()].concat()),
            Err(e) => dcrd_reject(e.kind_name(), e.to_string()),
        }),
        Cmd::EcdsaVerify => OursAnswer::plain(ecdsa_verify(data)),
        Cmd::EcdsaVerifyRaw => OursAnswer::plain(ecdsa_verify_raw(data)),
        Cmd::EcdsaSign => {
            let (key, hash) = key_and_hash(cmd, data);
            OursAnswer::plain(value(ecdsa::sign(&key, &hash).serialize()))
        }
        Cmd::PubkeyParse => OursAnswer::plain(match PublicKey::parse(data) {
            Ok(key) => value(
                [
                    key.serialize_uncompressed().as_slice(),
                    &key.serialize_compressed(),
                ]
                .concat(),
            ),
            Err(e) => dcrd_reject(e.kind_name(), e.to_string()),
        }),
        Cmd::SchnorrPubkeyParse => OursAnswer::plain(match schnorr::parse_pub_key(data) {
            Ok(key) => value(key.serialize_compressed().to_vec()),
            Err(
                e @ (schnorr::PubKeyError::InvalidLen(_) | schnorr::PubKeyError::NotCompressed(_)),
            ) => Answer::Reject {
                kind: Kind::Plain,
                text: Some(e.to_string()),
            },
            Err(e @ schnorr::PubKeyError::Invalid(inner)) => {
                dcrd_reject(inner.kind_name(), e.to_string())
            }
        }),
        Cmd::SchnorrParse => OursAnswer::plain(match schnorr::parse_signature(data) {
            Ok(sig) => value(sig.serialize().to_vec()),
            Err(e) => dcrd_reject(e.kind_name(), e.to_string()),
        }),
        Cmd::SchnorrSign => {
            let (key, hash) = key_and_hash(cmd, data);
            OursAnswer::plain(match schnorr::sign(&key, &hash) {
                Ok(sig) => value(sig.serialize().to_vec()),
                Err(e) => dcrd_reject(e.kind_name(), e.to_string()),
            })
        }
        Cmd::SchnorrVerify => schnorr_verify(data),
        Cmd::Ed25519PubkeyParse => OursAnswer::plain(match edwards::parse_pub_key(data) {
            Ok(key) => value(key.serialize().to_vec()),
            Err(e) => plain_reject(e.to_string()),
        }),
        Cmd::Ed25519Parse => OursAnswer::plain(match edwards::parse_signature(data) {
            Ok(sig) => value(sig.serialize().to_vec()),
            Err(e) => plain_reject(e.to_string()),
        }),
        Cmd::Ed25519Sign => {
            let (seed, msg) = split_at_checked(cmd, data, 32);
            let secret = edwards::SecretKey::from_seed(seed.try_into().expect("32 bytes"));
            let sig = edwards::sign(&secret, msg);
            OursAnswer::plain(value(
                [sig.serialize().as_slice(), &secret.public_key().serialize()].concat(),
            ))
        }
        Cmd::Ed25519Verify => {
            let (key, rest) = split_at_checked(cmd, data, 32);
            let (sig, msg) = split_at_checked(cmd, rest, 64);
            OursAnswer::plain(match edwards::parse_pub_key(key) {
                Ok(key) => Answer::Verdict(edwards::verify_raw(
                    &key,
                    msg,
                    sig.try_into().expect("64 bytes"),
                )),
                Err(e) => plain_reject(e.to_string()),
            })
        }
        Cmd::EcdsaSignCompact | Cmd::EcdsaRecoverCompact => {
            panic!(
                "{}: no adapter until the compact signature classes",
                cmd.name()
            )
        }
        Cmd::Blake256 | Cmd::HashString | Cmd::BuildInfo => {
            panic!("{}: not a command dcroxide answers", cmd.name())
        }
    }
}

fn value(bytes: Vec<u8>) -> Answer {
    Answer::Value { bytes, flag: None }
}

fn dcrd_reject(kind: &str, text: String) -> Answer {
    Answer::Reject {
        kind: Kind::Dcrd(kind.to_owned()),
        text: Some(text),
    }
}

fn plain_reject(text: String) -> Answer {
    Answer::Reject {
        kind: Kind::Plain,
        text: Some(text),
    }
}

/// `data` split at `at`, or a panic naming the command whose layout it
/// breaks.
fn split_at_checked(cmd: Cmd, data: &[u8], at: usize) -> (&[u8], &[u8]) {
    data.split_at_checked(at)
        .unwrap_or_else(|| panic!("{}: {} bytes do not fit its layout", cmd.name(), data.len()))
}

/// A signing request's 32-byte key, in `[1, N-1]` as every signing class
/// keeps it, and 32-byte hash.
fn key_and_hash(cmd: Cmd, data: &[u8]) -> (PrivateKey, [u8; 32]) {
    let (key, hash) = split_at_checked(cmd, data, 32);
    let key: &[u8; 32] = key.try_into().expect("32 bytes");
    let hash: [u8; 32] = hash
        .try_into()
        .unwrap_or_else(|_| panic!("{}: a hash of {} bytes", cmd.name(), hash.len()));
    let key = PrivateKey::from_bytes(key)
        .unwrap_or_else(|| panic!("{}: a private key outside [1, N-1]", cmd.name()));
    (key, hash)
}

/// `ecdsa_verify`: the key, then the DER signature, parsed in the oracle's
/// order, then verified.
fn ecdsa_verify(data: &[u8]) -> Answer {
    let (key, rest) = split_at_checked(Cmd::EcdsaVerify, data, 33);
    let (hash, der) = split_at_checked(Cmd::EcdsaVerify, rest, 32);
    let key = match PublicKey::parse(key) {
        Ok(key) => key,
        Err(e) => return dcrd_reject(e.kind_name(), e.to_string()),
    };
    let sig = match ecdsa::parse_der_signature(der) {
        Ok(sig) => sig,
        Err(e) => return dcrd_reject(e.kind_name(), e.to_string()),
    };
    Answer::Verdict(sig.verify(hash.try_into().expect("32 bytes"), &key))
}

/// `ecdsa_verify_raw`: key_len ‖ key ‖ hash ‖ r ‖ s.  The key is parsed
/// first, then r and s range-checked together (dcrec does not say which is
/// out of range), then the signature verified.
fn ecdsa_verify_raw(data: &[u8]) -> Answer {
    let cmd = Cmd::EcdsaVerifyRaw;
    let (len, rest) = split_at_checked(cmd, data, 1);
    let (key, rest) = split_at_checked(cmd, rest, usize::from(len[0]));
    assert_eq!(
        rest.len(),
        96,
        "{}: {} bytes after the key",
        cmd.name(),
        rest.len()
    );
    let key = match PublicKey::parse(key) {
        Ok(key) => key,
        Err(e) => return dcrd_reject(e.kind_name(), e.to_string()),
    };
    let (hash, rs) = rest.split_at(32);
    let (r, s) = rs.split_at(32);
    match ecdsa::Signature::new(
        r.try_into().expect("32 bytes"),
        s.try_into().expect("32 bytes"),
    ) {
        Some(sig) => Answer::Verdict(sig.verify(hash.try_into().expect("32 bytes"), &key)),
        None => Answer::Reject {
            kind: Kind::ScalarRange,
            text: None,
        },
    }
}

/// `schnorr_verify`: the key (parsed as `secp256k1.ParsePubKey` does, as
/// the oracle parses it), the signature, then `verify_detailed`, whose
/// reason is the answer's detail.
fn schnorr_verify(data: &[u8]) -> OursAnswer {
    let cmd = Cmd::SchnorrVerify;
    assert_eq!(
        data.len(),
        33 + 32 + 64,
        "{}: {} bytes",
        cmd.name(),
        data.len()
    );
    let (key, rest) = data.split_at(33);
    let (hash, sig) = rest.split_at(32);
    let key = match PublicKey::parse(key) {
        Ok(key) => key,
        Err(e) => return OursAnswer::plain(dcrd_reject(e.kind_name(), e.to_string())),
    };
    let sig = match schnorr::parse_signature(sig) {
        Ok(sig) => sig,
        Err(e) => return OursAnswer::plain(dcrd_reject(e.kind_name(), e.to_string())),
    };
    let reason = sig
        .verify_detailed(hash, &key)
        .map_err(schnorr::Error::kind_name);
    OursAnswer {
        answer: Answer::Verdict(reason.is_ok()),
        detail: Detail::Schnorr(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd;
    use dcroxide_testutil::unhex;

    /// A sample of answers whose dcrd counterparts are fixed: dcrd's own
    /// public key test vectors and parse failures.
    #[test]
    fn answers_follow_the_layouts() {
        let key = unhex(
            "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
        );
        let got = answer(Cmd::PubkeyParse, &key);
        let Answer::Value { bytes, flag: None } = got.answer else {
            panic!("{got:?}");
        };
        assert_eq!(bytes[..65], key[..]);
        assert_eq!(bytes[65], 0x03, "odd y compresses to 03");
        assert_eq!(bytes[66..], key[1..33]);

        assert_eq!(
            answer(Cmd::PubkeyParse, &[5]).answer,
            Answer::Reject {
                kind: Kind::Dcrd("ErrPubKeyInvalidLen".into()),
                text: Some("malformed public key: invalid length: 1".into())
            }
        );
        assert_eq!(
            answer(Cmd::SchnorrPubkeyParse, &key).answer,
            Answer::Reject {
                kind: Kind::Plain,
                text: Some("bad pubkey byte string size (want 33, have 65)".into())
            }
        );
        assert_eq!(
            answer(Cmd::EcdsaParseDer, &[0x30]).answer.label(),
            "reject:ErrSigTooShort"
        );
        let hash = [7u8; 32];
        let raw = cmd::ecdsa_verify_raw(&key, &hash, &[0xff; 32], &[1; 32]);
        assert_eq!(
            answer(raw.cmd, &raw.data).answer,
            Answer::Reject {
                kind: Kind::ScalarRange,
                text: None
            }
        );
        let raw = cmd::ecdsa_verify_raw(&key, &hash, &[1; 32], &[1; 32]);
        assert_eq!(answer(raw.cmd, &raw.data).answer, Answer::Verdict(false));

        // A signature dcrec makes verifies through both layouts.
        let mut d = [0u8; 32];
        d[31] = 1;
        let signed = answer(Cmd::EcdsaSign, &[d, hash].concat());
        let Answer::Value { bytes: der, .. } = signed.answer else {
            panic!("{signed:?}");
        };
        let g = PrivateKey::from_bytes(&d).expect("one").public_key();
        let req = cmd::ecdsa_verify(&g.serialize_compressed(), &hash, &der);
        assert_eq!(answer(req.cmd, &req.data).answer, Answer::Verdict(true));

        let req = cmd::schnorr_sign(&d, &hash);
        let Answer::Value { bytes: sig, .. } = answer(req.cmd, &req.data).answer else {
            panic!("schnorr_sign");
        };
        let req = cmd::schnorr_verify(
            &g.serialize_compressed(),
            &hash,
            &sig.try_into().expect("64 bytes"),
        );
        assert_eq!(
            answer(req.cmd, &req.data),
            OursAnswer {
                answer: Answer::Verdict(true),
                detail: Detail::Schnorr(Ok(()))
            }
        );

        let req = cmd::ed25519_sign(&[9; 32], b"message");
        let Answer::Value { bytes, .. } = answer(req.cmd, &req.data).answer else {
            panic!("ed25519_sign");
        };
        let req = cmd::ed25519_verify(
            &bytes[64..].try_into().expect("32"),
            &bytes[..64].try_into().expect("64"),
            b"message",
        );
        assert_eq!(answer(req.cmd, &req.data).answer, Answer::Verdict(true));
    }

    /// A layout the adapter cannot decode is a generator bug, and panics.
    #[test]
    fn a_broken_layout_panics() {
        for (cmd, data) in [
            (Cmd::EcdsaVerifyRaw, vec![0xff]),
            (Cmd::EcdsaVerify, vec![2; 40]),
            (Cmd::EcdsaSign, vec![0; 64]),
            (Cmd::SchnorrVerify, vec![2; 128]),
            (Cmd::Ed25519Verify, vec![0; 95]),
            (Cmd::BuildInfo, vec![]),
        ] {
            let result = std::panic::catch_unwind(|| answer(cmd, &data));
            assert!(result.is_err(), "{cmd:?}");
        }
    }
}
