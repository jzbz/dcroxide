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
//!
//! The canaries that put a model in place of a verify parse the request
//! here first ([`ecdsa_verify_parts`], [`schnorr_verify_parts`],
//! [`ed25519_verify_parts`]): dcrec's rejections, kinds and texts stand,
//! and only the arithmetic after parsing is the model's.

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
        Cmd::EcdsaVerify | Cmd::EcdsaVerifyRaw => {
            OursAnswer::plain(match ecdsa_verify_inputs(cmd, data) {
                Ok((key, hash, sig)) => Answer::Verdict(sig.verify(hash, &key)),
                Err(reject) => reject,
            })
        }
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
        Cmd::Ed25519Verify => OursAnswer::plain(match ed25519_verify_inputs(data) {
            Ok(inputs) => Answer::Verdict(edwards::verify_raw(&inputs.key, inputs.msg, inputs.sig)),
            Err(reject) => reject,
        }),
        Cmd::EcdsaSignCompact => OursAnswer::plain(ecdsa_sign_compact(data)),
        Cmd::EcdsaRecoverCompact => {
            let (hash, sig) = split_at_checked(cmd, data, 32);
            OursAnswer::plain(
                match ecdsa::recover_compact(sig, hash.try_into().expect("32 bytes")) {
                    Ok((key, compressed)) => Answer::Value {
                        bytes: if compressed {
                            key.serialize_compressed().to_vec()
                        } else {
                            key.serialize_uncompressed().to_vec()
                        },
                        flag: Some(compressed),
                    },
                    // dcrec collapses recovery's errors, so no kind is
                    // compared until it reports dcrd's.
                    Err(()) => Answer::Reject {
                        kind: Kind::Unavailable,
                        text: None,
                    },
                },
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

/// `ecdsa_sign_compact`: compressed(1) ‖ key ‖ hash.  dcrec has no compact
/// signer yet, so the answer is built from what it has: `sign`'s (r, s)
/// under the one header 27 + c + 4·compressed, c in 0..=3, for which
/// `recover_compact` returns the signer's key and the flag.  When no
/// header does, dcroxide cannot make the signature, and the answer is a
/// rejection, which disagrees with dcrd's signature.  Once dcrec signs
/// compactly, this calls its signer instead.
fn ecdsa_sign_compact(data: &[u8]) -> Answer {
    let cmd = Cmd::EcdsaSignCompact;
    let (flag, rest) = split_at_checked(cmd, data, 1);
    let compressed = match flag[0] {
        0 => false,
        1 => true,
        other => panic!("{}: compressed flag {other}", cmd.name()),
    };
    let (key, hash) = key_and_hash(cmd, rest);
    let sig = ecdsa::sign(&key, &hash);
    let signer = key.public_key();
    let first = ecdsa::COMPACT_SIG_MAGIC_OFFSET.saturating_add(if compressed {
        ecdsa::COMPACT_SIG_COMP_PUB_KEY
    } else {
        0
    });
    let mut compact = Vec::with_capacity(ecdsa::COMPACT_SIG_SIZE);
    compact.push(first);
    compact.extend_from_slice(sig.r_bytes());
    compact.extend_from_slice(sig.s_bytes());
    for code in 0..=3u8 {
        compact[0] = first.saturating_add(code);
        if ecdsa::recover_compact(&compact, &hash) == Ok((signer, compressed)) {
            return value(compact);
        }
    }
    Answer::Reject {
        kind: Kind::Unavailable,
        text: Some("no recovery header recovers the signer's key".to_owned()),
    }
}

/// An ECDSA or Schnorr verify request's inputs as dcroxide parsed them,
/// for a canary that verifies with a model instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyParts {
    /// The parsed key, uncompressed: 04 ‖ x ‖ y.
    pub key: [u8; 65],
    /// The hash.
    pub hash: [u8; 32],
    /// r, big-endian.
    pub r: [u8; 32],
    /// s, big-endian.
    pub s: [u8; 32],
}

/// The parts of an `ecdsa_verify` or `ecdsa_verify_raw` request as
/// dcroxide parses them, or dcroxide's rejection of the key or the
/// signature.
pub fn ecdsa_verify_parts(cmd: Cmd, data: &[u8]) -> Result<VerifyParts, Answer> {
    let (key, hash, sig) = ecdsa_verify_inputs(cmd, data)?;
    Ok(VerifyParts {
        key: key.serialize_uncompressed(),
        hash: *hash,
        r: *sig.r_bytes(),
        s: *sig.s_bytes(),
    })
}

/// The parts of a `schnorr_verify` request as dcroxide parses them, or
/// dcroxide's rejection of the key or the signature.
pub fn schnorr_verify_parts(data: &[u8]) -> Result<VerifyParts, Answer> {
    let (key, hash, sig) = schnorr_verify_inputs(data)?;
    Ok(VerifyParts {
        key: key.serialize_uncompressed(),
        hash: *hash,
        r: *sig.r_bytes(),
        s: *sig.s_bytes(),
    })
}

/// An `ed25519_verify` request's inputs as dcroxide parsed them, for a
/// canary that verifies with a model instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Parts<'a> {
    /// The key's encoding as the request gives it.
    pub key: [u8; 32],
    /// The parsed key's encoding, which dcroxide serializes: canonical.
    pub canonical: [u8; 32],
    /// The raw signature R ‖ S, as given.
    pub sig: [u8; 64],
    /// The message.
    pub msg: &'a [u8],
}

/// The parts of an `ed25519_verify` request as dcroxide parses them, or
/// dcroxide's rejection of the key.
pub fn ed25519_verify_parts(data: &[u8]) -> Result<Ed25519Parts<'_>, Answer> {
    let inputs = ed25519_verify_inputs(data)?;
    Ok(Ed25519Parts {
        key: *inputs.encoded,
        canonical: inputs.key.serialize(),
        sig: *inputs.sig,
        msg: inputs.msg,
    })
}

/// An ECDSA verify request's key, hash and signature, parsed in the
/// oracle's order.  `ecdsa_verify`: 33-byte key ‖ hash ‖ DER, the key then
/// the DER parsed.  `ecdsa_verify_raw`: key_len ‖ key ‖ hash ‖ r ‖ s, the
/// key parsed, then r and s range-checked together (dcrec does not say
/// which is out of range).
fn ecdsa_verify_inputs(
    cmd: Cmd,
    data: &[u8],
) -> Result<(PublicKey, &[u8; 32], ecdsa::Signature), Answer> {
    let (key, rest) = match cmd {
        Cmd::EcdsaVerify => split_at_checked(cmd, data, 33),
        Cmd::EcdsaVerifyRaw => {
            let (len, rest) = split_at_checked(cmd, data, 1);
            let (key, rest) = split_at_checked(cmd, rest, usize::from(len[0]));
            assert_eq!(
                rest.len(),
                96,
                "{}: {} bytes after the key",
                cmd.name(),
                rest.len()
            );
            (key, rest)
        }
        _ => panic!("{}: not an ECDSA verify command", cmd.name()),
    };
    let (hash, sig) = split_at_checked(cmd, rest, 32);
    let hash: &[u8; 32] = hash.try_into().expect("32 bytes");
    let key = PublicKey::parse(key).map_err(|e| dcrd_reject(e.kind_name(), e.to_string()))?;
    let sig = if cmd == Cmd::EcdsaVerify {
        ecdsa::parse_der_signature(sig).map_err(|e| dcrd_reject(e.kind_name(), e.to_string()))?
    } else {
        let (r, s) = sig.split_at(32);
        ecdsa::Signature::new(
            r.try_into().expect("32 bytes"),
            s.try_into().expect("32 bytes"),
        )
        .ok_or(Answer::Reject {
            kind: Kind::ScalarRange,
            text: None,
        })?
    };
    Ok((key, hash, sig))
}

/// `schnorr_verify`'s key (parsed as `secp256k1.ParsePubKey` does, as the
/// oracle parses it), hash and signature.
fn schnorr_verify_inputs(
    data: &[u8],
) -> Result<(PublicKey, &[u8; 32], schnorr::Signature), Answer> {
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
    let key = PublicKey::parse(key).map_err(|e| dcrd_reject(e.kind_name(), e.to_string()))?;
    let sig =
        schnorr::parse_signature(sig).map_err(|e| dcrd_reject(e.kind_name(), e.to_string()))?;
    Ok((key, hash.try_into().expect("32 bytes"), sig))
}

/// `schnorr_verify`: `verify_detailed`, whose reason is the answer's
/// detail.
fn schnorr_verify(data: &[u8]) -> OursAnswer {
    match schnorr_verify_inputs(data) {
        Ok((key, hash, sig)) => {
            let reason = sig
                .verify_detailed(hash, &key)
                .map_err(schnorr::Error::kind_name);
            OursAnswer {
                answer: Answer::Verdict(reason.is_ok()),
                detail: Detail::Schnorr(reason),
            }
        }
        Err(reject) => OursAnswer::plain(reject),
    }
}

/// An `ed25519_verify` request parsed: 32-byte key ‖ raw 64-byte
/// signature ‖ message.
struct Ed25519Inputs<'a> {
    key: edwards::PublicKey,
    encoded: &'a [u8; 32],
    sig: &'a [u8; 64],
    msg: &'a [u8],
}

/// `ed25519_verify`'s key, parsed as dcrd parses it, signature and
/// message.
fn ed25519_verify_inputs(data: &[u8]) -> Result<Ed25519Inputs<'_>, Answer> {
    let cmd = Cmd::Ed25519Verify;
    let (encoded, rest) = split_at_checked(cmd, data, 32);
    let (sig, msg) = split_at_checked(cmd, rest, 64);
    let key = edwards::parse_pub_key(encoded).map_err(|e| plain_reject(e.to_string()))?;
    Ok(Ed25519Inputs {
        key,
        encoded: encoded.try_into().expect("32 bytes"),
        sig: sig.try_into().expect("64 bytes"),
        msg,
    })
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

    /// The compact signer is dcrd's: `TestSignAndRecoverCompact`'s row for
    /// key 2 and BLAKE-256(01020304), whose recovery code has the oddness
    /// bit, under both flags; recovering it returns the signer's key, and
    /// a header outside 27..=34 is rejected without a kind.
    #[test]
    fn compact_signatures_follow_dcrds_vectors() {
        let mut d = [0u8; 32];
        d[31] = 2;
        let hash = unhex("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let hash: [u8; 32] = hash.try_into().expect("32 bytes");
        let rs = unhex(
            "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59\
             44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
        );
        let signer = PrivateKey::from_bytes(&d).expect("two").public_key();
        for (compressed, header, key) in [
            (false, 28u8, signer.serialize_uncompressed().to_vec()),
            (true, 32u8, signer.serialize_compressed().to_vec()),
        ] {
            let req = cmd::ecdsa_sign_compact(compressed, &d, &hash);
            let want = [&[header][..], &rs].concat();
            assert_eq!(
                answer(req.cmd, &req.data).answer,
                Answer::Value {
                    bytes: want.clone(),
                    flag: None
                }
            );
            let req = cmd::ecdsa_recover_compact(&hash, &want);
            assert_eq!(
                answer(req.cmd, &req.data).answer,
                Answer::Value {
                    bytes: key,
                    flag: Some(compressed)
                }
            );
        }
        let req = cmd::ecdsa_recover_compact(&hash, &[&[0x1a][..], &rs].concat());
        assert_eq!(
            answer(req.cmd, &req.data).answer,
            Answer::Reject {
                kind: Kind::Unavailable,
                text: None
            }
        );
    }

    /// The parts the canaries take are what dcrec parsed, and a request
    /// dcrec rejects gives the answer dcroxide gives it.
    #[test]
    fn parts_are_what_dcrec_parsed() {
        let mut d = [0u8; 32];
        d[31] = 1;
        let g = PrivateKey::from_bytes(&d).expect("one").public_key();
        let hash = [7u8; 32];
        let (r, s) = ([0x11u8; 32], [0x22u8; 32]);
        let want = VerifyParts {
            key: g.serialize_uncompressed(),
            hash,
            r,
            s,
        };
        for req in [
            cmd::ecdsa_verify_raw(&g.serialize_compressed(), &hash, &r, &s),
            cmd::ecdsa_verify_raw(&g.serialize_uncompressed(), &hash, &r, &s),
            cmd::ecdsa_verify(&g.serialize_compressed(), &hash, &der(&r, &s)),
        ] {
            assert_eq!(ecdsa_verify_parts(req.cmd, &req.data), Ok(want));
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);
        let req = cmd::schnorr_verify(&g.serialize_compressed(), &hash, &sig);
        assert_eq!(schnorr_verify_parts(&req.data), Ok(want));

        for req in [
            cmd::ecdsa_verify_raw(&[5; 33], &hash, &r, &s),
            cmd::ecdsa_verify_raw(&g.serialize_compressed(), &hash, &[0xff; 32], &s),
            cmd::ecdsa_verify(&g.serialize_compressed(), &hash, &[0x30]),
        ] {
            assert_eq!(
                ecdsa_verify_parts(req.cmd, &req.data),
                Err(answer(req.cmd, &req.data).answer)
            );
        }
        let req = cmd::schnorr_verify(&[5; 33], &hash, &sig);
        assert_eq!(
            schnorr_verify_parts(&req.data),
            Err(answer(req.cmd, &req.data).answer)
        );

        // The identity encoded as y = p + 1 parses, and serializes as
        // y = 1.
        let mut p_plus_1 = [0xffu8; 32];
        p_plus_1[0] = 0xee;
        p_plus_1[31] = 0x7f;
        let mut one = [0u8; 32];
        one[0] = 1;
        let req = cmd::ed25519_verify(&p_plus_1, &[3; 64], b"m");
        let parts = ed25519_verify_parts(&req.data).expect("the key parses");
        assert_eq!(
            (parts.key, parts.canonical, parts.sig, parts.msg),
            (p_plus_1, one, [3; 64], &b"m"[..])
        );
        // y = 2 is off the curve.
        let mut two = [0u8; 32];
        two[0] = 2;
        let req = cmd::ed25519_verify(&two, &[3; 64], b"m");
        assert_eq!(
            ed25519_verify_parts(&req.data).map(|p| p.key),
            Err(answer(req.cmd, &req.data).answer)
        );
    }

    /// Minimal DER of two values below 2^255 whose top bytes are below
    /// 0x80.
    fn der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0x30, 68, 0x02, 32];
        out.extend_from_slice(r);
        out.extend_from_slice(&[0x02, 32]);
        out.extend_from_slice(s);
        out
    }

    /// A layout the adapter cannot decode is a generator bug, and panics.
    #[test]
    fn a_broken_layout_panics() {
        for (cmd, data) in [
            (Cmd::EcdsaVerifyRaw, vec![0xff]),
            (Cmd::EcdsaVerify, vec![2; 40]),
            (Cmd::EcdsaSign, vec![0; 64]),
            (Cmd::EcdsaSignCompact, [&[2u8][..], &[1; 64]].concat()),
            (Cmd::EcdsaSignCompact, vec![0; 64]),
            (Cmd::EcdsaRecoverCompact, vec![0; 31]),
            (Cmd::SchnorrVerify, vec![2; 128]),
            (Cmd::Ed25519Verify, vec![0; 95]),
            (Cmd::BuildInfo, vec![]),
        ] {
            let result = std::panic::catch_unwind(|| answer(cmd, &data));
            assert!(result.is_err(), "{cmd:?}");
        }
    }
}
