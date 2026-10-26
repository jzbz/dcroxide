// SPDX-License-Identifier: ISC
//! The oracle commands the soak sends, and the request encoders: each lays
//! its arguments out exactly as `tools/oracle` reads them (the protocol
//! table in its `main.go` header and the handler of each command).

use core::fmt::Write as _;

use dcroxide_testutil::push_hex;

/// An oracle command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cmd {
    /// `ecdsa_parse_der`: DER → R‖S or a dcrd `ErrSig*` kind.
    EcdsaParseDer,
    /// `ecdsa_verify`: 33-byte key ‖ hash ‖ DER → verdict, or a key or DER kind.
    EcdsaVerify,
    /// `ecdsa_verify_raw`: key_len ‖ key ‖ hash ‖ r ‖ s → verdict, or a key
    /// kind, `ErrSigRTooBig` or `ErrSigSTooBig`.
    EcdsaVerifyRaw,
    /// `ecdsa_sign`: key ‖ hash → DER.
    EcdsaSign,
    /// `ecdsa_sign_compact`: compressed flag ‖ key ‖ hash → 65 bytes.
    EcdsaSignCompact,
    /// `ecdsa_recover_compact`: hash ‖ signature → key and flag, or a kind.
    EcdsaRecoverCompact,
    /// `pubkey_parse`: key → uncompressed and compressed, or a kind and text.
    PubkeyParse,
    /// `schnorr_pubkey_parse`: key → compressed, or an error.
    SchnorrPubkeyParse,
    /// `schnorr_parse`: signature → r‖s, or a kind.
    SchnorrParse,
    /// `schnorr_sign`: key ‖ hash → 64 bytes.
    SchnorrSign,
    /// `schnorr_verify`: 33-byte key ‖ hash ‖ 64-byte signature → verdict.
    SchnorrVerify,
    /// `ed25519_pubkey_parse`: key → canonical 32 bytes, or an error.
    Ed25519PubkeyParse,
    /// `ed25519_parse`: signature → R‖S, or an error.
    Ed25519Parse,
    /// `ed25519_sign`: seed ‖ message → signature and public key.
    Ed25519Sign,
    /// `ed25519_verify`: 32-byte key ‖ raw 64-byte signature ‖ message →
    /// verdict, or a key error.
    Ed25519Verify,
    /// `blake256`: data → digest.  Not a signature command: the pipe's own
    /// tests use it, and no class sends it.
    Blake256,
    /// `hash_string`: 32 hash bytes → display string.  Like
    /// [`Cmd::Blake256`], for the pipe's tests only.
    HashString,
    /// `build_info`: the oracle's Go version and signature module versions.
    BuildInfo,
}

impl Cmd {
    /// Every command, in declaration order.
    pub const ALL: [Cmd; 18] = [
        Cmd::EcdsaParseDer,
        Cmd::EcdsaVerify,
        Cmd::EcdsaVerifyRaw,
        Cmd::EcdsaSign,
        Cmd::EcdsaSignCompact,
        Cmd::EcdsaRecoverCompact,
        Cmd::PubkeyParse,
        Cmd::SchnorrPubkeyParse,
        Cmd::SchnorrParse,
        Cmd::SchnorrSign,
        Cmd::SchnorrVerify,
        Cmd::Ed25519PubkeyParse,
        Cmd::Ed25519Parse,
        Cmd::Ed25519Sign,
        Cmd::Ed25519Verify,
        Cmd::Blake256,
        Cmd::HashString,
        Cmd::BuildInfo,
    ];

    /// The oracle's command string.
    pub fn name(self) -> &'static str {
        match self {
            Cmd::EcdsaParseDer => "ecdsa_parse_der",
            Cmd::EcdsaVerify => "ecdsa_verify",
            Cmd::EcdsaVerifyRaw => "ecdsa_verify_raw",
            Cmd::EcdsaSign => "ecdsa_sign",
            Cmd::EcdsaSignCompact => "ecdsa_sign_compact",
            Cmd::EcdsaRecoverCompact => "ecdsa_recover_compact",
            Cmd::PubkeyParse => "pubkey_parse",
            Cmd::SchnorrPubkeyParse => "schnorr_pubkey_parse",
            Cmd::SchnorrParse => "schnorr_parse",
            Cmd::SchnorrSign => "schnorr_sign",
            Cmd::SchnorrVerify => "schnorr_verify",
            Cmd::Ed25519PubkeyParse => "ed25519_pubkey_parse",
            Cmd::Ed25519Parse => "ed25519_parse",
            Cmd::Ed25519Sign => "ed25519_sign",
            Cmd::Ed25519Verify => "ed25519_verify",
            Cmd::Blake256 => "blake256",
            Cmd::HashString => "hash_string",
            Cmd::BuildInfo => "build_info",
        }
    }

    /// Whether the command's success is a verdict (`"true"`/`"false"`)
    /// rather than a value.
    pub fn is_verify(self) -> bool {
        matches!(
            self,
            Cmd::EcdsaVerify | Cmd::EcdsaVerifyRaw | Cmd::SchnorrVerify | Cmd::Ed25519Verify
        )
    }
}

/// One oracle request: a command and the exact bytes the oracle receives
/// as its `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The command.
    pub cmd: Cmd,
    /// The argument bytes, laid out as the command's handler reads them.
    pub data: Vec<u8>,
}

impl Request {
    /// Appends the request's line, newline included, to `line`:
    /// `{"id":<id>,"cmd":"<name>","data":"<hex>"}`.  Command names need no
    /// escaping.
    pub fn push_line(&self, id: u64, line: &mut String) {
        // Formatting into a String cannot fail.
        let _ = write!(line, "{{\"id\":{id},\"cmd\":\"");
        line.push_str(self.cmd.name());
        line.push_str("\",\"data\":\"");
        push_hex(line, &self.data);
        line.push_str("\"}\n");
    }
}

/// The `build_info` request line: no id and no data.  It is the first line
/// every pipe sends.
pub const BUILD_INFO_LINE: &str = "{\"cmd\":\"build_info\"}\n";

/// `ecdsa_parse_der`: the DER bytes as they are.
pub fn ecdsa_parse_der(der: &[u8]) -> Request {
    Request {
        cmd: Cmd::EcdsaParseDer,
        data: der.to_vec(),
    }
}

/// `ecdsa_verify`: 33-byte key ‖ 32-byte hash ‖ DER.
pub fn ecdsa_verify(key: &[u8; 33], hash: &[u8; 32], der: &[u8]) -> Request {
    let mut data = Vec::with_capacity(key.len().saturating_add(32).saturating_add(der.len()));
    data.extend_from_slice(key);
    data.extend_from_slice(hash);
    data.extend_from_slice(der);
    Request {
        cmd: Cmd::EcdsaVerify,
        data,
    }
}

/// `ecdsa_verify_raw`: key_len(1) ‖ key ‖ 32-byte hash ‖ 32-byte r ‖
/// 32-byte s, the key in any format.  Panics on a key longer than 255
/// bytes, which no layout can carry.
pub fn ecdsa_verify_raw(key: &[u8], hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> Request {
    let key_len = u8::try_from(key.len()).expect("ecdsa_verify_raw: key of at most 255 bytes");
    let mut data = Vec::with_capacity(key.len().saturating_add(97));
    data.push(key_len);
    data.extend_from_slice(key);
    data.extend_from_slice(hash);
    data.extend_from_slice(r);
    data.extend_from_slice(s);
    Request {
        cmd: Cmd::EcdsaVerifyRaw,
        data,
    }
}

/// `ecdsa_sign`: 32-byte private key ‖ 32-byte hash.
pub fn ecdsa_sign(key: &[u8; 32], hash: &[u8; 32]) -> Request {
    Request {
        cmd: Cmd::EcdsaSign,
        data: [key.as_slice(), hash].concat(),
    }
}

/// `ecdsa_sign_compact`: compressed(1: 0 or 1) ‖ 32-byte key ‖ 32-byte hash.
pub fn ecdsa_sign_compact(compressed: bool, key: &[u8; 32], hash: &[u8; 32]) -> Request {
    Request {
        cmd: Cmd::EcdsaSignCompact,
        data: [&[u8::from(compressed)][..], key, hash].concat(),
    }
}

/// `ecdsa_recover_compact`: 32-byte hash ‖ the signature, of any length.
pub fn ecdsa_recover_compact(hash: &[u8; 32], sig: &[u8]) -> Request {
    Request {
        cmd: Cmd::EcdsaRecoverCompact,
        data: [hash.as_slice(), sig].concat(),
    }
}

/// `pubkey_parse`: the key bytes as they are.
pub fn pubkey_parse(key: &[u8]) -> Request {
    Request {
        cmd: Cmd::PubkeyParse,
        data: key.to_vec(),
    }
}

/// `schnorr_pubkey_parse`: the key bytes as they are.
pub fn schnorr_pubkey_parse(key: &[u8]) -> Request {
    Request {
        cmd: Cmd::SchnorrPubkeyParse,
        data: key.to_vec(),
    }
}

/// `schnorr_parse`: the signature bytes as they are.
pub fn schnorr_parse(sig: &[u8]) -> Request {
    Request {
        cmd: Cmd::SchnorrParse,
        data: sig.to_vec(),
    }
}

/// `schnorr_sign`: 32-byte private key ‖ 32-byte hash.
pub fn schnorr_sign(key: &[u8; 32], hash: &[u8; 32]) -> Request {
    Request {
        cmd: Cmd::SchnorrSign,
        data: [key.as_slice(), hash].concat(),
    }
}

/// `schnorr_verify`: 33-byte key ‖ 32-byte hash ‖ 64-byte signature.
pub fn schnorr_verify(key: &[u8; 33], hash: &[u8; 32], sig: &[u8; 64]) -> Request {
    Request {
        cmd: Cmd::SchnorrVerify,
        data: [key.as_slice(), hash, sig].concat(),
    }
}

/// `ed25519_pubkey_parse`: the key bytes as they are.
pub fn ed25519_pubkey_parse(key: &[u8]) -> Request {
    Request {
        cmd: Cmd::Ed25519PubkeyParse,
        data: key.to_vec(),
    }
}

/// `ed25519_parse`: the signature bytes as they are.
pub fn ed25519_parse(sig: &[u8]) -> Request {
    Request {
        cmd: Cmd::Ed25519Parse,
        data: sig.to_vec(),
    }
}

/// `ed25519_sign`: 32-byte seed ‖ message.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Request {
    Request {
        cmd: Cmd::Ed25519Sign,
        data: [seed.as_slice(), msg].concat(),
    }
}

/// `ed25519_verify`: 32-byte key ‖ raw 64-byte signature (R ‖ S, never
/// parsed) ‖ message.
pub fn ed25519_verify(key: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> Request {
    Request {
        cmd: Cmd::Ed25519Verify,
        data: [key.as_slice(), sig, msg].concat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    /// Names are distinct, and are the oracle's command strings.
    #[test]
    fn names_are_the_oracles() {
        let names: std::collections::BTreeSet<&str> = Cmd::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), Cmd::ALL.len(), "two commands share a name");
        let oracle = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/oracle/main.go"
        ));
        for cmd in Cmd::ALL {
            assert!(
                oracle.contains(&format!("case \"{}\":", cmd.name())),
                "tools/oracle has no command {}",
                cmd.name()
            );
        }
    }

    /// Each encoder's bytes, laid out as the oracle's handler slices them.
    #[test]
    fn encoders_follow_the_oracle_layouts() {
        let key33: [u8; 33] = core::array::from_fn(|i| u8::try_from(i).expect("small") | 0x80);
        let key32 = [0x11u8; 32];
        let hash = [0x22u8; 32];
        let r = [0x33u8; 32];
        let s = [0x44u8; 32];
        let sig64 = [0x55u8; 64];

        let req = ecdsa_verify(&key33, &hash, &[0x30, 0x06]);
        assert_eq!(req.cmd, Cmd::EcdsaVerify);
        assert_eq!(req.data[..33], key33);
        assert_eq!(req.data[33..65], hash);
        assert_eq!(req.data[65..], [0x30, 0x06]);

        let req = ecdsa_verify_raw(&key33[..], &hash, &r, &s);
        assert_eq!(
            req.data.len(),
            1 + 33 + 96,
            "1 + key_len + 96, as the handler requires"
        );
        assert_eq!(req.data[0], 33);
        assert_eq!(req.data[1..34], key33);
        assert_eq!(req.data[34..66], hash);
        assert_eq!(req.data[66..98], r);
        assert_eq!(req.data[98..], s);
        assert_eq!(ecdsa_verify_raw(&[], &hash, &r, &s).data[0], 0);

        assert_eq!(ecdsa_sign(&key32, &hash).data, [key32, hash].concat());
        let req = ecdsa_sign_compact(true, &key32, &hash);
        assert_eq!(req.data.len(), 65);
        assert_eq!(
            (req.data[0], &req.data[1..33], &req.data[33..]),
            (1, &key32[..], &hash[..])
        );
        assert_eq!(ecdsa_sign_compact(false, &key32, &hash).data[0], 0);
        assert_eq!(
            ecdsa_recover_compact(&hash, &sig64[..3]).data,
            [&hash[..], &sig64[..3]].concat()
        );
        assert_eq!(schnorr_sign(&key32, &hash).data, [key32, hash].concat());
        let req = schnorr_verify(&key33, &hash, &sig64);
        assert_eq!(req.data.len(), 33 + 32 + 64);
        assert_eq!(
            (&req.data[..33], &req.data[33..65], &req.data[65..]),
            (&key33[..], &hash[..], &sig64[..])
        );
        let req = ed25519_verify(&key32, &sig64, b"msg");
        assert_eq!(
            (&req.data[..32], &req.data[32..96], &req.data[96..]),
            (&key32[..], &sig64[..], &b"msg"[..])
        );
        assert_eq!(ed25519_sign(&key32, b"m").data, [&key32[..], b"m"].concat());
        for (req, cmd) in [
            (ecdsa_parse_der(&[1, 2]), Cmd::EcdsaParseDer),
            (pubkey_parse(&[1, 2]), Cmd::PubkeyParse),
            (schnorr_pubkey_parse(&[1, 2]), Cmd::SchnorrPubkeyParse),
            (schnorr_parse(&[1, 2]), Cmd::SchnorrParse),
            (ed25519_pubkey_parse(&[1, 2]), Cmd::Ed25519PubkeyParse),
            (ed25519_parse(&[1, 2]), Cmd::Ed25519Parse),
        ] {
            assert_eq!((req.cmd, req.data), (cmd, vec![1, 2]));
        }
    }

    /// A request line is one JSON object the oracle's decoder takes, with
    /// the id first and the data in lowercase hex.
    #[test]
    fn request_lines_are_json() {
        let mut line = String::new();
        pubkey_parse(&unhex("00abff")).push_line(18_446_744_073_709_551_615, &mut line);
        assert_eq!(
            line,
            "{\"id\":18446744073709551615,\"cmd\":\"pubkey_parse\",\"data\":\"00abff\"}\n"
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("JSON");
        assert_eq!(parsed["id"], 18_446_744_073_709_551_615_u64);
        let parsed: serde_json::Value = serde_json::from_str(BUILD_INFO_LINE).expect("JSON");
        assert_eq!(parsed["cmd"], "build_info");
        assert!(parsed.get("id").is_none());
    }
}
