// SPDX-License-Identifier: ISC
//! ECDSA signatures over secp256k1 (Decred signature type 0), mirroring dcrd
//! `dcrec/secp256k1/v4/ecdsa`: DER parsing with dcrd's exact acceptance
//! rules and error identities, low-S DER serialization, verification that
//! accepts high-S signatures (as dcrd does), and RFC6979 deterministic
//! signing.

use core::fmt;

use super::{GROUP_ORDER_BYTES, HALF_GROUP_ORDER, PrivateKey, PublicKey, is_zero, negate_mod_n};

/// The ASN.1 identifier for a sequence.
const ASN1_SEQUENCE_ID: u8 = 0x30;

/// The ASN.1 identifier for an integer.
const ASN1_INTEGER_ID: u8 = 0x02;

/// DER signature parsing errors, 1:1 with dcrd `ecdsa.ErrorKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Signature shorter than the 8-byte minimum (`ErrSigTooShort`).
    SigTooShort,
    /// Signature longer than the 72-byte maximum (`ErrSigTooLong`).
    SigTooLong,
    /// Wrong ASN.1 sequence identifier (`ErrSigInvalidSeqID`).
    SigInvalidSeqID,
    /// Declared data length does not match the signature length
    /// (`ErrSigInvalidDataLen`).
    SigInvalidDataLen,
    /// The S type identifier is missing (`ErrSigMissingSTypeID`).
    SigMissingSTypeID,
    /// The S length is missing (`ErrSigMissingSLen`).
    SigMissingSLen,
    /// The declared S length does not match (`ErrSigInvalidSLen`).
    SigInvalidSLen,
    /// Wrong ASN.1 integer identifier for R (`ErrSigInvalidRIntID`).
    SigInvalidRIntID,
    /// R has zero length (`ErrSigZeroRLen`).
    SigZeroRLen,
    /// R is negative (`ErrSigNegativeR`).
    SigNegativeR,
    /// R has excess leading padding (`ErrSigTooMuchRPadding`).
    SigTooMuchRPadding,
    /// R is zero (`ErrSigRIsZero`).
    SigRIsZero,
    /// R is >= the group order (`ErrSigRTooBig`).
    SigRTooBig,
    /// Wrong ASN.1 integer identifier for S (`ErrSigInvalidSIntID`).
    SigInvalidSIntID,
    /// S has zero length (`ErrSigZeroSLen`).
    SigZeroSLen,
    /// S is negative (`ErrSigNegativeS`).
    SigNegativeS,
    /// S has excess leading padding (`ErrSigTooMuchSPadding`).
    SigTooMuchSPadding,
    /// S is zero (`ErrSigSIsZero`).
    SigSIsZero,
    /// S is >= the group order (`ErrSigSTooBig`).
    SigSTooBig,
}

impl Error {
    /// The dcrd error kind name, used for differential comparison.
    pub fn kind_name(self) -> &'static str {
        match self {
            Error::SigTooShort => "ErrSigTooShort",
            Error::SigTooLong => "ErrSigTooLong",
            Error::SigInvalidSeqID => "ErrSigInvalidSeqID",
            Error::SigInvalidDataLen => "ErrSigInvalidDataLen",
            Error::SigMissingSTypeID => "ErrSigMissingSTypeID",
            Error::SigMissingSLen => "ErrSigMissingSLen",
            Error::SigInvalidSLen => "ErrSigInvalidSLen",
            Error::SigInvalidRIntID => "ErrSigInvalidRIntID",
            Error::SigZeroRLen => "ErrSigZeroRLen",
            Error::SigNegativeR => "ErrSigNegativeR",
            Error::SigTooMuchRPadding => "ErrSigTooMuchRPadding",
            Error::SigRIsZero => "ErrSigRIsZero",
            Error::SigRTooBig => "ErrSigRTooBig",
            Error::SigInvalidSIntID => "ErrSigInvalidSIntID",
            Error::SigZeroSLen => "ErrSigZeroSLen",
            Error::SigNegativeS => "ErrSigNegativeS",
            Error::SigTooMuchSPadding => "ErrSigTooMuchSPadding",
            Error::SigSIsZero => "ErrSigSIsZero",
            Error::SigSTooBig => "ErrSigSTooBig",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

impl core::error::Error for Error {}

/// An ECDSA signature: R and S as 32-byte big-endian scalars in `[0, N-1]`
/// (parsing rejects zero, but like dcrd's `NewSignature` the direct
/// constructor allows it; verification of a zero component always fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Construct from raw 32-byte big-endian scalars; `None` if either is
    /// >= the group order.
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Option<Signature> {
        if r >= GROUP_ORDER_BYTES || s >= GROUP_ORDER_BYTES {
            return None;
        }
        Some(Signature { r, s })
    }

    /// The R component as 32 big-endian bytes.
    pub fn r_bytes(&self) -> &[u8; 32] {
        &self.r
    }

    /// The S component as 32 big-endian bytes.
    pub fn s_bytes(&self) -> &[u8; 32] {
        &self.s
    }

    /// Serialize as DER with the S component normalized to at most half the
    /// group order, exactly like dcrd `Signature.Serialize` (which also does
    /// not append the Decred sighash-type byte).
    // Length arithmetic is bounded by the fixed 33-byte component buffers
    // (total <= 72); the scalar negation itself lives in negate_mod_n.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn serialize(&self) -> Vec<u8> {
        // Force low-S: both S and its negation are valid, so serialization
        // makes the malleability-free choice.
        let mut s = self.s;
        if s > HALF_GROUP_ORDER {
            s = negate_mod_n(&s);
        }

        // 33-byte buffers keep a leading zero available for values whose
        // high bit is set (DER sign bit).
        let mut r_buf = [0u8; 33];
        r_buf[1..].copy_from_slice(&self.r);
        let mut s_buf = [0u8; 33];
        s_buf[1..].copy_from_slice(&s);

        // Trim leading zeros while the value stays non-negative per DER.
        fn canonical(buf: &[u8; 33]) -> &[u8] {
            let mut v: &[u8] = buf;
            while v.len() > 1 && v[0] == 0x00 && v[1] & 0x80 == 0 {
                v = &v[1..];
            }
            v
        }
        let canon_r = canonical(&r_buf);
        let canon_s = canonical(&s_buf);

        let total_len = 6 + canon_r.len() + canon_s.len();
        let mut b = Vec::with_capacity(total_len);
        b.push(ASN1_SEQUENCE_ID);
        b.push((total_len - 2) as u8);
        b.push(ASN1_INTEGER_ID);
        b.push(canon_r.len() as u8);
        b.extend_from_slice(canon_r);
        b.push(ASN1_INTEGER_ID);
        b.push(canon_s.len() as u8);
        b.extend_from_slice(canon_s);
        b
    }

    /// Whether the signature is valid for the 32-byte hash and public key
    /// (dcrd `Signature.Verify`). High-S signatures verify, matching dcrd —
    /// the low-S rule applies to serialization, not verification.
    pub fn verify(&self, hash: &[u8; 32], pub_key: &PublicKey) -> bool {
        // R and S must be in [1, N-1] (upper bound guaranteed by
        // construction).
        if is_zero(&self.r) || is_zero(&self.s) {
            return false;
        }

        // libsecp256k1 verification enforces low-S; (r, s) and (r, N-s) are
        // valid for exactly the same message/key pairs, so normalizing first
        // yields dcrd's accept-any-S verdict.
        let mut s = self.s;
        if s > HALF_GROUP_ORDER {
            s = negate_mod_n(&s);
        }
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&self.r);
        compact[32..].copy_from_slice(&s);
        let sig = libsecp256k1::ecdsa::Signature::from_compact(&compact)
            .expect("r and s are reduced scalars");

        let msg = libsecp256k1::Message::from_digest(*hash);
        libsecp256k1::SECP256K1
            .verify_ecdsa(&msg, &sig, pub_key.inner())
            .is_ok()
    }
}

/// Parse a DER signature with dcrd's exact acceptance rules and error
/// identities (`ecdsa.ParseDERSignature`): ASN.1 sequence/integer structure
/// with single-byte lengths, minimal-padding integer encodings, and R/S
/// required to be in `[1, N-1]`.
// Offset arithmetic is bounded by the 72-byte maximum signature length
// enforced up front (single-byte DER lengths keep every sum under 328).
#[allow(clippy::arithmetic_side_effects)]
pub fn parse_der_signature(sig: &[u8]) -> Result<Signature, Error> {
    // Offsets into the signature per the DER layout; see dcrd for the
    // annotated walkthrough. All lengths in secp256k1 signatures fit in a
    // single byte, so multi-byte ASN.1 lengths are (correctly) not handled.
    const MIN_SIG_LEN: usize = 8;
    const MAX_SIG_LEN: usize = 72;
    const SEQUENCE_OFFSET: usize = 0;
    const DATA_LEN_OFFSET: usize = 1;
    const R_TYPE_OFFSET: usize = 2;
    const R_LEN_OFFSET: usize = 3;
    const R_OFFSET: usize = 4;

    let sig_len = sig.len();
    if sig_len < MIN_SIG_LEN {
        return Err(Error::SigTooShort);
    }
    if sig_len > MAX_SIG_LEN {
        return Err(Error::SigTooLong);
    }

    if sig[SEQUENCE_OFFSET] != ASN1_SEQUENCE_ID {
        return Err(Error::SigInvalidSeqID);
    }

    if usize::from(sig[DATA_LEN_OFFSET]) != sig_len - 2 {
        return Err(Error::SigInvalidDataLen);
    }

    // Locate the S elements and ensure they are inside the signature. The
    // check order below deliberately matches dcrd's for error-identity
    // parity.
    let r_len = usize::from(sig[R_LEN_OFFSET]);
    let s_type_offset = R_OFFSET + r_len;
    let s_len_offset = s_type_offset + 1;
    if s_type_offset >= sig_len {
        return Err(Error::SigMissingSTypeID);
    }
    if s_len_offset >= sig_len {
        return Err(Error::SigMissingSLen);
    }

    let s_offset = s_len_offset + 1;
    let s_len = usize::from(sig[s_len_offset]);
    if s_offset + s_len != sig_len {
        return Err(Error::SigInvalidSLen);
    }

    if sig[R_TYPE_OFFSET] != ASN1_INTEGER_ID {
        return Err(Error::SigInvalidRIntID);
    }
    if r_len == 0 {
        return Err(Error::SigZeroRLen);
    }
    if sig[R_OFFSET] & 0x80 != 0 {
        return Err(Error::SigNegativeR);
    }
    if r_len > 1 && sig[R_OFFSET] == 0x00 && sig[R_OFFSET + 1] & 0x80 == 0 {
        return Err(Error::SigTooMuchRPadding);
    }

    if sig[s_type_offset] != ASN1_INTEGER_ID {
        return Err(Error::SigInvalidSIntID);
    }
    if s_len == 0 {
        return Err(Error::SigZeroSLen);
    }
    if sig[s_offset] & 0x80 != 0 {
        return Err(Error::SigNegativeS);
    }
    if s_len > 1 && sig[s_offset] == 0x00 && sig[s_offset + 1] & 0x80 == 0 {
        return Err(Error::SigTooMuchSPadding);
    }

    // The encoding is valid DER; now enforce that R and S are in [1, N-1]
    // per the ECDSA spec.
    let r = scalar_from_der_int(&sig[R_OFFSET..R_OFFSET + r_len], Error::SigRTooBig)?;
    if is_zero(&r) {
        return Err(Error::SigRIsZero);
    }
    let s = scalar_from_der_int(&sig[s_offset..s_offset + s_len], Error::SigSTooBig)?;
    if is_zero(&s) {
        return Err(Error::SigSIsZero);
    }

    Ok(Signature { r, s })
}

/// Interpret a DER integer body as a 32-byte scalar in `[0, N-1]`, stripping
/// leading zeros first (dcrd strips then checks size/overflow).
// The stripped length is checked <= 32 before the 32 - len indexing.
#[allow(clippy::arithmetic_side_effects)]
fn scalar_from_der_int(bytes: &[u8], too_big: Error) -> Result<[u8; 32], Error> {
    let mut stripped = bytes;
    while !stripped.is_empty() && stripped[0] == 0x00 {
        stripped = &stripped[1..];
    }
    if stripped.len() > 32 {
        return Err(too_big);
    }
    let mut out = [0u8; 32];
    out[32 - stripped.len()..].copy_from_slice(stripped);
    if out >= GROUP_ORDER_BYTES {
        return Err(too_big);
    }
    Ok(out)
}

/// Produce a deterministic (RFC6979) low-S signature for the 32-byte hash,
/// matching dcrd `ecdsa.Sign` byte-for-byte (verified differentially).
pub fn sign(priv_key: &PrivateKey, hash: &[u8; 32]) -> Signature {
    let msg = libsecp256k1::Message::from_digest(*hash);
    let sig = libsecp256k1::SECP256K1.sign_ecdsa(&msg, priv_key.inner());
    let compact = sig.serialize_compact();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&compact[..32]);
    s.copy_from_slice(&compact[32..]);
    Signature { r, s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    /// Ported from dcrd's TestSignatureParsing (signature_test.go).
    #[test]
    fn parse_der_vectors() {
        struct Case {
            name: &'static str,
            sig: &'static str,
            want: Result<(), Error>,
        }
        let cases = [
            Case {
                // Signature from Decred blockchain tx
                // 76634e947f49dfc6228c3e8a09cd3e9e15893439fc06df7df0fc6f08d659856c:0
                name: "valid signature 1",
                sig: "3045022100cd496f2ab4fe124f977ffe3caa09f7576d8a34156b4e55d326b4dffc0399a094022013500a0510b5094bff220c74656879b8ca0369d3da78004004c970790862fc03",
                want: Ok(()),
            },
            Case {
                name: "valid signature 2",
                sig: "3044022036334e598e51879d10bf9ce3171666bc2d1bbba6164cf46dd1d882896ba35d5d022056c39af9ea265c1b6d7eab5bc977f06f81e35cdcac16f3ec0fd218e30f2bad2a",
                want: Ok(()),
            },
            Case {
                name: "empty",
                sig: "",
                want: Err(Error::SigTooShort),
            },
            Case {
                name: "too short",
                sig: "30050201000200",
                want: Err(Error::SigTooShort),
            },
            Case {
                name: "too long",
                sig: "3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef8481352480101",
                want: Err(Error::SigTooLong),
            },
            Case {
                name: "bad ASN.1 sequence id",
                sig: "3145022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidSeqID),
            },
            Case {
                name: "mismatched data length (short one byte)",
                sig: "3044022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidDataLen),
            },
            Case {
                name: "mismatched data length (long one byte)",
                sig: "3046022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidDataLen),
            },
            Case {
                name: "bad R ASN.1 int marker",
                sig: "304403204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                want: Err(Error::SigInvalidRIntID),
            },
            Case {
                name: "zero R length",
                sig: "30240200022030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigZeroRLen),
            },
            Case {
                name: "negative R (too little padding)",
                sig: "30440220b2ec8d34d473c3aa2ab5eb7cc4a0783977e5db8c8daf777e0b6d7bfa6b6623f302207df6f09af2c40460da2c2c5778f636d3b2e27e20d10d90f5a5afb45231454700",
                want: Err(Error::SigNegativeR),
            },
            Case {
                name: "too much R padding",
                sig: "304402200077f6e93de5ed43cf1dfddaa79fca4b766e1a8fc879b0333d377f62538d7eb5022054fed940d227ed06d6ef08f320976503848ed1f52d0dd6d17f80c9c160b01d86",
                want: Err(Error::SigTooMuchRPadding),
            },
            Case {
                name: "bad S ASN.1 int marker",
                sig: "3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074032030e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidSIntID),
            },
            Case {
                name: "missing S ASN.1 int marker",
                sig: "3023022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074",
                want: Err(Error::SigMissingSTypeID),
            },
            Case {
                name: "S length missing",
                sig: "3024022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef07402",
                want: Err(Error::SigMissingSLen),
            },
            Case {
                name: "invalid S length (short one byte)",
                sig: "3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074021f30e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidSLen),
            },
            Case {
                name: "invalid S length (long one byte)",
                sig: "3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef074022130e09575e7a1541aa018876a4003cefe1b061a90556b5140c63e0ef848135248",
                want: Err(Error::SigInvalidSLen),
            },
            Case {
                name: "zero S length",
                sig: "3025022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e49f2a1ac584fd546bef0740200",
                want: Err(Error::SigZeroSLen),
            },
            Case {
                name: "negative S (too little padding)",
                sig: "304402204fc10344934662ca0a93a84d14d650d8a21cf2ab91f608e8783d2999c955443202208441aacd6b17038ff3f6700b042934f9a6fea0cec2051b51dc709e52a5bb7d61",
                want: Err(Error::SigNegativeS),
            },
            Case {
                name: "too much S padding",
                sig: "304402206ad2fdaf8caba0f2cb2484e61b81ced77474b4c2aa069c852df1351b3314fe20022000695ad175b09a4a41cd9433f6b2e8e83253d6a7402096ba313a7be1f086dde5",
                want: Err(Error::SigTooMuchSPadding),
            },
            Case {
                name: "R == 0",
                sig: "30250201000220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                want: Err(Error::SigRIsZero),
            },
            Case {
                name: "R == N",
                sig: "3045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                want: Err(Error::SigRTooBig),
            },
            Case {
                name: "R > N (>32 bytes)",
                sig: "3045022101cd496f2ab4fe124f977ffe3caa09f756283910fc1a96f60ee6873e88d3cfe1d50220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                want: Err(Error::SigRTooBig),
            },
            Case {
                name: "R > N",
                sig: "3045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641420220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                want: Err(Error::SigRTooBig),
            },
            Case {
                name: "S == 0",
                sig: "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020100",
                want: Err(Error::SigSIsZero),
            },
            Case {
                name: "S == N",
                sig: "304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                want: Err(Error::SigSTooBig),
            },
            Case {
                name: "S > N (>32 bytes)",
                sig: "304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4102210113500a0510b5094bff220c74656879b784b246ba89c0a07bc49bcf05d8993d44",
                want: Err(Error::SigSTooBig),
            },
            Case {
                name: "S > N",
                sig: "304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
                want: Err(Error::SigSTooBig),
            },
        ];

        for case in &cases {
            let got = parse_der_signature(&unhex(case.sig)).map(|_| ());
            assert_eq!(got, case.want, "{}", case.name);
        }
    }

    /// Ported from dcrd's TestSignatureSerialize (signature_test.go).
    #[test]
    fn serialize_vectors() {
        fn scalar(hex: &str) -> [u8; 32] {
            unhex(hex).try_into().expect("32 bytes")
        }

        // (name, r, s, expected DER)
        let cases = [
            (
                "valid 1 - r and s most significant bits are zero",
                scalar("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"),
                scalar("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"),
                "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
            ),
            (
                "valid 2 - r most significant bit is one",
                scalar("82235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3"),
                scalar("24bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724"),
                "304502210082235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3022024bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724",
            ),
            (
                // High-S input: serialization must emit the low-S variant.
                "valid 3 - s most significant bit is one",
                scalar("1cadddc2838598fee7dc35a12b340c6bde8b389f7bfd19a1252a17c4b5ed2d71"),
                scalar("c1a251bbecb14b058a8bd77f65de87e51c47e95904f4c0e9d52eddc21c1415ac"),
                "304402201cadddc2838598fee7dc35a12b340c6bde8b389f7bfd19a1252a17c4b5ed2d7102203e5dae44134eb4fa757428809a2178199e66f38daa53df51eaa380cab4222b95",
            ),
            ("zero signature", [0u8; 32], [0u8; 32], "3006020100020100"),
        ];

        for (name, r, s, want) in cases {
            let sig = Signature::new(r, s).expect("scalars in range");
            assert_eq!(sig.serialize(), unhex(want), "{name}");
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let priv_key = PrivateKey::from_bytes(&{
            let mut k = [0u8; 32];
            k[31] = 42;
            k
        })
        .expect("valid key");
        let hash = dcroxide_testutil::unhex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        let hash: [u8; 32] = hash.try_into().expect("32 bytes");

        let sig = sign(&priv_key, &hash);
        let pub_key = priv_key.public_key();
        assert!(sig.verify(&hash, &pub_key));

        // Round-trips through DER.
        let der = sig.serialize();
        let parsed = parse_der_signature(&der).expect("own serialization parses");
        assert_eq!(parsed, sig, "sign always produces low-S");
        assert!(parsed.verify(&hash, &pub_key));

        // The high-S malleated variant still verifies (dcrd semantics)...
        let high_s = Signature::new(sig.r, negate_mod_n(&sig.s)).expect("in range");
        assert!(high_s.verify(&hash, &pub_key));
        // ...but serializes back to the low-S form.
        assert_eq!(high_s.serialize(), der);

        // A different message does not verify.
        let mut other = hash;
        other[0] ^= 1;
        assert!(!sig.verify(&other, &pub_key));
    }

    #[test]
    fn zero_component_never_verifies() {
        let priv_key = PrivateKey::from_bytes(&{
            let mut k = [0u8; 32];
            k[31] = 7;
            k
        })
        .expect("valid key");
        let pub_key = priv_key.public_key();
        let hash = [0x24u8; 32];
        let sig = sign(&priv_key, &hash);

        let zero_r = Signature::new([0u8; 32], *sig.s_bytes()).expect("in range");
        let zero_s = Signature::new(*sig.r_bytes(), [0u8; 32]).expect("in range");
        assert!(!zero_r.verify(&hash, &pub_key));
        assert!(!zero_s.verify(&hash, &pub_key));
    }
}
