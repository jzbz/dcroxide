// SPDX-License-Identifier: ISC
//! ECDSA signatures over secp256k1 (Decred signature type 0), mirroring dcrd
//! `dcrec/secp256k1/v4/ecdsa`: DER parsing with dcrd's exact acceptance
//! rules and error identities, low-S DER serialization, verification that
//! accepts high-S signatures (as dcrd does), RFC6979 deterministic
//! signing, plain and compact, and public key recovery from a compact
//! signature.

use alloc::vec::Vec;
use core::fmt;

use super::nonce::nonce_rfc6979;
use super::{
    GROUP_ORDER_BYTES, HALF_GROUP_ORDER, PRIME_MINUS_ORDER_BYTES, PrivateKey, PublicKey,
    add_group_order, is_zero, negate_mod_n,
};

/// The ASN.1 identifier for a sequence.
const ASN1_SEQUENCE_ID: u8 = 0x30;

/// The ASN.1 identifier for an integer.
const ASN1_INTEGER_ID: u8 = 0x02;

/// DER signature parsing and compact recovery errors, 1:1 with dcrd
/// `ecdsa.ErrorKind` (ecdsa/error.go).
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
    /// A compact signature is not 65 bytes long (`ErrSigInvalidLen`).
    SigInvalidLen,
    /// A compact signature's header is outside 27..=34, so it carries no
    /// valid public key recovery code (`ErrSigInvalidRecoveryCode`).
    SigInvalidRecoveryCode,
    /// A compact signature's recovery code has the overflow bit set, but
    /// R + N would reach the field prime (`ErrSigOverflowsPrime`).
    SigOverflowsPrime,
    /// Recovery found no curve point with R's x coordinate, or recovered
    /// the point at infinity (`ErrPointNotOnCurve`).
    PointNotOnCurve,
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
            Error::SigInvalidLen => "ErrSigInvalidLen",
            Error::SigInvalidRecoveryCode => "ErrSigInvalidRecoveryCode",
            Error::SigOverflowsPrime => "ErrSigOverflowsPrime",
            Error::PointNotOnCurve => "ErrPointNotOnCurve",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

impl core::error::Error for Error {}

/// The step of dcrd's `Signature.Verify` (ecdsa/signature.go:169-294)
/// that decides a verification, as [`Signature::verify_detailed`] reports
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStep {
    /// Step 1: r or s is zero; reject.
    Step1Zero,
    /// Step 6: u1 * G + u2 * Q is the point at infinity; reject.
    Step6Infinity,
    /// Step 8: r equals X.x; accept.
    Step8Accept,
    /// Step 9: r is at or above P - N, so r + N would wrap; reject.
    Step9Reject,
    /// Step 10: r + N equals X.x; accept.
    Step10Accept,
    /// Step 10: r + N does not equal X.x either; reject.
    Step10Reject,
}

impl VerifyStep {
    /// Whether dcrd's verdict at this step is true.
    pub fn accepts(self) -> bool {
        matches!(self, VerifyStep::Step8Accept | VerifyStep::Step10Accept)
    }
}

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
    /// (dcrd `Signature.Verify`), by dcrd's algorithm run by hand on k256
    /// ([`Signature::verify_detailed`]). High-S signatures verify, matching
    /// dcrd — the low-S rule applies to serialization, not verification.
    pub fn verify(&self, hash: &[u8; 32], pub_key: &PublicKey) -> bool {
        self.verify_detailed(hash, pub_key).accepts()
    }

    /// dcrd's `Signature.Verify` (ecdsa/signature.go:169-294) step by step
    /// on k256, returning the step that decides the verdict
    /// ([`VerifyStep::accepts`] is the verdict [`Signature::verify`]
    /// returns).  dcrd exports only the verdict; the step is what the
    /// signature soak holds against the branch each of its constructed
    /// cases was built to reach.
    ///
    /// Every input is public, so like dcrd's `NonConst` operations this
    /// runs in variable time.  dcrd's steps 7 and 8 compare r * Z^2 with
    /// the Jacobian X.x to save an inversion.  k256 keeps its homogeneous
    /// coordinates private, so the sum is normalized once and its affine x
    /// compared instead: with r in [1, N-1], X.x below P and P < 2N, X.x
    /// mod N equals r exactly when X.x is r or r + N, so one comparison
    /// covers steps 7 to 10, and r's bytes tell which step decided.  No S
    /// is normalized: dcrd accepts any S in [1, N-1].
    // The flagged operators are k256 scalar arithmetic, modular by definition.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn verify_detailed(&self, hash: &[u8; 32], pub_key: &PublicKey) -> VerifyStep {
        use k256::elliptic_curve::PrimeField;
        use k256::elliptic_curve::group::Group;
        use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
        use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};
        use k256::{FieldBytes, ProjectivePoint, Scalar};

        // Step 1: R and S must be in [1, N-1]; the upper bound holds by
        // construction (`Signature::new`, `parse_der_signature`).
        if is_zero(&self.r) || is_zero(&self.s) {
            return VerifyStep::Step1Zero;
        }
        let r = Scalar::from_repr(self.r.into()).expect("below N by construction");
        let s = Scalar::from_repr(self.s.into()).expect("below N by construction");

        // Step 2: e = H(m) mod N, as dcrd's `SetByteSlice` reduces the hash:
        // one conditional subtraction of N, exact for any 256-bit value
        // since 2^256 < 2N.
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());

        // Step 3: w = S^-1 mod N, in variable time like dcrd's
        // `InverseValNonConst`.
        let w = Option::<Scalar>::from(s.invert_vartime()).expect("s is nonzero");

        // Step 4: u1 = e * w mod N and u2 = R * w mod N.
        let u1 = e * w;
        let u2 = r * w;

        // Step 5: X = u1 * G + u2 * Q, as one variable-time GLV/wNAF pass
        // over both scalars.  dcrd's `AddNonConst` doubles when its two
        // operands are equal; every k256 addition is a complete formula,
        // which needs no such branch.  A zero u1 (a hash that is a multiple
        // of N) contributes the identity, as dcrd's
        // `ScalarBaseMultNonConst` of zero does.
        let big_x = ProjectivePoint::mul_by_generator_and_mul_add_vartime(
            &u1,
            &u2,
            &pub_key.as_k256_point(),
        );

        // Step 6: fail if X is the point at infinity.  This comes before
        // normalizing, which maps the identity to an x of zero and would
        // report the rejection as step 9 or 10.
        if bool::from(big_x.is_identity()) {
            return VerifyStep::Step6Infinity;
        }

        // Steps 7 to 10 on X's affine x, below P: one variable-time
        // inversion.
        let [affine] =
            <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[
                big_x,
            ]);
        let x = affine.x();
        if <Scalar as Reduce<FieldBytes>>::reduce(&x) == r {
            // X.x is r (step 8) or r + N (step 10; step 9 lets it through,
            // since r + N = X.x < P).
            let x_bytes: [u8; 32] = x.into();
            if x_bytes == self.r {
                VerifyStep::Step8Accept
            } else {
                VerifyStep::Step10Accept
            }
        } else if self.r >= PRIME_MINUS_ORDER_BYTES {
            // Step 9: r + N would reach P (big-endian byte order is
            // numeric order).
            VerifyStep::Step9Reject
        } else {
            // Step 10: X.x is neither r nor r + N.
            VerifyStep::Step10Reject
        }
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

/// The size of a compact recoverable signature: one header byte
/// carrying the recovery code plus R and S (dcrd `compactSigSize`).
pub const COMPACT_SIG_SIZE: usize = 65;

/// The value the compact signature header byte carries on top of the
/// recovery code (dcrd `compactSigMagicOffset`).
pub const COMPACT_SIG_MAGIC_OFFSET: u8 = 27;

/// The header flag marking the public key as compressed (dcrd
/// `compactSigCompPubKey`).
pub const COMPACT_SIG_COMP_PUB_KEY: u8 = 4;

/// Recover the public key from a compact recoverable signature over
/// the 32-byte hash, returning it along with whether the signature
/// commits to its compressed serialization: dcrd's `ecdsa.RecoverCompact`
/// (ecdsa/signature.go:792-997), with its error kinds in its order.
///
/// The checks run in dcrd's order, the first failing one deciding the
/// error: the length ([`Error::SigInvalidLen`]); the header, 27 to 34
/// ([`Error::SigInvalidRecoveryCode`]); R below N
/// ([`Error::SigRTooBig`]) and nonzero ([`Error::SigRIsZero`]); S below N
/// ([`Error::SigSTooBig`]) and nonzero ([`Error::SigSIsZero`]); with the
/// recovery code's overflow bit, R + N below P
/// ([`Error::SigOverflowsPrime`]); a curve point with that x coordinate
/// and the code's oddness ([`Error::PointNotOnCurve`]); and a recovered
/// key that is not the point at infinity ([`Error::PointNotOnCurve`]
/// again).  dcrd's doc comment says it first verifies the signature; it
/// does not, and neither does this: the key returned is the one the
/// signature and code determine.
///
/// Every input is public, so like dcrd's `NonConst` operations the
/// arithmetic runs in variable time.
// The flagged operators are k256 scalar arithmetic, modular by definition,
// and the header's subtraction, which the range check above it guards.
#[allow(clippy::arithmetic_side_effects)]
pub fn recover_compact(signature: &[u8], hash: &[u8; 32]) -> Result<(PublicKey, bool), Error> {
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::group::Group;
    use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
    use k256::elliptic_curve::point::{BatchNormalize, DecompressPoint};
    use k256::elliptic_curve::subtle::Choice;
    use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

    // The signature must be the correct length.
    if signature.len() != COMPACT_SIG_SIZE {
        return Err(Error::SigInvalidLen);
    }

    // The compact signature recovery code is the value 27 + the public
    // key recovery code, with the compressed flag on top.
    let sig_recovery_code = signature[0];
    if !(COMPACT_SIG_MAGIC_OFFSET..COMPACT_SIG_MAGIC_OFFSET + COMPACT_SIG_COMP_PUB_KEY * 2)
        .contains(&sig_recovery_code)
    {
        return Err(Error::SigInvalidRecoveryCode);
    }
    let sig_recovery_code = sig_recovery_code - COMPACT_SIG_MAGIC_OFFSET;
    let was_compressed = sig_recovery_code & COMPACT_SIG_COMP_PUB_KEY != 0;
    let pub_key_recovery_code = sig_recovery_code & 3;

    // Step 1: R and S must be in [1, N-1], each checked against N before
    // it is checked against zero.
    let r_bytes: [u8; 32] = signature[1..33].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = signature[33..65].try_into().expect("32 bytes");
    let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).ok_or(Error::SigRTooBig)?;
    if bool::from(r.is_zero()) {
        return Err(Error::SigRIsZero);
    }
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes.into())).ok_or(Error::SigSTooBig)?;
    if bool::from(s.is_zero()) {
        return Err(Error::SigSIsZero);
    }

    // Steps 2 and 3: R as a field element, plus N when the overflow bit is
    // set, which fails when R + N would reach P (dcrd's
    // `IsGtOrEqPrimeMinusOrder`).  Big-endian byte order is numeric order.
    let mut x_bytes = r_bytes;
    if pub_key_recovery_code & 2 != 0 {
        if r_bytes >= PRIME_MINUS_ORDER_BYTES {
            return Err(Error::SigOverflowsPrime);
        }
        x_bytes = add_group_order(&r_bytes);
    }

    // Steps 4 and 5: the point X with that x and the y whose oddness the
    // code's low bit gives, failing when x^3 + 7 has no square root (dcrd's
    // `DecompressY`, which normalizes the root before choosing it, as
    // k256's `decompress` does).  x is below P here.
    let big_x = Option::<AffinePoint>::from(AffinePoint::decompress(
        &x_bytes.into(),
        Choice::from(pub_key_recovery_code & 1),
    ))
    .ok_or(Error::PointNotOnCurve)?;

    // Step 6: e = H(m) mod N, one conditional subtraction of N.
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());

    // Step 7: w = R^-1 mod N, in variable time like dcrd's
    // `InverseValNonConst`.
    let w = Option::<Scalar>::from(r.invert_vartime()).expect("r is nonzero");

    // Step 8: u1 = -(e * w) mod N and u2 = s * w mod N.
    let u1 = -(e * w);
    let u2 = s * w;

    // Step 9: Q = u1 * G + u2 * X, as one variable-time GLV/wNAF pass.
    // dcrd's `AddNonConst` doubles when its operands are equal; k256's
    // complete additions need no such branch, as in verification.
    let q = ProjectivePoint::mul_by_generator_and_mul_add_vartime(
        &u1,
        &u2,
        &ProjectivePoint::from(big_x),
    );

    // Step 10: fail if Q is the point at infinity, dcrd's second use of
    // `ErrPointNotOnCurve`, tested before Q is normalized.
    if bool::from(q.is_identity()) {
        return Err(Error::PointNotOnCurve);
    }

    // The key in affine coordinates: one variable-time inversion.
    let [affine] =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[q]);
    Ok((PublicKey::from_affine(affine), was_compressed))
}

/// dcrd's `sign` (ecdsa/signature.go:554-663): steps 2 to 6 of the
/// signature with the private key `d`, the nonce `k` in [1, N-1] and the
/// hash reduced mod N, `e`.  It returns the low-S signature with its
/// public key recovery code (bit 0: R.y is odd; bit 1: R.x is at or above
/// N), or `None` when r or s is zero, for the caller to retry with the
/// next nonce.
///
/// `k` and `d` are secret, so this runs in constant time where dcrd uses
/// its variable-time `ScalarBaseMultNonConst` and `InverseValNonConst`:
/// k256's `GENERATOR * k`, `invert` and `to_affine`, the same values.
/// dcrd branches on whether s is above half the order; the negation and
/// the recovery code's oddness flip here are selected, not branched on,
/// with the same result.  The only branches left are dcrd's retries on a
/// zero r or s.
// The flagged operators are k256 scalar arithmetic, modular by definition.
#[allow(clippy::arithmetic_side_effects)]
fn sign_with_nonce(
    d: &k256::Scalar,
    k: &k256::Scalar,
    e: &k256::Scalar,
) -> Option<(Signature, u8)> {
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::scalar::IsHigh;
    use k256::elliptic_curve::subtle::{Choice, ConditionallySelectable};
    use k256::{FieldBytes, ProjectivePoint, Scalar};
    use zeroize::Zeroize;

    // Step 2: kG, in affine coordinates.
    let kg = (ProjectivePoint::GENERATOR * *k).to_affine();

    // Step 3: r = kG.x mod N (dcrd `fieldToModNScalar`), retrying when
    // zero; overflow records whether kG.x was at or above N.
    let xb = kg.x();
    let overflow: Choice = Scalar::from_repr(xb).is_none();
    let r = <Scalar as Reduce<FieldBytes>>::reduce(&xb);
    if bool::from(r.is_zero()) {
        return None;
    }

    // The public key recovery code: the overflow bit, then R.y's oddness.
    let mut code = u8::conditional_select(&0, &2, overflow) | kg.y_is_odd().unwrap_u8();

    // Step 4: e = H(m) mod N is the caller's, computed once per hash.

    // Step 5: s = k^-1(e + dr) mod N, retrying when zero.
    let mut k_inv = Option::<Scalar>::from(k.invert()).expect("nonce is nonzero");
    let mut s = (*d * r + *e) * k_inv;
    k_inv.zeroize();
    if bool::from(s.is_zero()) {
        return None;
    }

    // Modification B: s = -s when above N/2, which flips R.y's oddness
    // (the point -k*G).
    let high = s.is_high();
    s = Scalar::conditional_select(&s, &-s, high);
    code ^= high.unwrap_u8();

    // Step 6.
    Some((
        Signature {
            r: r.to_repr().into(),
            s: s.to_repr().into(),
        },
        code,
    ))
}

/// dcrd's `signRFC6979` (ecdsa/signature.go:668-720): the RFC6979 nonce
/// from the private key and the raw hash, never reduced, through
/// [`sign_with_nonce`], retrying with the next nonce while it returns
/// `None`.  The key copy, the private scalar and each nonce are wiped, as
/// dcrd zeroes its key bytes and each nonce.
fn sign_rfc6979(priv_key: &PrivateKey, hash: &[u8; 32]) -> (Signature, u8) {
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::ops::Reduce;
    use k256::{FieldBytes, Scalar};
    use zeroize::{Zeroize, Zeroizing};

    let priv_bytes = priv_key.secret_bytes();
    let mut d = Scalar::from_repr((*priv_bytes).into()).expect("private key is a valid scalar");

    // Step 4: e = H(m) mod N (dcrd `e.SetByteSlice(hash)`), the same for
    // every attempt.
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());

    let mut iteration = 0u32;
    loop {
        // Step 1: the deterministic nonce in [1, N-1].
        let nonce = Zeroizing::new(nonce_rfc6979(&priv_bytes[..], hash, None, None, iteration));
        iteration = iteration.wrapping_add(1);
        let mut k = Scalar::from_repr((*nonce).into()).expect("the nonce is a valid scalar");

        // Steps 2 to 6.
        let attempt = sign_with_nonce(&d, &k, &e);
        k.zeroize();
        if let Some(result) = attempt {
            d.zeroize();
            return result;
        }
    }
}

/// Produce a deterministic (RFC6979) low-S signature for the 32-byte hash,
/// dcrd's `ecdsa.Sign` (ecdsa/signature.go:727-730), byte for byte.
///
/// Every hash, below or above the group order N, is signed on k256
/// through a port of dcrd's `signRFC6979`, which derives the nonce from
/// the hash as it is, never reduced mod N.
pub fn sign(priv_key: &PrivateKey, hash: &[u8; 32]) -> Signature {
    sign_rfc6979(priv_key, hash).0
}

/// Produce a compact recoverable signature for the 32-byte hash, dcrd's
/// `ecdsa.SignCompact` (ecdsa/signature.go:771-786), byte for byte.
///
/// The format is `<1-byte code><32-byte R><32-byte S>`, where the code is
/// 27 ([`COMPACT_SIG_MAGIC_OFFSET`]) plus the public key recovery code,
/// plus 4 ([`COMPACT_SIG_COMP_PUB_KEY`]) when `is_compressed_key` says the
/// signer's key is serialized compressed.  [`recover_compact`] returns
/// that key and the flag.  R and S are the signature [`sign`] makes.
// The code is at most 27 + 3 + 4 = 34.
#[allow(clippy::arithmetic_side_effects)]
pub fn sign_compact(
    priv_key: &PrivateKey,
    hash: &[u8; 32],
    is_compressed_key: bool,
) -> [u8; COMPACT_SIG_SIZE] {
    let (sig, code) = sign_rfc6979(priv_key, hash);
    let mut b = [0u8; COMPACT_SIG_SIZE];
    // `+`, as dcrd adds: 27 is 0b11011, so an OR would lose bits.
    b[0] = COMPACT_SIG_MAGIC_OFFSET
        + code
        + if is_compressed_key {
            COMPACT_SIG_COMP_PUB_KEY
        } else {
            0
        };
    b[1..33].copy_from_slice(&sig.r);
    b[33..65].copy_from_slice(&sig.s);
    b
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
        assert_eq!(
            zero_r.verify_detailed(&hash, &pub_key),
            VerifyStep::Step1Zero
        );
        assert_eq!(
            zero_s.verify_detailed(&hash, &pub_key),
            VerifyStep::Step1Zero
        );
    }

    /// Compact recovery's checks run in dcrd's order
    /// (ecdsa/signature.go:858-923): a signature failing two of them
    /// reports the earlier one.
    #[test]
    fn recover_checks_in_dcrds_order() {
        fn compact(header: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
            [&[header][..], r, s].concat()
        }
        let hash = [0x5au8; 32];
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[31] = 1;
        let n = GROUP_ORDER_BYTES;
        let p_minus_n = PRIME_MINUS_ORDER_BYTES;
        // 27 plus the overflow bit, for an uncompressed key.
        let overflow = COMPACT_SIG_MAGIC_OFFSET + 2;

        let cases: [(&str, Vec<u8>, Error); 7] = [
            (
                "64 bytes with a bad header",
                compact(26, &n, &zero)[..64].to_vec(),
                Error::SigInvalidLen,
            ),
            (
                "header 26 with R >= N",
                compact(26, &n, &one),
                Error::SigInvalidRecoveryCode,
            ),
            (
                "R >= N with S = 0",
                compact(COMPACT_SIG_MAGIC_OFFSET, &n, &zero),
                Error::SigRTooBig,
            ),
            (
                "R = 0 with S >= N",
                compact(COMPACT_SIG_MAGIC_OFFSET, &zero, &n),
                Error::SigRIsZero,
            ),
            (
                "overflow bit, R >= P - N and S >= N",
                compact(overflow, &p_minus_n, &n),
                Error::SigSTooBig,
            ),
            (
                "overflow bit, R >= P - N and S = 0",
                compact(overflow, &p_minus_n, &zero),
                Error::SigSIsZero,
            ),
            (
                "overflow bit with R = P - N",
                compact(overflow, &p_minus_n, &one),
                Error::SigOverflowsPrime,
            ),
        ];
        for (name, sig, want) in cases {
            assert_eq!(recover_compact(&sig, &hash), Err(want), "{name}");
        }
    }

    /// dcrd's TestSignAndVerify rows that sign with an explicit nonce
    /// rather than the RFC6979 one (ecdsa/signature_test.go): `sign_with_nonce`
    /// returns each row's (r, s) and recovery code.  The RFC6979 rows check
    /// the code through `sign_compact` (`tests/ecdsa_vectors.rs`).
    #[test]
    fn sign_with_nonce_returns_dcrds_code() {
        use k256::elliptic_curve::PrimeField;
        use k256::elliptic_curve::ops::Reduce;
        use k256::{FieldBytes, Scalar};

        /// A big-endian value left-padded to 32 bytes (one row's S has 31).
        fn be32(hex: &str) -> [u8; 32] {
            let bytes = unhex(hex);
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(&bytes);
            out
        }
        fn scalar(hex: &str) -> Scalar {
            Scalar::from_repr(be32(hex).into()).expect("below the group order")
        }

        // (name, key, nonce, hash, r, s, code); code bit 0 is R.y's
        // oddness (dcrd `pubKeyRecoveryCodeOddnessBit`).
        let cases = [
            (
                "key 0x1, blake256(0x01020304), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "a6df66500afeb7711d4c8e2220960855d940a5ed57260d2c98fbf6066cca283e",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "b073759a96a835b09b79e7b93c37fdbe48fb82b000c4a0e1404ba5d1fbc15d0a",
                "7e34928a3e3832ec21e7711644d9388f7deb6340ead661d7056b0665974b87f3",
                1u8,
            ),
            (
                "key 0x2, blake256(0x01020304), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "679a6d36e7fe6c02d7668af86d78186e8f9ccc04371ac1c8c37939d1f5cae07a",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "4a090d82f48ca12d9e7aa24b5dcc187ee0db2920496f671d63e86036aaa7997e",
                "261ffe8ba45007fc5fbbba6b4c6ed41beafb48b09fa8af1d6a3fbc6ccefbad",
                0,
            ),
            (
                "key 0x1, blake256(0x0102030405), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "65f880c892fdb6e7f74f76b18c7c942cfd037ef9cf97c39c36e08bbc36b41616",
                "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
                "72e5666f4e9d1099447b825cf737ee32112f17a67e2ca7017ae098da31dfbb8b",
                "1a7326da661a62f66358dcf53300afdc8e8407939dae1192b5b0899b0254311b",
                1,
            ),
            (
                "key 0x2, blake256(0x0102030405), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "026ece4cfb704733dd5eef7898e44c33bd5a0d749eb043f48705e40fa9e9afa0",
                "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
                "3c4c5a2f217ea758113fd4e89eb756314dfad101a300f48e5bd764d3b6e0f8bf",
                "6513e82442f133cb892514926ed9158328ead488ff1b027a31827603a65009df",
                1,
            ),
        ];

        for (name, key, nonce, hash, r, s, code) in cases {
            let e = <Scalar as Reduce<FieldBytes>>::reduce(&be32(hash).into());
            let want = Signature::new(be32(r), be32(s)).expect("below the group order");
            assert_eq!(
                sign_with_nonce(&scalar(key), &scalar(nonce), &e),
                Some((want, code)),
                "{name}"
            );
        }
    }
}
