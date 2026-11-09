// SPDX-License-Identifier: ISC
//! The seam between this crate's dcrd-ordered steps and the variable-time
//! arithmetic they borrow from `dcroxide-secp256k1-vartime` (ADR-0016).
//! This is the only module of the crate that names that crate, so another
//! backend, k256's code before it or a libsecp256k1 binding, slots in, as
//! code, by changing this module alone.  Only the verification, recovery
//! and key-parsing functions name this module, with the public key's
//! field and the conversion of a private key's public point, so no
//! signing function reaches it; `tests/vartime_boundary.rs` holds both
//! rules.
//!
//! Every function here takes public values only, and none can panic: when
//! the vartime crate declines (its safegcd loop past an iteration cap, a
//! case its proof rules out) or hands back a value the seam's own check
//! rejects, the seam computes the answer on k256 instead,
//! as the code before it did, and debug builds assert.  An assertion in
//! release would be an outage under `panic = "abort"`.  Tests can force
//! that path, which production never takes, so it is tested too.
//!
//! ECDSA verification's sum, u1*G + u2*Q, comes back as an opaque [`Sum`]
//! that answers dcrd's steps 6 to 10 (is it infinity, is its x this
//! value) without the caller knowing which backend computed it.  Compact
//! recovery and Schnorr verification always need the affine point, so
//! their entry points convert inside, where the inverse's cap can fall
//! back, and return the answer resolved ([`Recovery`], R's x and parity).
//! dcrec's `PublicKey` holds the crate's affine point ([`KeyPoint`]), so
//! verification hands it to the multiply as it is, and parsing and
//! recovery produce it; k256 meets a public key only in the fallback
//! arms, which convert it, and in `PrivateKey::public_key`, whose
//! constant-time product enters the key type once.

use dcroxide_secp256k1_vartime as vartime;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

use super::PublicKey;

/// A public key's point on the vartime crate: on the curve, never
/// infinity, both coordinates normalized.  dcrec's `PublicKey` holds it,
/// and its equality compares x and y, as dcrd's `IsEqual` does, on the
/// crate's normalized limbs and in variable time, since a public key is
/// public.  Only this module names the crate, so the key type lives here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyPoint(vartime::Affine);

impl KeyPoint {
    /// (x, y), each big-endian and below P.
    pub(crate) fn to_be_bytes(self) -> ([u8; 32], [u8; 32]) {
        self.0.to_be_bytes()
    }

    /// Whether y is odd.
    pub(crate) fn y_is_odd(self) -> bool {
        self.0.y_is_odd()
    }
}

/// The key point (x, y), each given big-endian and below P, as dcrec's key
/// parsing has checked: `None` unless y^2 = x^3 + 7, by the vartime
/// crate's port of libsecp256k1's `ge_set_xy` and `ge_is_valid_var`
/// (dcrd's `IsOnCurve`).  Its `None` is the answer, not a reason to fall
/// back: the check has no cap or guard that could decline.  Builds with
/// debug assertions hold it to k256's `from_coordinates`.
pub(crate) fn from_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Option<KeyPoint> {
    let p = vartime::Affine::from_be_coordinates(x, y).map(KeyPoint);
    #[cfg(test)]
    let p = if curve_check_refused() { None } else { p };
    debug_assert_eq!(
        p.is_some(),
        k256_affine(x, y).is_some(),
        "the vartime crate and k256 disagree on whether a key is on the curve"
    );
    p
}

/// A point k256 computed, a finished public value, as the key type: its
/// normalized coordinates through the vartime crate's curve check.
/// `None` only if that check refuses a point k256 holds, a fault in one
/// of them, which its callers reject on (or test builds force it).
/// Callers: `PrivateKey::public_key`, and the k256 arms of decompression
/// and recovery.
pub(crate) fn key_from_k256(p: &AffinePoint) -> Option<KeyPoint> {
    if conversion_refused() {
        return None;
    }
    vartime::Affine::from_be_coordinates(&p.x().into(), &p.y().into()).map(KeyPoint)
}

/// The key as k256's point, for the fallback arms: `from_coordinates` on
/// the key's coordinates, which the vartime crate has checked.  `None`
/// only if k256 refuses them, a fault in one of the two curve checks (or
/// test builds force it).
fn k256_key(q: &PublicKey) -> Option<ProjectivePoint> {
    if conversion_refused() {
        return None;
    }
    let (x, y) = q.point.to_be_bytes();
    k256_affine(&x, &y).map(ProjectivePoint::from)
}

/// k256's point (x, y), through `from_coordinates`, which checks both
/// coordinates below P and the curve equation; `None` if it refuses.
fn k256_affine(x: &[u8; 32], y: &[u8; 32]) -> Option<AffinePoint> {
    Option::<AffinePoint>::from(AffinePoint::from_coordinates(&(*x).into(), &(*y).into()))
}

/// X = u1*G + u2*Q of ECDSA verification, from whichever backend computed
/// it.  The caller asks only what dcrd's steps 6 to 10 ask.
pub(crate) struct Sum(SumInner);

/// The two backends' forms of the sum.
enum SumInner {
    /// The vartime crate's Jacobian point.
    Vt(vartime::Point),
    /// k256's sum, normalized once; `None` is the identity.
    K256(Option<AffinePoint>),
}

impl Sum {
    /// Whether X is the point at infinity (dcrd's step 6).
    pub(crate) fn is_infinity(&self) -> bool {
        match &self.0 {
            SumInner::Vt(p) => p.is_infinity(),
            SumInner::K256(a) => a.is_none(),
        }
    }

    /// Whether X's affine x equals x, given big-endian and below P: dcrd's
    /// steps 8 and 10, false at infinity.  The vartime crate's point
    /// answers as dcrd does, X == x * Z^2, with no inversion.  k256 keeps
    /// its projective coordinates private, so its sum was normalized once
    /// and its affine x is compared instead.
    pub(crate) fn x_equals(&self, x_be: &[u8; 32]) -> bool {
        match &self.0 {
            SumInner::Vt(p) => p.x_equals_var(x_be),
            SumInner::K256(a) => a.is_some_and(|a| <[u8; 32]>::from(a.x()) == *x_be),
        }
    }
}

/// ECDSA verification's steps 2 to 5 for a signature (r, s) with both in
/// [1, N-1], as the caller's step 1 and the signature's construction
/// establish: e = H mod N, w = s^-1, u1 = e*w, u2 = r*w and X = u1*G +
/// u2*Q, dcrd's order, all on the vartime crate's port of libsecp256k1
/// (its safegcd inverse, its scalar products and its Straus loop over
/// static generator tables).
///
/// Should the vartime crate decline anywhere (r or s not below N, the
/// inverse's cap, the wNAF builder's guard; none happens for valid
/// inputs), the sum is k256's combined multiply and one
/// `batch_normalize_vartime` instead, the code the last gate soak ran
/// (stage 2a's fallback), and debug builds assert.  Builds with debug
/// assertions also compute k256's sum every time and stop if the two
/// disagree on infinity or on x; that check only reads, so they compute
/// what release computes.
pub(crate) fn ecdsa_mul_g_add(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], q: &PublicKey) -> Sum {
    if !forced_fallback() {
        let x = vartime_sum(hash, r, s, q).filter(|_| !forced_decline());
        debug_assert!(
            x.is_some(),
            "the vartime crate declined ECDSA verification's sum"
        );
        if let Some(x) = x {
            let sum = Sum(SumInner::Vt(x));
            #[cfg(debug_assertions)]
            cross_check(&sum, &k256_sum(hash, r, s, q));
            return sum;
        }
    }
    k256_sum(hash, r, s, q)
}

/// Steps 2 to 5 on the vartime crate; `None` wherever it declines.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the vartime crate's Scalar operators are arithmetic mod N"
)]
fn vartime_sum(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    q: &PublicKey,
) -> Option<vartime::Point> {
    let r = vartime::Scalar::from_be_bytes(r)?;
    let s = vartime::Scalar::from_be_bytes(s)?;
    let e = vartime::Scalar::reduce_be_bytes(hash);
    let w = s.try_inverse_var()?;
    let u1 = e * w;
    let u2 = r * w;
    #[cfg(test)]
    let u2 = if skewed_sum() { u2 + vt_one() } else { u2 };
    mul_g_add(&u1, &u2, q)
}

/// u1*G + u2*Q on the vartime crate: the key is already the crate's
/// point, so it goes to `ecmult_var` as it is.  ECDSA and Schnorr
/// verification share it.
fn mul_g_add(u1: &vartime::Scalar, u2: &vartime::Scalar, q: &PublicKey) -> Option<vartime::Point> {
    vartime::ecmult_var(&q.point.0, u2, u1)
}

/// Steps 2 to 5 on k256, the code the last gate soak ran as stage 2a's
/// fallback: its `invert_vartime`, its scalar products, its combined multiply
/// `mul_by_generator_and_mul_add_vartime` and one `batch_normalize_vartime`,
/// on the key converted to k256's point.  Should r or s not be below N,
/// which the caller rules out, or k256 refuse the key, which takes a
/// fault in one of the two curve checks on top of the decline that sent
/// the seam here, there is no answer to fall back to: the sum is the
/// identity, so verification fails at step 6, and debug builds assert.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256's Scalar operators are arithmetic mod N"
)]
fn k256_sum(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], q: &PublicKey) -> Sum {
    let r = Option::<Scalar>::from(Scalar::from_repr((*r).into()));
    let w = Option::<Scalar>::from(Scalar::from_repr((*s).into()))
        .and_then(|s| Option::<Scalar>::from(s.invert_vartime()));
    let (Some(r), Some(w)) = (r, w) else {
        debug_assert!(false, "k256_sum: r or s not in [1, N-1]");
        return Sum(SumInner::K256(None));
    };
    let Some(q) = k256_key(q) else {
        debug_assert!(false, "k256 refused a key the vartime crate holds");
        return Sum(SumInner::K256(None));
    };
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());
    let x = ProjectivePoint::mul_by_generator_and_mul_add_vartime(&(e * w), &(r * w), &q);
    if bool::from(x.is_identity()) {
        return Sum(SumInner::K256(None));
    }
    let [a] =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[x]);
    Sum(SumInner::K256(Some(a)))
}

/// Builds with debug assertions: the vartime crate's sum agrees with
/// k256's on infinity and, when finite, on x.  Reads and asserts only.
#[cfg(debug_assertions)]
fn cross_check(vt: &Sum, k: &Sum) {
    assert_eq!(
        vt.is_infinity(),
        k.is_infinity(),
        "ECDSA verification's sum: infinity differs from k256's"
    );
    if let SumInner::K256(Some(a)) = &k.0 {
        assert!(
            vt.x_equals(&a.x().into()),
            "ECDSA verification's sum: x differs from k256's"
        );
    }
}

/// Compact recovery's steps 4 to 10, from whichever backend computed them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Steps 4 and 5: no curve point has the x (dcrd's `DecompressY`
    /// fails).
    NoPoint,
    /// Step 10: Q = u1*G + u2*R is the point at infinity.
    Infinity,
    /// The recovered key.
    Key(PublicKey),
}

/// Compact recovery's steps 4 to 10 for r and s in [1, N-1], as the
/// caller's step 1 establishes, and x, below P, the R.x of its steps 2
/// and 3, with the oddness of the code's low bit: R decompressed, e = H
/// mod N, w = r^-1, u1 = -e*w, u2 = s*w, Q = u1*G + u2*R, and Q's affine
/// coordinates, dcrd's order, all on the vartime crate's port of
/// libsecp256k1 (its square root, its safegcd inverses, its scalar
/// products, its Straus loop and one field inversion, x and y normalized
/// as dcrd's `ToAffine` does).  The key is the crate's point, as it came.
///
/// Should the vartime crate decline anywhere (r or s not below N, R of
/// the wrong x or oddness, an inverse's cap, the wNAF builder's guard;
/// none happens for valid inputs), the answer is
/// k256's instead, and debug builds assert.  Builds with debug assertions
/// also compute k256's answer every time and stop unless both give the
/// same outcome and, for a key, the same bytes; that check only reads.
pub(crate) fn recover_key(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    x: &[u8; 32],
    odd: bool,
) -> Recovery {
    if !forced_fallback() {
        let v = vartime_recover(hash, r, s, x, odd).filter(|_| !forced_decline());
        debug_assert!(v.is_some(), "the vartime crate declined compact recovery");
        if let Some(v) = v {
            #[cfg(debug_assertions)]
            cross_check_recovery(&v, &k256_recover(hash, r, s, x, odd));
            return v;
        }
    }
    k256_recover(hash, r, s, x, odd)
}

/// Steps 4 to 10 on the vartime crate; `None` wherever it declines.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the vartime crate's Scalar operators are arithmetic mod N"
)]
fn vartime_recover(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    x: &[u8; 32],
    odd: bool,
) -> Option<Recovery> {
    let Some(big_r) = vt_decompress(x, odd)? else {
        return Some(Recovery::NoPoint);
    };
    let r = vartime::Scalar::from_be_bytes(r)?;
    let s = vartime::Scalar::from_be_bytes(s)?;
    let e = vartime::Scalar::reduce_be_bytes(hash);
    let w = r.try_inverse_var()?;
    let u1 = -(e * w);
    let u2 = s * w;
    #[cfg(test)]
    let u2 = if skewed_sum() { u2 + vt_one() } else { u2 };
    #[cfg(test)]
    let (u1, u2) = if negated_recovery() {
        (-u1, -u2)
    } else {
        (u1, u2)
    };
    let q = vartime::ecmult_var(&big_r, &u2, &u1)?;
    match vt_to_affine(&q) {
        Ok(None) => Some(Recovery::Infinity),
        Ok(Some(a)) => Some(Recovery::Key(PublicKey { point: KeyPoint(a) })),
        Err(vartime::Fallback) => None,
    }
}

/// Steps 4 to 10 on k256, the fallback and the reference: its
/// decompression, its scalar arithmetic and `invert_vartime`, its combined
/// multiply `mul_by_generator_and_mul_add_vartime` (the multiply stage
/// 2a's loop fell back to) and one `batch_normalize_vartime`, recovery's
/// normalization before the vartime crate took it, the key entering the
/// key type through [`key_from_k256`].  Should r or s not be in [1, N-1],
/// which the caller rules out, or that conversion fail, which takes a
/// fault in one of the two curve checks on top of the decline that sent
/// the seam here, there is no answer to fall back to: it is `Infinity`,
/// which rejects, and debug builds assert.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256's Scalar operators are arithmetic mod N"
)]
fn k256_recover(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], x: &[u8; 32], odd: bool) -> Recovery {
    let Some(big_r) = k256_decompress(x, odd) else {
        return Recovery::NoPoint;
    };
    let w = Option::<Scalar>::from(Scalar::from_repr((*r).into()))
        .and_then(|r| Option::<Scalar>::from(r.invert_vartime()));
    let s = Option::<Scalar>::from(Scalar::from_repr((*s).into()));
    let (Some(w), Some(s)) = (w, s) else {
        debug_assert!(false, "k256_recover: r or s not in [1, N-1]");
        return Recovery::Infinity;
    };
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());
    let q = ProjectivePoint::mul_by_generator_and_mul_add_vartime(
        &-(e * w),
        &(s * w),
        &ProjectivePoint::from(big_r),
    );
    if bool::from(q.is_identity()) {
        return Recovery::Infinity;
    }
    let [a] =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[q]);
    let Some(point) = key_from_k256(&a) else {
        debug_assert!(false, "the vartime crate refused a key k256 computed");
        return Recovery::Infinity;
    };
    Recovery::Key(PublicKey { point })
}

/// Builds with debug assertions: the vartime crate's recovery gives
/// k256's outcome and, for a key, k256's key bytes.  Reads and asserts
/// only.
#[cfg(debug_assertions)]
fn cross_check_recovery(vt: &Recovery, k: &Recovery) {
    if let (Recovery::Key(a), Recovery::Key(b)) = (vt, k) {
        assert_eq!(
            a.serialize_uncompressed(),
            b.serialize_uncompressed(),
            "compact recovery: the key differs from k256's"
        );
    } else {
        assert_eq!(vt, k, "compact recovery: the outcome differs from k256's");
    }
}

/// EC-Schnorr-DCRv0 verification's steps 7 to 10, the arithmetic, for s
/// below N (parsing) and e below N (step 6), both given big-endian: R =
/// s*G + e*Q in affine form, as R.x big-endian and whether R.y is odd, or
/// `None` when R is the point at infinity.  On the vartime crate: one
/// pass of its Straus loop (with s = 0 the G half has no digits, so only
/// e*Q is formed) and one field inversion, x and y normalized before
/// either is read, as dcrd's `ToAffine` does.
///
/// Should the vartime crate decline (s or e not below N, the wNAF
/// builder's guard, the inverse's cap; none happens for valid inputs), R
/// is k256's instead, and debug builds assert.
/// Builds with debug assertions also compute k256's R every time and stop
/// unless both agree on infinity, on x and on the parity; that check only
/// reads.
pub(crate) fn schnorr_mul_g_add(
    s: &[u8; 32],
    e: &[u8; 32],
    q: &PublicKey,
) -> Option<([u8; 32], bool)> {
    if !forced_fallback() {
        let v = vartime_schnorr(s, e, q).filter(|_| !forced_decline());
        debug_assert!(
            v.is_some(),
            "the vartime crate declined Schnorr verification's sum"
        );
        if let Some(v) = v {
            #[cfg(debug_assertions)]
            assert_eq!(
                v,
                k256_schnorr(s, e, q),
                "Schnorr verification's R differs from k256's"
            );
            return v;
        }
    }
    k256_schnorr(s, e, q)
}

/// Steps 7 to 10's arithmetic on the vartime crate: the outer `None`
/// wherever it declines, the inner `None` at infinity.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the vartime crate's Scalar operators are arithmetic mod N"
)]
fn vartime_schnorr(s: &[u8; 32], e: &[u8; 32], q: &PublicKey) -> Option<Option<([u8; 32], bool)>> {
    let s = vartime::Scalar::from_be_bytes(s)?;
    let e = vartime::Scalar::from_be_bytes(e)?;
    #[cfg(test)]
    let e = if skewed_sum() { e + vt_one() } else { e };
    match vt_to_affine(&mul_g_add(&s, &e, q)?) {
        Ok(None) => Some(None),
        Ok(Some(a)) => Some(Some((a.to_be_bytes().0, a.y_is_odd()))),
        Err(vartime::Fallback) => None,
    }
}

/// Steps 7 to 10's arithmetic on k256, the fallback and the reference:
/// its combined multiply `mul_by_generator_and_mul_add_vartime` (the
/// multiply stage 2a's loop fell back to) and the constant-time
/// `to_affine` Schnorr verification used before the vartime crate took
/// it, on the key converted to k256's point.  Should s or e not be below
/// N, which the caller rules out, or k256 refuse the key, which takes a
/// fault in one of the two curve checks on top of the decline that sent
/// the seam here, there is no answer to fall back to: R counts as
/// infinity, so verification fails at step 8, and debug builds assert.
fn k256_schnorr(s: &[u8; 32], e: &[u8; 32], q: &PublicKey) -> Option<([u8; 32], bool)> {
    let s = Option::<Scalar>::from(Scalar::from_repr((*s).into()));
    let e = Option::<Scalar>::from(Scalar::from_repr((*e).into()));
    let (Some(s), Some(e)) = (s, e) else {
        debug_assert!(false, "k256_schnorr: s or e not below N");
        return None;
    };
    let Some(q) = k256_key(q) else {
        debug_assert!(false, "k256 refused a key the vartime crate holds");
        return None;
    };
    let x = ProjectivePoint::mul_by_generator_and_mul_add_vartime(&s, &e, &q);
    if bool::from(x.is_identity()) {
        return None;
    }
    let a = x.to_affine();
    Some((a.x().into(), bool::from(a.y_is_odd())))
}

/// The vartime crate's affine conversion: `Ok(None)` at infinity, and
/// `Err(Fallback)`, a decline, should the field inverse pass its cap,
/// which no input reaches.  Test builds can force that decline for a
/// finite point, so that both callers' handling of it is tested.
#[inline(always)]
fn vt_to_affine(q: &vartime::Point) -> Result<Option<vartime::Affine>, vartime::Fallback> {
    #[cfg(test)]
    if !q.is_infinity() && FORCE_CAP.with(core::cell::Cell::get) {
        return Err(vartime::Fallback);
    }
    q.to_affine_var()
}

/// x's point with the oddness asked for, on the vartime crate:
/// `Some(None)` when no point has x, which is an answer (builds with debug
/// assertions hold it to k256's), and `None`, a decline, when the point it
/// returns has another x or oddness, as a port bug might give.
fn vt_decompress(x: &[u8; 32], odd: bool) -> Option<Option<vartime::Affine>> {
    let Some(a) = vartime::Affine::decompress_var(x, odd ^ wrong_oddness()) else {
        debug_assert!(
            k256_decompress(x, odd).is_none(),
            "the vartime crate found no point for an x k256 decompresses"
        );
        return Some(None);
    };
    let (ax, _) = a.to_be_bytes();
    (ax == *x && a.y_is_odd() == odd).then_some(Some(a))
}

/// The curve point whose x, below P, is given big-endian and whose y has
/// the oddness `odd`, or `None` when x^3 + 7 has no square root, so that
/// no point has this x: dcrd's `DecompressY`, on the vartime crate's port
/// of libsecp256k1's square root, which normalizes the root before reading
/// its oddness and again after negating it, as dcrd does.  Its caller,
/// compressed key parsing, has established x < P; compact recovery
/// decompresses inside [`recover_key`].
///
/// The vartime crate's `None` is the answer, not a reason to fall back;
/// builds with debug assertions hold it to k256's.  Its point must have
/// the x and the oddness asked for, two byte compares, and is the key as
/// it is; should either compare refuse it, the seam decompresses on k256
/// instead, the code before this, its point entering the key type
/// through [`key_from_k256`], and debug builds assert.  Should that
/// conversion fail too, which takes two independent faults, there is no
/// answer to fall back to, and the key is refused.
pub(crate) fn decompress(x: &[u8; 32], odd: bool) -> Option<KeyPoint> {
    if !forced_fallback() {
        let p = vt_decompress(x, odd);
        debug_assert!(
            p.is_some(),
            "the vartime crate's decompressed point has another x or oddness"
        );
        if let Some(p) = p {
            return p.map(KeyPoint);
        }
    }
    let p = key_from_k256(&k256_decompress(x, odd)?);
    debug_assert!(p.is_some(), "the vartime crate refused a key k256 computed");
    p
}

/// k256's decompression, the code before the vartime crate's.
fn k256_decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    Option::<AffinePoint>::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
}

#[cfg(test)]
std::thread_local! {
    /// Set by [`tests::force_fallback`]: the seam takes k256's path.
    static FORCE_FALLBACK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::force_wrong_oddness`]: the seam asks the vartime
    /// crate for the other oddness, as a port bug might answer.
    static WRONG_ODDNESS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::force_decline`]: the vartime crate's result counts
    /// as declined (ECDSA verification's sum, recovery, Schnorr's R).
    static FORCE_DECLINE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::skew_sum`]: the vartime crate is given u2 + 1
    /// (ECDSA verification and recovery) or e + 1 (Schnorr verification),
    /// as a port bug might compute, so the debug cross-check must stop it.
    static SKEW_SUM: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::force_cap`]: the vartime crate's affine conversion
    /// declines for a finite point, as past the field inverse's cap.
    static FORCE_CAP: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::refuse_conversion`]: the conversions between the
    /// key type and k256 ([`key_from_k256`], [`k256_key`]) refuse, as a
    /// fault in either curve check would, so that the paths behind a
    /// refused conversion are tested.
    static REFUSE_CONVERSION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::negate_recovery`]: the vartime crate's recovery is
    /// given -u1 and -u2, so it computes -Q, a key with the right x and
    /// the other y, as a port bug might, and the debug cross-check must
    /// stop it.
    static NEGATE_RECOVERY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    /// Set by [`tests::refuse_curve_check`]: the vartime crate's curve
    /// check of a 65-byte key refuses every point, as a port bug might,
    /// so the debug cross-check must stop it.
    static REFUSE_CURVE_CHECK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Whether a test has the vartime crate's recovery negate u1 and u2.
#[cfg(test)]
fn negated_recovery() -> bool {
    NEGATE_RECOVERY.with(core::cell::Cell::get)
}

/// Whether a test has the vartime crate's curve check refuse every point.
#[cfg(test)]
fn curve_check_refused() -> bool {
    REFUSE_CURVE_CHECK.with(core::cell::Cell::get)
}

/// Whether a test has the key's conversions refuse on this thread.
#[cfg(test)]
fn conversion_refused() -> bool {
    REFUSE_CONVERSION.with(core::cell::Cell::get)
}

/// Production converts every key it is given.
#[cfg(not(test))]
#[inline(always)]
fn conversion_refused() -> bool {
    false
}

/// Whether a test has the vartime crate's result count as declined.
#[cfg(test)]
fn forced_decline() -> bool {
    FORCE_DECLINE.with(core::cell::Cell::get)
}

/// Whether a test has the vartime crate given a skewed u2 or e.
#[cfg(test)]
fn skewed_sum() -> bool {
    SKEW_SUM.with(core::cell::Cell::get)
}

/// One, the skew.
#[cfg(test)]
fn vt_one() -> vartime::Scalar {
    let mut one = [0u8; 32];
    one[31] = 1;
    vartime::Scalar::reduce_be_bytes(&one)
}

/// Production never declines a result it has.
#[cfg(not(test))]
#[inline(always)]
fn forced_decline() -> bool {
    false
}

/// Whether a test has forced k256's path on this thread.
#[cfg(test)]
fn forced_fallback() -> bool {
    FORCE_FALLBACK.with(core::cell::Cell::get)
}

/// Whether a test has the seam ask for the wrong oddness on this thread.
#[cfg(test)]
fn wrong_oddness() -> bool {
    WRONG_ODDNESS.with(core::cell::Cell::get)
}

/// Production never forces the fallback.
#[cfg(not(test))]
#[inline(always)]
fn forced_fallback() -> bool {
    false
}

/// Production asks for the oddness it was given.
#[cfg(not(test))]
#[inline(always)]
fn wrong_oddness() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic: k256 scalar operators, which are modular, \
                  and byte indices below 32"
    )]

    use super::*;

    use dcroxide_testutil::SplitMix64;
    use k256::FieldBytes;
    use k256::elliptic_curve::ops::Reduce;

    use crate::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES};

    /// Runs `f` with `flag` set on this thread, and clears it on the way
    /// out, a panic included.
    fn with_flag<T>(
        flag: &'static std::thread::LocalKey<core::cell::Cell<bool>>,
        f: impl FnOnce() -> T,
    ) -> T {
        struct Clear(&'static std::thread::LocalKey<core::cell::Cell<bool>>);
        impl Drop for Clear {
            fn drop(&mut self) {
                self.0.with(|c| c.set(false));
            }
        }
        flag.with(|c| c.set(true));
        let _clear = Clear(flag);
        f()
    }

    /// Runs `f` with the seam forced onto k256's path on this thread.
    pub(super) fn force_fallback<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&FORCE_FALLBACK, f)
    }

    /// Runs `f` with the seam asking the vartime crate for the other
    /// oddness on this thread.
    pub(super) fn force_wrong_oddness<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&WRONG_ODDNESS, f)
    }

    /// Runs `f` with the vartime crate's result counted as declined on
    /// this thread.
    fn force_decline<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&FORCE_DECLINE, f)
    }

    /// Runs `f` with the vartime crate given u2 + 1 on this thread.
    #[cfg(debug_assertions)]
    fn skew_sum<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&SKEW_SUM, f)
    }

    /// Runs `f` with the vartime crate's affine conversion declining for
    /// a finite point on this thread.
    fn force_cap<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&FORCE_CAP, f)
    }

    /// Runs `f` with the key's conversions between the key type and k256
    /// refusing on this thread.
    fn refuse_conversion<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&REFUSE_CONVERSION, f)
    }

    /// Runs `f` with the vartime crate's recovery given -u1 and -u2 on
    /// this thread.
    #[cfg(debug_assertions)]
    fn negate_recovery<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&NEGATE_RECOVERY, f)
    }

    /// Runs `f` with the vartime crate's curve check of a 65-byte key
    /// refusing every point on this thread.
    fn refuse_curve_check<T>(f: impl FnOnce() -> T) -> T {
        with_flag(&REFUSE_CURVE_CHECK, f)
    }

    /// The key type of a point k256 holds, which must be on the curve.
    fn key_of(a: &AffinePoint) -> PublicKey {
        PublicKey::from_k256_point(a).expect("a curve point")
    }

    /// A k256 point's coordinates, big-endian.
    fn bytes_of(a: &AffinePoint) -> ([u8; 32], [u8; 32]) {
        (a.x().into(), a.y().into())
    }

    /// Nonzero scalars below N for recovery's r, s and hash: 1, 2, N-1,
    /// N-2, every 2^k below N, and random ones, uniform and with long runs
    /// of zero or one bits.
    fn inputs() -> Vec<[u8; 32]> {
        let mut v = Vec::new();
        let mut one = [0u8; 32];
        one[31] = 1;
        v.push(one);
        let mut two = [0u8; 32];
        two[31] = 2;
        v.push(two);
        let mut nm1 = GROUP_ORDER_BYTES;
        nm1[31] -= 1;
        v.push(nm1);
        let mut nm2 = GROUP_ORDER_BYTES;
        nm2[31] -= 2;
        v.push(nm2);
        for k in 0..256 {
            let mut b = [0u8; 32];
            b[31 - k / 8] = 1 << (k % 8);
            if b < GROUP_ORDER_BYTES {
                v.push(b);
            }
        }
        let mut rng = SplitMix64(0xbac4_e2d0_0001);
        for i in 0..512 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            match i % 4 {
                1 => b[..20].fill(0),
                2 => b[..16].fill(0xff),
                3 => b[8..].fill(0),
                _ => {}
            }
            let s = <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
            if !bool::from(s.is_zero()) {
                v.push(s.to_repr().into());
            }
        }
        v
    }

    /// k256's own decompression, the reference.
    fn reference_decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
        Option::<AffinePoint>::from(AffinePoint::decompress(
            &(*x).into(),
            Choice::from(u8::from(odd)),
        ))
    }

    /// x values below P for decompression: 0, 1, 2, 7, P-1, P-2, P-3 (the
    /// largest x with a point), P-N and N (the recovery boundary), every
    /// 2^k, and random ones, uniform and with long runs of zero or one
    /// bits; about half have no point.
    fn decompress_inputs() -> Vec<[u8; 32]> {
        let small = |v: u8| {
            let mut b = [0u8; 32];
            b[31] = v;
            b
        };
        let below_p = |d: u8| {
            let mut b = FIELD_PRIME_BYTES;
            b[31] -= d;
            b
        };
        let mut v = vec![
            small(0),
            small(1),
            small(2),
            small(7),
            below_p(1),
            below_p(2),
            below_p(3),
            crate::secp256k1::PRIME_MINUS_ORDER_BYTES,
            GROUP_ORDER_BYTES,
        ];
        for k in 0..256 {
            let mut b = [0u8; 32];
            b[31 - k / 8] = 1 << (k % 8);
            v.push(b);
        }
        let mut rng = SplitMix64(0xbac4_e2d0_0002);
        while v.len() < 1024 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            match v.len() % 4 {
                1 => b[..20].fill(0),
                2 => b[..16].fill(0xff),
                3 => b[8..].fill(0),
                _ => {}
            }
            if b < FIELD_PRIME_BYTES {
                v.push(b);
            }
        }
        v
    }

    /// The seam's decompression equals k256's `decompress`, point for
    /// point and None for None, through the vartime crate and through the
    /// forced fallback, for both oddnesses of every input.
    #[test]
    fn decompress_matches_k256_on_both_paths() {
        let (mut points, mut none) = (0u32, 0u32);
        for x in &decompress_inputs() {
            for odd in [false, true] {
                let want = reference_decompress(x, odd).map(|p| bytes_of(&p));
                let got = decompress(x, odd);
                let forced = force_fallback(|| decompress(x, odd));
                assert_eq!(
                    got.map(KeyPoint::to_be_bytes),
                    want,
                    "vartime path, x {x:02x?} odd {odd}"
                );
                assert_eq!(forced, got, "forced path, x {x:02x?} odd {odd}");
                match got {
                    Some(p) => {
                        points += 1;
                        assert_eq!(p.to_be_bytes().0, *x);
                        assert_eq!(p.y_is_odd(), odd);
                    }
                    None => none += 1,
                }
            }
        }
        // x = 0 has no point (7 is not a square mod P), and P-3 is the
        // largest x below P that has one.
        assert!(decompress(&[0; 32], false).is_none());
        let mut pm3 = FIELD_PRIME_BYTES;
        pm3[31] -= 3;
        assert!(decompress(&pm3, true).is_some());
        assert!(points > 700 && none > 700, "{points} points, {none} none");
    }

    /// The seam's consistency check: a point of the other oddness from the
    /// vartime crate, as a port bug might give, is not passed on.  Builds
    /// with debug assertions stop on it; without them the seam gives
    /// k256's point, and a `None` stays `None`.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "decompressed point has another x or oddness")
    )]
    fn a_point_of_the_wrong_oddness_is_not_passed_on() {
        for x in decompress_inputs().iter().take(64) {
            for odd in [false, true] {
                let got = force_wrong_oddness(|| decompress(x, odd));
                let want = reference_decompress(x, odd).map(|p| bytes_of(&p));
                assert_eq!(got.map(KeyPoint::to_be_bytes), want, "x {x:02x?} odd {odd}");
            }
        }
        assert!(!wrong_oddness());
    }

    /// The forced fallback really skips the vartime crate's decompression:
    /// with the vartime crate asked for the wrong oddness, the forced path
    /// still gives k256's point and the debug check that stops a point of
    /// the wrong oddness never runs.
    #[cfg(debug_assertions)]
    #[test]
    fn the_forced_fallback_skips_the_vartime_decompression() {
        for x in decompress_inputs().iter().take(64) {
            for odd in [false, true] {
                let got = force_fallback(|| force_wrong_oddness(|| decompress(x, odd)));
                let want = reference_decompress(x, odd).map(|p| bytes_of(&p));
                assert_eq!(got.map(KeyPoint::to_be_bytes), want, "x {x:02x?} odd {odd}");
            }
        }
    }

    // ---------------------------------------------------------------------
    // ECDSA verification's sum.

    use k256::elliptic_curve::group::CurveAffine;

    use crate::secp256k1::ecdsa::{Signature, VerifyStep, sign};
    use crate::secp256k1::{PRIME_MINUS_ORDER_BYTES, PrivateKey};

    /// The step verification decides at, through the vartime crate and
    /// through the forced k256 arm; both must agree.
    fn step_both(sig: &Signature, hash: &[u8; 32], key: &PublicKey) -> VerifyStep {
        let vt = sig.verify_detailed(hash, key);
        let k = force_fallback(|| sig.verify_detailed(hash, key));
        assert_eq!(vt, k, "the two arms disagree");
        vt
    }

    /// A k256 scalar as big-endian bytes.
    fn be(x: &Scalar) -> [u8; 32] {
        x.to_repr().into()
    }

    /// A random nonzero k256 scalar.
    fn rand_scalar(rng: &mut SplitMix64) -> Scalar {
        loop {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let s = <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
            if !bool::from(s.is_zero()) {
                return s;
            }
        }
    }

    /// The signature, hash and key that make verification compute exactly
    /// (u1, u2) and reach X = u1*G + u2*Q with the given r: Q = (X -
    /// u1*G) / u2, s = r / u2, e = u1 * s (below N, so the hash's
    /// reduction keeps it).  `None` when Q would be infinity.
    fn sig_for(
        x: &ProjectivePoint,
        r: &Scalar,
        u1: &Scalar,
        u2: &Scalar,
    ) -> Option<(Signature, [u8; 32], PublicKey)> {
        let u2i = Option::<Scalar>::from(u2.invert_vartime())?;
        let q = ((*x - ProjectivePoint::GENERATOR * u1) * u2i).to_affine();
        if bool::from(q.is_identity()) {
            return None;
        }
        let s = *r * u2i;
        let e = *u1 * s;
        Some((Signature::new(be(r), be(&s))?, be(&e), key_of(&q)))
    }

    /// The point with x and the given oddness, by k256.
    fn point_at(x: &[u8; 32], odd: bool) -> Option<ProjectivePoint> {
        reference_decompress(x, odd).map(ProjectivePoint::from)
    }

    /// The first x at or above `from` that has a point, as bytes and the
    /// point; `from` advances by one each try.
    fn first_point_from(mut from: [u8; 32]) -> ([u8; 32], ProjectivePoint) {
        loop {
            if let Some(p) = point_at(&from, from[31] & 1 == 1) {
                return (from, p);
            }
            let mut i = 31;
            loop {
                from[i] = from[i].wrapping_add(1);
                if from[i] != 0 || i == 0 {
                    break;
                }
                i -= 1;
            }
        }
    }

    /// Signatures signed by k256 (dcrec's `sign`), their high-S twins, a
    /// hash at or above N and a hash equal to N (e = 0), and tampered
    /// hashes, r, s and keys: the vartime crate's sum and k256's give the
    /// same step.
    #[test]
    fn ecdsa_sum_matches_k256_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0003);
        let mut steps = [0u32; 6];
        for i in 0..96 {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            let Some(key) = PrivateKey::from_bytes(&d) else {
                continue;
            };
            let pk = key.public_key();
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            match i % 8 {
                1 => hash = GROUP_ORDER_BYTES,
                2 => hash[..4].fill(0xff),
                _ => {}
            }
            let sig = sign(&key, &hash);
            let high = Signature::new(
                *sig.r_bytes(),
                crate::secp256k1::negate_mod_n(sig.s_bytes()),
            )
            .expect("below N");
            let other = PrivateKey::from_bytes(&[7; 32])
                .expect("a key")
                .public_key();
            let mut bad_hash = hash;
            bad_hash[31] ^= 1;
            let mut r1 = *sig.r_bytes();
            r1[31] ^= 1;
            let mut s1 = *sig.s_bytes();
            s1[31] ^= 1;
            assert!(step_both(&sig, &hash, &pk).accepts());
            assert!(step_both(&high, &hash, &pk).accepts());
            for (sg, h, k) in [
                (sig, bad_hash, pk),
                (sig, hash, other),
                (
                    Signature::new(r1, *sig.s_bytes()).expect("below N"),
                    hash,
                    pk,
                ),
                (
                    Signature::new(*sig.r_bytes(), s1).expect("below N"),
                    hash,
                    pk,
                ),
            ] {
                let st = step_both(&sg, &h, &k);
                assert!(!st.accepts());
                steps[st as usize] += 1;
            }
        }
        // A signer's r is almost never below P - N, so tampering rejects
        // at step 9.
        assert!(steps[VerifyStep::Step9Reject as usize] > 0);
    }

    /// Every step verification can decide at, constructed, through both
    /// arms: step 6 (Q = -(u1/u2)G, so X is infinity); step 8 with X.x
    /// random below N and with X.x in [P - N, N); step 9 (r at or above P - N,
    /// X.x not r); step 10 accepting (X.x in [N, N + 2^32), r = X.x - N);
    /// step 10 rejecting (r below P - N, X.x neither r nor r + N).
    #[test]
    fn each_verify_step_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0004);
        let g = ProjectivePoint::GENERATOR;
        let sc = |b: &[u8; 32]| Option::<Scalar>::from(Scalar::from_repr((*b).into()));
        let mut seen = [0u32; 6];
        for _ in 0..16 {
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));

            // Step 6: Q = -(u1/u2)G, any r.
            let u2i = u2.invert_vartime().expect("nonzero");
            let q = (g * -(u1 * u2i)).to_affine();
            let r = rand_scalar(&mut rng);
            let s = r * u2i;
            let sig = Signature::new(be(&r), be(&s)).expect("below N");
            let st = step_both(&sig, &be(&(u1 * s)), &key_of(&q));
            assert_eq!(st, VerifyStep::Step6Infinity);
            seen[st as usize] += 1;

            // Step 8, X.x below N (r = X.x).
            let x = g * rand_scalar(&mut rng);
            let xb: [u8; 32] = x.to_affine().x().into();
            if let Some(r) = sc(&xb)
                && let Some((sig, h, k)) = sig_for(&x, &r, &u1, &u2)
            {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
                seen[VerifyStep::Step8Accept as usize] += 1;
            }

            // Step 9: r at or above P - N, X.x random.
            // P - N's byte 30 is 0xba, so this adds up to 0x40 there
            // without a carry.
            let mut rb = PRIME_MINUS_ORDER_BYTES;
            rb[30] += (rng.next_u64() % 0x41) as u8;
            let r = sc(&rb).expect("below N");
            if let Some((sig, h, k)) = sig_for(&(g * rand_scalar(&mut rng)), &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);
                seen[VerifyStep::Step9Reject as usize] += 1;
            }

            // Step 10 rejecting: r below P - N, X.x random.
            let mut rb = [0u8; 32];
            rng.fill(&mut rb[20..]);
            let r = sc(&rb).expect("below N");
            if let Some((sig, h, k)) = sig_for(&(g * rand_scalar(&mut rng)), &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step10Reject);
                seen[VerifyStep::Step10Reject as usize] += 1;
            }
        }

        // Step 8 with X.x in [P - N, N): the first such x with a point.
        let (xb, x) = first_point_from(PRIME_MINUS_ORDER_BYTES);
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let (sig, h, k) = sig_for(&x, &sc(&xb).expect("below N"), &u1, &u2).expect("Q");
        assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
        let mut r1 = xb;
        r1[31] = r1[31].wrapping_add(1);
        let (sig, h, k) = sig_for(&x, &sc(&r1).expect("below N"), &u1, &u2).expect("Q");
        assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);

        // Step 10 accepting: X.x in [N, N + 2^32), r = X.x - N.
        for start in [1u8, 77, 200] {
            let mut from = GROUP_ORDER_BYTES;
            from[31] = from[31].wrapping_add(start);
            from[30] = from[30].wrapping_add(u8::from(from[31] < start));
            let (xb, x) = first_point_from(from);
            let mut rb = [0u8; 32];
            let (mut borrow, mut i) = (0i16, 31usize);
            loop {
                let d = i16::from(xb[i]) - i16::from(GROUP_ORDER_BYTES[i]) - borrow;
                rb[i] = d.rem_euclid(256) as u8;
                borrow = i16::from(d < 0);
                if i == 0 {
                    break;
                }
                i -= 1;
            }
            assert_eq!(rb[..28], [0u8; 28], "X.x - N is not tiny");
            let r = sc(&rb).expect("below N");
            let (sig, h, k) = sig_for(&x, &r, &u1, &u2).expect("Q");
            assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step10Accept);
            seen[VerifyStep::Step10Accept as usize] += 1;
        }
        for st in [
            VerifyStep::Step6Infinity,
            VerifyStep::Step8Accept,
            VerifyStep::Step9Reject,
            VerifyStep::Step10Accept,
            VerifyStep::Step10Reject,
        ] {
            assert!(seen[st as usize] > 0, "{st:?} never reached");
        }
    }

    /// A sum the vartime crate declines is k256's instead: builds with
    /// debug assertions stop on the decline; without them the step is
    /// k256's.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate declined ECDSA verification's sum")
    )]
    fn a_declined_sum_falls_back() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        let declined = force_decline(|| sig.verify_detailed(&hash, &pk));
        assert_eq!(declined, force_fallback(|| sig.verify_detailed(&hash, &pk)));
        assert!(declined.accepts());
    }

    /// The debug cross-check stops a vartime sum that differs from k256's:
    /// here the vartime crate is given u2 + 1.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ECDSA verification's sum: x differs from k256's")]
    fn the_cross_check_catches_a_skewed_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        let _ = skew_sum(|| sig.verify_detailed(&hash, &pk));
    }

    /// r or s at N, which no caller passes, reaches neither a panic in
    /// release nor a verdict: debug builds stop on the decline, and
    /// without debug assertions the sum is the identity on both arms.
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "declined"))]
    fn out_of_range_inputs_reject_without_panicking() {
        let pk = PrivateKey::from_bytes(&[3; 32])
            .expect("a key")
            .public_key();
        let mut one = [0u8; 32];
        one[31] = 1;
        for (r, s) in [(GROUP_ORDER_BYTES, one), (one, GROUP_ORDER_BYTES)] {
            assert!(ecdsa_mul_g_add(&[1; 32], &r, &s, &pk).is_infinity());
            assert!(force_fallback(|| ecdsa_mul_g_add(&[1; 32], &r, &s, &pk)).is_infinity());
        }
    }

    /// r exactly P - N, the bound of dcrd's step 9: rejected at step 9
    /// when X.x is not r, before r + N = P is formed, and accepted at
    /// step 8 when X.x is P - N (that x has a point).
    #[test]
    fn step_9_at_exactly_p_minus_n() {
        let mut rng = SplitMix64(0xbac4_e2d0_0005);
        let g = ProjectivePoint::GENERATOR;
        let r = Option::<Scalar>::from(Scalar::from_repr(PRIME_MINUS_ORDER_BYTES.into()))
            .expect("below N");
        for _ in 0..8 {
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let x = g * rand_scalar(&mut rng);
            if let Some((sig, h, k)) = sig_for(&x, &r, &u1, &u2) {
                assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step9Reject);
            }
        }
        for odd in [false, true] {
            let x = point_at(&PRIME_MINUS_ORDER_BYTES, odd).expect("P - N is an x");
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let (sig, h, k) = sig_for(&x, &r, &u1, &u2).expect("Q");
            assert_eq!(step_both(&sig, &h, &k), VerifyStep::Step8Accept);
        }
    }

    /// The forced fallback really skips the vartime crate's sum on ECDSA
    /// verification: with u2 skewed for the vartime crate only, the forced
    /// path still accepts and the debug cross-check never runs.
    #[cfg(debug_assertions)]
    #[test]
    fn the_forced_fallback_skips_the_vartime_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign(&key, &hash);
        let pk = key.public_key();
        assert!(force_fallback(|| skew_sum(|| sig.verify_detailed(&hash, &pk))).accepts());
    }

    // ---------------------------------------------------------------------
    // Compact recovery.

    use crate::secp256k1::add_group_order;
    use crate::secp256k1::ecdsa::{Error as RecoverError, recover_compact, sign_compact};

    /// Recovery by k256's constant-time operations, independent of both
    /// arms: decompression, `invert`, two multiplications and an addition,
    /// `to_affine`.
    fn reference_recover(
        hash: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &[u8; 32],
        odd: bool,
    ) -> Recovery {
        let Some(big_r) = reference_decompress(x, odd) else {
            return Recovery::NoPoint;
        };
        let r = Option::<Scalar>::from(Scalar::from_repr((*r).into())).expect("r below N");
        let s = Option::<Scalar>::from(Scalar::from_repr((*s).into())).expect("s below N");
        let w = Option::<Scalar>::from(r.invert()).expect("r nonzero");
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&(*hash).into());
        let q = ProjectivePoint::GENERATOR * -(e * w) + ProjectivePoint::from(big_r) * (s * w);
        let a = q.to_affine();
        if bool::from(a.is_identity()) {
            Recovery::Infinity
        } else {
            Recovery::Key(key_of(&a))
        }
    }

    /// R.x for r and a recovery code: r, or r + N with the overflow bit.
    fn recovery_x(r: &[u8; 32], code: u8) -> [u8; 32] {
        if code & 2 != 0 {
            add_group_order(r)
        } else {
            *r
        }
    }

    /// `recover_key` through the vartime crate and through the forced
    /// k256 arm, which must agree with each other and, key bytes and all,
    /// with the constant-time reference.
    fn recover_both(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], code: u8) -> Recovery {
        let (x, odd) = (recovery_x(r, code), code & 1 != 0);
        let vt = recover_key(hash, r, s, &x, odd);
        let k = force_fallback(|| recover_key(hash, r, s, &x, odd));
        let want = reference_recover(hash, r, s, &x, odd);
        assert_eq!(vt, k, "the two arms disagree");
        assert_eq!(vt, want, "the seam and the reference disagree");
        if let (Recovery::Key(a), Recovery::Key(b)) = (&vt, &want) {
            assert_eq!(a.serialize_uncompressed(), b.serialize_uncompressed());
        }
        vt
    }

    /// The public `recover_compact` through both arms; they must agree.
    fn compact_both(sig: &[u8], hash: &[u8; 32]) -> Result<(PublicKey, bool), RecoverError> {
        let vt = recover_compact(sig, hash);
        let k = force_fallback(|| recover_compact(sig, hash));
        assert_eq!(vt, k, "the two arms disagree");
        vt
    }

    /// A compact signature's parts: the hash, r, s and the recovery code.
    type Parts = ([u8; 32], [u8; 32], [u8; 32], u8);

    /// The compact signature that makes recovery compute exactly (u1, u2)
    /// with R as given: r = R.x (less N, with the overflow bit, when R.x
    /// is at or above N), s = u2*r and e = -u1*r (below N, so the hash's
    /// reduction keeps it), so that Q = u1*G + u2*R.  Returns the hash, r,
    /// s and the recovery code, or `None` when r would be zero.
    fn recovering(big_r: &ProjectivePoint, u1: &Scalar, u2: &Scalar) -> Option<Parts> {
        let a = big_r.to_affine();
        let x: [u8; 32] = a.x().into();
        let mut code = u8::from(bool::from(a.y_is_odd()));
        let rb = if x >= GROUP_ORDER_BYTES {
            code |= 2;
            let mut rb = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let d = i16::from(x[i]) - i16::from(GROUP_ORDER_BYTES[i]) - borrow;
                rb[i] = d.rem_euclid(256) as u8;
                borrow = i16::from(d < 0);
            }
            rb
        } else {
            x
        };
        let r = Option::<Scalar>::from(Scalar::from_repr(rb.into()))?;
        if bool::from(r.is_zero()) {
            return None;
        }
        Some((be(&-(*u1 * r)), rb, be(&(*u2 * r)), code))
    }

    /// Compact signatures signed by k256 (`sign_compact`) for random keys
    /// and both compressed flags, with hashes at and above N (e = 0 for a
    /// hash of N, so u1 = 0 and the G half is empty), recover the signer's
    /// key on both arms; tampered hashes and s recover other keys, the
    /// same on both arms.  r and s at the edges (1, 2, N-1, N-2, every
    /// 2^k) with every recovery code that applies, and hashes 0 and N:
    /// both arms and the reference give the same outcome and key bytes.
    #[test]
    fn recovery_matches_k256_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0006);
        for i in 0..48 {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            let Some(key) = PrivateKey::from_bytes(&d) else {
                continue;
            };
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            match i % 8 {
                1 => hash = GROUP_ORDER_BYTES,
                2 => hash = [0xff; 32],
                3 => hash = [0; 32],
                _ => {}
            }
            let compressed = i % 2 == 0;
            let sig = sign_compact(&key, &hash, compressed);
            assert_eq!(
                compact_both(&sig, &hash),
                Ok((key.public_key(), compressed))
            );
            let mut bad_hash = hash;
            bad_hash[31] ^= 1;
            let mut bad_s = sig;
            bad_s[64] ^= 1;
            for (sg, h) in [(sig, bad_hash), (bad_s, hash)] {
                let got = compact_both(&sg, &h).map(|(k, _)| k);
                assert_ne!(got, Ok(key.public_key()));
            }
            let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
            let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
            assert!(matches!(
                recover_both(&hash, &r, &s, (sig[0] - 27) & 3),
                Recovery::Key(_)
            ));
        }

        let edges: Vec<[u8; 32]> = inputs().into_iter().take(4 + 256).collect();
        let (mut keys, mut no_point) = (0u32, 0u32);
        for (j, r) in edges.iter().enumerate() {
            let s = edges[(j * 7 + 3) % edges.len()];
            let hash = match j % 3 {
                0 => [0; 32],
                1 => GROUP_ORDER_BYTES,
                _ => edges[(j * 13 + 5) % edges.len()],
            };
            for code in 0..4u8 {
                if code & 2 != 0 && *r >= PRIME_MINUS_ORDER_BYTES {
                    continue;
                }
                match recover_both(&hash, r, &s, code) {
                    Recovery::Key(_) => keys += 1,
                    Recovery::NoPoint => no_point += 1,
                    Recovery::Infinity => {}
                }
            }
        }
        assert!(
            keys > 200 && no_point > 200,
            "{keys} keys, {no_point} with no point"
        );
    }

    /// Every outcome recovery can reach, constructed, on both arms: no
    /// point for R.x (steps 4 and 5); Q at infinity (R = cG, u1 = -u2*c,
    /// step 10); and a key for each recovery code, the overflow codes from
    /// R.x in [N, P), the key's bytes equal to u1*G + u2*R by k256.
    #[test]
    fn each_recovery_step_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0007);
        let g = ProjectivePoint::GENERATOR;

        // Steps 4 and 5: the first r with no point, either oddness.
        let r = (1u8..)
            .map(|v| {
                let mut b = [0u8; 32];
                b[31] = v;
                b
            })
            .find(|b| point_at(b, false).is_none())
            .expect("an x with no point");
        for code in [0u8, 1] {
            assert_eq!(recover_both(&[7; 32], &r, &r, code), Recovery::NoPoint);
        }

        let mut codes = [0u32; 4];
        for _ in 0..16 {
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));

            // Step 10: R = cG and u1 = -u2*c.
            let c = rand_scalar(&mut rng);
            if let Some((h, r, s, code)) = recovering(&(g * c), &-(u2 * c), &u2) {
                assert_eq!(recover_both(&h, &r, &s, code), Recovery::Infinity);
            }

            // A key, R random.
            let big_r = g * rand_scalar(&mut rng);
            if let Some((h, r, s, code)) = recovering(&big_r, &u1, &u2) {
                let want = (g * u1 + big_r * u2).to_affine();
                let Recovery::Key(k) = recover_both(&h, &r, &s, code) else {
                    panic!("no key");
                };
                assert_eq!(k, key_of(&want));
                codes[usize::from(code)] += 1;
            }
        }

        // The overflow codes: R.x in [N, P), both oddnesses.
        for (start, odd) in [(1u8, false), (1, true), (90, false), (90, true)] {
            let mut from = GROUP_ORDER_BYTES;
            from[31] = from[31].wrapping_add(start);
            from[30] = from[30].wrapping_add(u8::from(from[31] < start));
            let (mut xb, _) = first_point_from(from);
            let big_r = loop {
                if let Some(p) = point_at(&xb, odd) {
                    break p;
                }
                xb[31] = xb[31].wrapping_add(1);
            };
            let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let (h, r, s, code) = recovering(&big_r, &u1, &u2).expect("r nonzero");
            assert_eq!(code, 2 | u8::from(odd));
            let want = (g * u1 + big_r * u2).to_affine();
            assert_eq!(recover_both(&h, &r, &s, code), Recovery::Key(key_of(&want)));
            codes[usize::from(code)] += 1;
        }
        assert!(codes.iter().all(|&c| c > 0), "codes reached {codes:?}");
    }

    /// The vartime crate alone, with no seam: decompression, the inverse,
    /// the scalar products, the multiply and `to_affine_var`, as bytes.
    fn crate_alone_recover(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], code: u8) -> [u8; 65] {
        let big_r =
            vartime::Affine::decompress_var(&recovery_x(r, code), code & 1 != 0).expect("a point");
        let r = vartime::Scalar::from_be_bytes(r).expect("below N");
        let s = vartime::Scalar::from_be_bytes(s).expect("below N");
        let w = r.try_inverse_var().expect("the inverse");
        let e = vartime::Scalar::reduce_be_bytes(hash);
        let q = vartime::ecmult_var(&big_r, &(s * w), &-(e * w)).expect("the guard");
        let (x, y) = q
            .to_affine_var()
            .expect("the cap")
            .expect("finite")
            .to_be_bytes();
        let mut out = [4u8; 65];
        out[1..33].copy_from_slice(&x);
        out[33..].copy_from_slice(&y);
        out
    }

    /// The forced path really is k256's: the switches are per thread and
    /// clear themselves, and the vartime crate alone gives the seam's key.
    #[test]
    fn the_switch_forces_and_clears() {
        assert!(!forced_fallback());
        assert!(force_fallback(forced_fallback));
        assert!(!forced_fallback());
        assert!(force_decline(forced_decline));
        assert!(!forced_decline());
        assert!(!skewed_sum());
        assert!(!wrong_oddness());
        assert!(!FORCE_CAP.with(core::cell::Cell::get));
        assert!(!conversion_refused());
        assert!(refuse_conversion(conversion_refused));
        assert!(!conversion_refused());
        let key = PrivateKey::from_bytes(&[9; 32]).expect("a key");
        let hash = [0x3c; 32];
        let sig = sign_compact(&key, &hash, false);
        let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
        let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
        let code = (sig[0] - 27) & 3;
        let Recovery::Key(k) = recover_both(&hash, &r, &s, code) else {
            panic!("no key");
        };
        assert_eq!(
            crate_alone_recover(&hash, &r, &s, code),
            k.serialize_uncompressed()
        );
        assert_eq!(k, key.public_key());
    }

    /// A recovery the vartime crate declines is k256's instead: builds
    /// with debug assertions stop on the decline; without them the key is
    /// k256's.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate declined compact recovery")
    )]
    fn a_declined_recovery_falls_back() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = sign_compact(&key, &hash, true);
        let declined = force_decline(|| recover_compact(&sig, &hash));
        assert_eq!(declined, force_fallback(|| recover_compact(&sig, &hash)));
        assert_eq!(declined, Ok((key.public_key(), true)));
    }

    /// The debug cross-check stops a recovered key that differs from
    /// k256's: here the vartime crate is given u2 + 1.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "compact recovery: the key differs from k256's")]
    fn the_cross_check_catches_a_skewed_recovery() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign_compact(&key, &hash, true);
        let _ = skew_sum(|| recover_compact(&sig, &hash));
    }

    /// The debug cross-check compares the whole recovered key, not just
    /// its x: here the vartime crate computes -Q, which shares the
    /// signer's x and has the other y.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "compact recovery: the key differs from k256's")]
    fn the_cross_check_catches_a_negated_recovery() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign_compact(&key, &hash, true);
        let _ = negate_recovery(|| recover_compact(&sig, &hash));
    }

    /// The forced fallback really skips the vartime crate's recovery: with
    /// u2 skewed for the vartime crate only, the forced path still
    /// recovers the signer's key and the debug cross-check never runs.
    #[cfg(debug_assertions)]
    #[test]
    fn the_forced_fallback_skips_the_vartime_recovery() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = sign_compact(&key, &hash, false);
        assert_eq!(
            force_fallback(|| skew_sum(|| recover_compact(&sig, &hash))),
            Ok((key.public_key(), false))
        );
    }

    /// Recovery's R of the other oddness from the vartime crate, as a port
    /// bug might give, is not passed on: builds with debug assertions stop
    /// on the decline; without them the key is k256's.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate declined compact recovery")
    )]
    fn a_recovered_point_of_the_wrong_oddness_is_not_passed_on() {
        let mut rng = SplitMix64(0xbac4_e2d0_0008);
        for _ in 0..16 {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            let Some(key) = PrivateKey::from_bytes(&d) else {
                continue;
            };
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            let sig = sign_compact(&key, &hash, true);
            let got = force_wrong_oddness(|| recover_compact(&sig, &hash));
            assert_eq!(got, Ok((key.public_key(), true)));
        }
        assert!(!wrong_oddness());
    }

    /// r or s at N, which no caller passes, into recovery, and s or e at N
    /// into Schnorr verification's sum, reach neither a panic in release
    /// nor an accepting answer: debug builds stop on the decline, and
    /// without debug assertions both arms reject (Q or R at infinity).
    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "declined"))]
    fn out_of_range_recovery_and_schnorr_inputs_reject_without_panicking() {
        let pk = PrivateKey::from_bytes(&[3; 32])
            .expect("a key")
            .public_key();
        let mut one = [0u8; 32];
        one[31] = 1;
        let x = first_point_from(one).0;
        for (r, s) in [(GROUP_ORDER_BYTES, one), (one, GROUP_ORDER_BYTES)] {
            let odd = false;
            assert_eq!(recover_key(&[1; 32], &r, &s, &x, odd), Recovery::Infinity);
            assert_eq!(
                force_fallback(|| recover_key(&[1; 32], &r, &s, &x, odd)),
                Recovery::Infinity
            );
        }
        for (s, e) in [(GROUP_ORDER_BYTES, one), (one, GROUP_ORDER_BYTES)] {
            assert_eq!(schnorr_mul_g_add(&s, &e, &pk), None);
            assert_eq!(force_fallback(|| schnorr_mul_g_add(&s, &e, &pk)), None);
        }
    }

    // ---------------------------------------------------------------------
    // EC-Schnorr-DCRv0 verification's sum.

    use crate::secp256k1::schnorr::{self, Error as SchnorrError};

    /// Schnorr verification through the vartime crate and through the
    /// forced k256 arm; both must agree.
    fn schnorr_both(
        sig: &schnorr::Signature,
        hash: &[u8; 32],
        key: &PublicKey,
    ) -> Result<(), SchnorrError> {
        let vt = sig.verify_detailed(hash, key);
        let k = force_fallback(|| sig.verify_detailed(hash, key));
        assert_eq!(vt, k, "the two arms disagree");
        vt
    }

    /// BLAKE-256(r || hash) as a scalar, `None` at or above N or at zero.
    fn challenge_of(r: &[u8; 32], hash: &[u8; 32]) -> Option<Scalar> {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(r);
        input[32..].copy_from_slice(hash);
        let e = Option::<Scalar>::from(Scalar::from_repr(
            dcroxide_crypto::blake256::sum256(&input).into(),
        ))?;
        (!bool::from(e.is_zero())).then_some(e)
    }

    /// A nonce whose kG has the y parity asked for, kG's x, and a hash
    /// whose challenge for that x is below N (and not zero).
    fn nonce_and_hash(rng: &mut SplitMix64, odd: bool) -> (Scalar, [u8; 32], [u8; 32], Scalar) {
        let mut k = rand_scalar(rng);
        let a = (ProjectivePoint::GENERATOR * k).to_affine();
        if bool::from(a.y_is_odd()) != odd {
            k = -k;
        }
        let r: [u8; 32] = (ProjectivePoint::GENERATOR * k).to_affine().x().into();
        loop {
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            if let Some(e) = challenge_of(&r, &hash) {
                return (k, r, hash, e);
            }
        }
    }

    /// Signatures signed by k256 (`schnorr::sign`) verify on both arms;
    /// tampered hashes, s and keys, and s = 0 with random keys, reject
    /// with the same error on both arms.
    #[test]
    fn schnorr_sum_matches_k256_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_0009);
        let mut errors = 0u32;
        for _ in 0..48 {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            let Some(key) = PrivateKey::from_bytes(&d) else {
                continue;
            };
            let pk = key.public_key();
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            let sig = schnorr::sign(&key, &hash).expect("a signature");
            assert_eq!(schnorr_both(&sig, &hash, &pk), Ok(()));
            let mut bad_hash = hash;
            bad_hash[0] ^= 0x80;
            let mut s1 = *sig.s_bytes();
            s1[31] ^= 1;
            let other = PrivateKey::from_bytes(&[7; 32])
                .expect("a key")
                .public_key();
            let zero_s = schnorr::Signature::new(*sig.r_bytes(), [0; 32]).expect("in range");
            for (sg, h, k) in [
                (sig, bad_hash, pk),
                (
                    schnorr::Signature::new(*sig.r_bytes(), s1).expect("in range"),
                    hash,
                    pk,
                ),
                (sig, hash, other),
                (zero_s, hash, pk),
            ] {
                if schnorr_both(&sg, &h, &k).is_err() {
                    errors += 1;
                }
            }
        }
        assert!(errors > 150, "{errors} rejections");
    }

    /// Every step Schnorr verification decides at, constructed, on both
    /// arms: step 8 (s = -e*d, so R is infinity), step 9 (kG of odd y),
    /// step 10 (R.x is not r) and acceptance, all for a key d; and a
    /// valid s = 0 for a key built for it, Q = (k/e)G, and its odd twin.
    #[test]
    fn each_schnorr_step_on_both_paths() {
        let mut rng = SplitMix64(0xbac4_e2d0_000a);
        let g = ProjectivePoint::GENERATOR;
        for _ in 0..16 {
            let d = rand_scalar(&mut rng);
            let pk = key_of(&(g * d).to_affine());
            let sig =
                |r: [u8; 32], s: Scalar| schnorr::Signature::new(r, be(&s)).expect("in range");

            // Accepting, and step 10 with another r for the same R.
            let (k, r, hash, e) = nonce_and_hash(&mut rng, false);
            assert_eq!(schnorr_both(&sig(r, k - e * d), &hash, &pk), Ok(()));
            let mut r2 = r;
            r2[0] ^= 0x01;
            if r2 < FIELD_PRIME_BYTES
                && let Some(e2) = challenge_of(&r2, &hash)
            {
                assert_eq!(
                    schnorr_both(&sig(r2, k - e2 * d), &hash, &pk),
                    Err(SchnorrError::UnequalRValues)
                );
            }

            // Step 8: s = -e*d.
            assert_eq!(
                schnorr_both(&sig(r, -(e * d)), &hash, &pk),
                Err(SchnorrError::SigRNotOnCurve)
            );

            // Step 9: kG of odd y.
            let (k, r, hash, e) = nonce_and_hash(&mut rng, true);
            assert_eq!(
                schnorr_both(&sig(r, k - e * d), &hash, &pk),
                Err(SchnorrError::SigRYIsOdd)
            );

            // A valid s = 0: Q = (k/e)G, so e*Q = kG.
            for odd in [false, true] {
                let (k, r, hash, e) = nonce_and_hash(&mut rng, odd);
                let q = g * (k * e.invert_vartime().expect("nonzero"));
                let qk = key_of(&q.to_affine());
                let want = if odd {
                    Err(SchnorrError::SigRYIsOdd)
                } else {
                    Ok(())
                };
                assert_eq!(schnorr_both(&sig(r, Scalar::ZERO), &hash, &qk), want);
            }
        }
    }

    /// A Schnorr sum the vartime crate declines is k256's instead: builds
    /// with debug assertions stop on the decline; without them the verdict
    /// is k256's.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate declined Schnorr verification's sum")
    )]
    fn a_declined_schnorr_sum_falls_back() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = schnorr::sign(&key, &hash).expect("a signature");
        let pk = key.public_key();
        let declined = force_decline(|| sig.verify_detailed(&hash, &pk));
        assert_eq!(declined, force_fallback(|| sig.verify_detailed(&hash, &pk)));
        assert_eq!(declined, Ok(()));
    }

    /// The debug cross-check stops a Schnorr R that differs from k256's:
    /// here the vartime crate is given e + 1.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Schnorr verification's R differs from k256's")]
    fn the_cross_check_catches_a_skewed_schnorr_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = schnorr::sign(&key, &hash).expect("a signature");
        let _ = skew_sum(|| sig.verify_detailed(&hash, &key.public_key()));
    }

    /// The forced fallback really skips the vartime crate's Schnorr sum:
    /// with e skewed for the vartime crate only, the forced path still
    /// accepts and the debug cross-check never runs.
    #[cfg(debug_assertions)]
    #[test]
    fn the_forced_fallback_skips_the_vartime_schnorr_sum() {
        let key = PrivateKey::from_bytes(&[5; 32]).expect("a key");
        let hash = [11u8; 32];
        let sig = schnorr::sign(&key, &hash).expect("a signature");
        assert_eq!(
            force_fallback(|| skew_sum(|| sig.verify_detailed(&hash, &key.public_key()))),
            Ok(())
        );
    }

    // ---------------------------------------------------------------------
    // Both affine conversions.

    /// A capped affine conversion is a decline, never an answer: recovery
    /// and Schnorr's sum return `None`, which sends the seam to k256, and
    /// never `Infinity` or `Some(None)`, which would reject a valid
    /// signature.  At infinity no inversion is attempted, so the answer
    /// stands.
    #[test]
    fn a_capped_affine_conversion_is_a_decline() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = sign_compact(&key, &hash, true);
        let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
        let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
        let code = (sig[0] - 27) & 3;
        let (x, odd) = (recovery_x(&r, code), code & 1 != 0);
        assert!(matches!(
            vartime_recover(&hash, &r, &s, &x, odd),
            Some(Recovery::Key(_))
        ));
        assert_eq!(force_cap(|| vartime_recover(&hash, &r, &s, &x, odd)), None);

        let ssig = schnorr::sign(&key, &hash).expect("a signature");
        let pk = key.public_key();
        let e = challenge_of(ssig.r_bytes(), &hash).expect("a challenge");
        assert!(matches!(
            vartime_schnorr(ssig.s_bytes(), &be(&e), &pk),
            Some(Some(_))
        ));
        assert_eq!(
            force_cap(|| vartime_schnorr(ssig.s_bytes(), &be(&e), &pk)),
            None
        );

        // Q and R at infinity: the cap is never consulted.
        let mut rng = SplitMix64(0xbac4_e2d0_000b);
        let g = ProjectivePoint::GENERATOR;
        let (c, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let (h, r, s, code) = recovering(&(g * c), &-(u2 * c), &u2).expect("r nonzero");
        let (x, odd) = (recovery_x(&r, code), code & 1 != 0);
        assert_eq!(
            force_cap(|| vartime_recover(&h, &r, &s, &x, odd)),
            Some(Recovery::Infinity)
        );
        let d = rand_scalar(&mut rng);
        let pk = key_of(&(g * d).to_affine());
        let e = rand_scalar(&mut rng);
        assert_eq!(
            force_cap(|| vartime_schnorr(&be(&-(e * d)), &be(&e), &pk)),
            Some(None)
        );
    }

    // ---------------------------------------------------------------------
    // The key type.

    /// The x of the points with y = 1 (odd) and y = P - 1 (even), the
    /// smallest y any point has: x^3 = 1 - 7 has a cube root.
    const Y_ONE_X: [u8; 32] = [
        0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5,
        0xa6, 0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf,
        0xf5, 0x07,
    ];

    /// Points for the key tests: seeded keys' points and their negations,
    /// and both points at x = 1 (the smallest x with a point), P-4 and P-3
    /// (the largest two), N (the recovery boundary) and the x of y = 1.
    fn key_points() -> Vec<AffinePoint> {
        let mut rng = SplitMix64(0xbac4_e2d0_000c);
        let g = ProjectivePoint::GENERATOR;
        let mut v = Vec::new();
        for _ in 0..32 {
            let p = g * rand_scalar(&mut rng);
            v.push(p.to_affine());
            v.push((-p).to_affine());
        }
        let mut one = [0u8; 32];
        one[31] = 1;
        let below_p = |d: u8| {
            let mut b = FIELD_PRIME_BYTES;
            b[31] -= d;
            b
        };
        for x in [one, below_p(4), below_p(3), GROUP_ORDER_BYTES, Y_ONE_X] {
            for odd in [false, true] {
                v.push(reference_decompress(&x, odd).expect("a point"));
            }
        }
        let y_one = bytes_of(&reference_decompress(&Y_ONE_X, true).expect("a point")).1;
        assert_eq!(y_one, one, "the x of y = 1");
        v
    }

    /// y + 1, big-endian, wrapping at 2^256 (no input here is that high).
    fn plus_one(y: &[u8; 32]) -> [u8; 32] {
        let mut out = *y;
        for b in out.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        out
    }

    /// The seam's curve check of an uncompressed key equals k256's
    /// `from_coordinates` on every point of [`key_points`] and on the
    /// near misses around it, (x, y + 1), (x, 0), (0, y) and (x, P - 1),
    /// on random coordinates below P, and on coordinates at P, which key
    /// parsing refuses before it asks; an accepted point gives back its
    /// coordinates and y's parity.
    #[test]
    fn from_coordinates_matches_k256() {
        let mut p_minus_1 = FIELD_PRIME_BYTES;
        p_minus_1[31] -= 1;
        let mut cases = Vec::new();
        for a in key_points() {
            let (x, y) = bytes_of(&a);
            cases.extend([(x, y), (x, plus_one(&y)), (x, [0; 32]), ([0; 32], y)]);
            cases.extend([
                (x, p_minus_1),
                (FIELD_PRIME_BYTES, y),
                (x, FIELD_PRIME_BYTES),
            ]);
        }
        let mut rng = SplitMix64(0xbac4_e2d0_000d);
        while cases.len() < 1024 {
            let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
            rng.fill(&mut x);
            rng.fill(&mut y);
            if x < FIELD_PRIME_BYTES && y < FIELD_PRIME_BYTES {
                cases.push((x, y));
            }
        }
        let (mut on, mut off) = (0u32, 0u32);
        for (x, y) in &cases {
            let got = from_coordinates(x, y);
            let want = Option::<AffinePoint>::from(AffinePoint::from_coordinates(
                &(*x).into(),
                &(*y).into(),
            ));
            assert_eq!(
                got.map(KeyPoint::to_be_bytes),
                want.map(|a| bytes_of(&a)),
                "x {x:02x?} y {y:02x?}"
            );
            match got {
                Some(p) => {
                    on += 1;
                    assert_eq!(p.to_be_bytes(), (*x, *y));
                    assert_eq!(p.y_is_odd(), y[31] & 1 == 1);
                }
                None => off += 1,
            }
        }
        // Every point, and (x, P - 1) for both points at the x of y = 1,
        // one of which is (x, P - 1) itself.
        assert_eq!(on, 74 + 2, "{on} accepted");
        assert!(off > 600, "{off} refused");
    }

    /// The curve check of a 65-byte key takes no fallback: should the
    /// vartime crate refuse a point on the curve, as a port bug might,
    /// builds with debug assertions stop on the disagreement with k256,
    /// and release answers with the crate's refusal, dcrd's
    /// `ErrPubKeyNotOnCurve`, in both formats that reach the check.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(
            expected = "the vartime crate and k256 disagree on whether a key is on the curve"
        )
    )]
    fn a_refused_curve_check_is_the_answer() {
        let pk = PrivateKey::from_bytes(&[3; 32])
            .expect("a key")
            .public_key();
        let uncompressed = pk.serialize_uncompressed();
        assert_eq!(PublicKey::parse(&uncompressed), Ok(pk));
        let mut hybrid = uncompressed;
        hybrid[0] = 0x06 | (uncompressed[64] & 1);
        assert_eq!(PublicKey::parse(&hybrid), Ok(pk));
        let (x, y) = pk.point.to_be_bytes();
        for key in [uncompressed, hybrid] {
            assert_eq!(
                refuse_curve_check(|| PublicKey::parse(&key)),
                Err(crate::secp256k1::Error::PubKeyNotOnCurve { x, y: Some(y) })
            );
        }
    }

    /// The two conversions are each other's inverse on curve points: k256's
    /// point of a key is the point it came from, and the key type of that
    /// point is the key; k256's identity has no key.
    #[test]
    fn key_conversions_round_trip() {
        for a in key_points() {
            let pk = key_of(&a);
            assert_eq!(pk.point.to_be_bytes(), bytes_of(&a));
            assert_eq!(pk.point.y_is_odd(), bool::from(a.y_is_odd()));
            assert_eq!(k256_key(&pk), Some(ProjectivePoint::from(a)));
            assert_eq!(key_from_k256(&a), Some(pk.point));
        }
        assert_eq!(key_from_k256(&AffinePoint::IDENTITY), None);
    }

    /// A k256 arm whose conversion of the key fails as well, two faults,
    /// rejects and never panics in release: ECDSA verification at step 6
    /// (the sum counts as infinity) and Schnorr verification at step 8.
    /// Builds with debug assertions stop on the refusal.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "k256 refused a key the vartime crate holds")
    )]
    fn a_refused_conversion_rejects_in_the_fallback() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let pk = key.public_key();
        let hash = [9u8; 32];
        let sig = sign(&key, &hash);
        let ssig = schnorr::sign(&key, &hash).expect("a signature");
        assert!(force_fallback(|| sig.verify_detailed(&hash, &pk)).accepts());
        assert_eq!(force_fallback(|| ssig.verify_detailed(&hash, &pk)), Ok(()));
        assert_eq!(
            force_fallback(|| refuse_conversion(|| sig.verify_detailed(&hash, &pk))),
            VerifyStep::Step6Infinity
        );
        assert_eq!(
            force_fallback(|| refuse_conversion(|| ssig.verify_detailed(&hash, &pk))),
            Err(SchnorrError::SigRNotOnCurve)
        );
    }

    /// k256's recovered key that the key type refuses, two faults, is
    /// `Infinity`, so recovery rejects with dcrd's `ErrPointNotOnCurve`
    /// and never panics in release.  Builds with debug assertions stop on
    /// the refusal.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate refused a key k256 computed")
    )]
    fn a_refused_conversion_rejects_recovery() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let hash = [9u8; 32];
        let sig = sign_compact(&key, &hash, true);
        let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
        let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
        let code = (sig[0] - 27) & 3;
        let (x, odd) = (recovery_x(&r, code), code & 1 != 0);
        assert!(matches!(
            force_fallback(|| recover_key(&hash, &r, &s, &x, odd)),
            Recovery::Key(_)
        ));
        assert_eq!(
            force_fallback(|| refuse_conversion(|| recover_key(&hash, &r, &s, &x, odd))),
            Recovery::Infinity
        );
        assert_eq!(
            force_fallback(|| refuse_conversion(|| recover_compact(&sig, &hash))),
            Err(RecoverError::PointNotOnCurve)
        );
    }

    /// k256's decompressed point that the key type refuses, two faults,
    /// is no key, on the forced path and behind a point of the wrong
    /// oddness, and never a panic in release.  Builds with debug
    /// assertions stop on the refusal.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the vartime crate refused a key k256 computed")
    )]
    fn a_refused_conversion_rejects_decompression() {
        let mut points = 0u32;
        for x in decompress_inputs().iter().take(64) {
            for odd in [false, true] {
                points += u32::from(reference_decompress(x, odd).is_some());
                assert_eq!(
                    force_fallback(|| refuse_conversion(|| decompress(x, odd))),
                    None
                );
                assert_eq!(
                    force_wrong_oddness(|| refuse_conversion(|| decompress(x, odd))),
                    None
                );
            }
        }
        assert!(points > 32, "{points} points");
    }

    /// `PrivateKey::public_key` has no answer to fall back to when the
    /// key type refuses k256's dG, so it stops, in every profile, rather
    /// than return a wrong key.
    #[test]
    #[should_panic(expected = "k256's dG passes the curve check")]
    fn public_key_stops_on_a_refused_conversion() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let _ = refuse_conversion(|| key.public_key());
    }

    /// Release's paths convert no key: with every conversion refused,
    /// ECDSA verification, compact recovery, Schnorr verification and the
    /// parsing of each key format still give the right answers, so none
    /// of them reached a conversion.  (Builds with debug assertions run
    /// the k256 arms beside them for the cross-checks, which do convert.)
    #[cfg(not(debug_assertions))]
    #[test]
    fn the_vartime_path_converts_no_key() {
        let key = PrivateKey::from_bytes(&[3; 32]).expect("a key");
        let pk = key.public_key();
        let hash = [9u8; 32];
        let sig = sign(&key, &hash);
        let csig = sign_compact(&key, &hash, true);
        let ssig = schnorr::sign(&key, &hash).expect("a signature");
        let compressed = pk.serialize_compressed();
        let uncompressed = pk.serialize_uncompressed();
        let mut hybrid = uncompressed;
        hybrid[0] = 6 | (uncompressed[64] & 1);
        refuse_conversion(|| {
            assert!(sig.verify_detailed(&hash, &pk).accepts());
            assert_eq!(recover_compact(&csig, &hash), Ok((pk, true)));
            assert_eq!(ssig.verify_detailed(&hash, &pk), Ok(()));
            for k in [&compressed[..], &uncompressed[..], &hybrid[..]] {
                assert_eq!(PublicKey::parse(k), Ok(pk));
            }
        });
    }
}
