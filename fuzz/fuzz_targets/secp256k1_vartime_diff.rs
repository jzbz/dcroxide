// SPDX-License-Identifier: ISC
//! Differential fuzz target for dcroxide-secp256k1-vartime against k256,
//! in process, with no oracle.  The first input byte chooses the level and
//! the rest is the level's input; today the crate has one level, the
//! scalar, and every byte chooses it (the field joins when the crate gains
//! it).
//!
//! Scalar level, two 32-byte big-endian values a and b: `from_be_bytes`
//! must accept exactly what k256's `from_repr` accepts (values below N)
//! and agree on the value; `reduce_be_bytes` must equal k256's reduction;
//! on the reduced values, a + b, a * b and -a must equal k256's, a's
//! bytes must parse back to a, and `try_inverse_var` must return a value
//! (its cap is never reached) equal to k256's `invert_vartime` and
//! constant-time `invert`, with the inverse of zero zero.  Any difference
//! panics with the inputs.

#![no_main]

use dcroxide_secp256k1_vartime::Scalar;
use k256::FieldBytes;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::ops::Reduce;
use libfuzzer_sys::fuzz_target;

/// k256's scalar as big-endian bytes.
fn kb(s: &k256::Scalar) -> [u8; 32] {
    s.to_repr().into()
}

fn scalar_level(a: &[u8; 32], b: &[u8; 32]) {
    // Parsing: exactly the values below N, with the same value.
    for x in [a, b] {
        let ours = Scalar::from_be_bytes(x);
        let theirs = Option::<k256::Scalar>::from(k256::Scalar::from_repr((*x).into()));
        assert_eq!(
            ours.map(|s| s.to_be_bytes()),
            theirs.map(|s| kb(&s)),
            "from_be_bytes {x:02x?}"
        );
    }
    let (ra, rb) = (Scalar::reduce_be_bytes(a), Scalar::reduce_be_bytes(b));
    let ka = <k256::Scalar as Reduce<FieldBytes>>::reduce(&(*a).into());
    let kbb = <k256::Scalar as Reduce<FieldBytes>>::reduce(&(*b).into());
    assert_eq!(ra.to_be_bytes(), kb(&ka), "reduce_be_bytes {a:02x?}");
    assert_eq!(rb.to_be_bytes(), kb(&kbb), "reduce_be_bytes {b:02x?}");
    assert_eq!(
        Scalar::from_be_bytes(&ra.to_be_bytes()),
        Some(ra),
        "round trip {a:02x?}"
    );

    assert_eq!(
        (ra + rb).to_be_bytes(),
        kb(&(ka + kbb)),
        "add {a:02x?} {b:02x?}"
    );
    assert_eq!(
        (ra * rb).to_be_bytes(),
        kb(&(ka * kbb)),
        "mul {a:02x?} {b:02x?}"
    );
    assert_eq!((-ra).to_be_bytes(), kb(&(-ka)), "neg {a:02x?}");

    for (x, kx, raw) in [(ra, ka, a), (rb, kbb, b)] {
        let inv = x
            .try_inverse_var()
            .expect("the inverse stays within its cap");
        if x.is_zero() {
            assert!(inv.is_zero(), "inverse of zero {raw:02x?}");
            continue;
        }
        let kv = Option::<k256::Scalar>::from(kx.invert_vartime()).expect("nonzero");
        let kc = Option::<k256::Scalar>::from(kx.invert()).expect("nonzero");
        assert_eq!(
            inv.to_be_bytes(),
            kb(&kv),
            "inverse vs invert_vartime {raw:02x?}"
        );
        assert_eq!(inv.to_be_bytes(), kb(&kc), "inverse vs invert {raw:02x?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((_level, rest)) = data.split_first() else {
        return;
    };
    if rest.len() < 64 {
        return;
    }
    let a: [u8; 32] = rest[..32].try_into().expect("32 bytes");
    let b: [u8; 32] = rest[32..64].try_into().expect("32 bytes");
    scalar_level(&a, &b);
});
