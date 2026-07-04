// SPDX-License-Identifier: ISC
//! uint256 fuzz target: no operation panics on arbitrary operands (other
//! than the documented division-by-zero), and core algebraic laws hold.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_uint256::{OutputBase, Uint256};

fuzz_target!(|data: &[u8]| {
    if data.len() < 73 {
        return;
    }
    let a = Uint256::from_be_bytes(&data[1..33].try_into().expect("32 bytes"));
    let b = Uint256::from_be_bytes(&data[33..65].try_into().expect("32 bytes"));
    let aux = u64::from_be_bytes(data[65..73].try_into().expect("8 bytes"));

    // Add/sub inverse.
    let mut v = a;
    v.add(&b);
    v.sub(&b);
    assert_eq!(v, a);

    // Division identity when the divisor is nonzero.
    if !b.is_zero() {
        let mut q = a;
        q.div(&b);
        let mut qb = q;
        qb.mul(&b);
        let mut r = a;
        r.sub(&qb);
        assert!(r < b, "remainder in range");
    }
    if aux != 0 {
        let mut q = a;
        q.div_u64(aux);
        let _ = q;
    }

    // Shifts, squaring, negation, text conversion never panic.
    let mut s = a;
    s.lsh(aux as u32);
    s.rsh(aux as u32);
    let mut sq = a;
    sq.square();
    let mut neg = a;
    neg.negate();
    neg.add(&a);
    assert!(neg.is_zero(), "a + (-a) == 0");
    let _ = a.text(OutputBase::Binary);
    let _ = a.text(OutputBase::Octal);
    let _ = a.text(OutputBase::Decimal);
    let _ = a.text(OutputBase::Hex);
    let _ = a.bit_len();
});
