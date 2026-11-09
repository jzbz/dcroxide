// SPDX-License-Identifier: ISC
//! The generator tables: byte-for-byte regeneration of `src/g_tables.rs`,
//! and every entry checked against k256's point arithmetic.

use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};
use k256::{ProjectivePoint, Scalar as KScalar};

use super::*;
use crate::g_tables::{PRE_G, PRE_G_128, WINDOW_G};
use crate::group::GeStorage;

/// The committed file.
const COMMITTED: &str = include_str!("../g_tables.rs");

/// The generator's text equals the committed file.  With
/// `DCROXIDE_REGEN_TABLES=<dir>` set, a mismatching text is written to
/// `<dir>/g_tables.rs`, never into the source tree, and the test still
/// fails.
#[test]
fn regenerate() {
    let text = super::table_gen::table_file(WINDOW_G);
    println!(
        "window {WINDOW_G}: generated {} bytes, {} lines; committed {} bytes",
        text.len(),
        text.lines().count(),
        COMMITTED.len()
    );
    if text != COMMITTED {
        if let Ok(dir) = std::env::var("DCROXIDE_REGEN_TABLES") {
            let p = std::path::Path::new(&dir).join("g_tables.rs");
            std::fs::write(&p, &text).expect("write the regenerated table");
            println!("wrote {}", p.display());
        }
        panic!("src/g_tables.rs differs from the generator's output");
    }
}

/// A storage entry's coordinates, big-endian.
fn storage_to_be(s: &GeStorage) -> Bytes2 {
    (words_to_be(&s.x), words_to_be(&s.y))
}

/// A k256 affine point's coordinates, big-endian.
fn kaff_be(p: &k256::AffinePoint) -> Bytes2 {
    (p.x().into(), p.y().into())
}

/// Every entry of both tables against k256: the first entry and the last,
/// (2^(w-1) - 1) times the base, by k256's scalar multiplication; every
/// entry by the walk T\[i\] = T\[i-1\] + 2B in k256's projective
/// additions, normalized in batches of 256, compared as affine bytes; no
/// entry at infinity (storage cannot hold one) and every limb below p.
#[test]
fn every_entry_matches_k256() {
    let n = 1usize << (WINDOW_G - 2);
    let two128 = ksc(&[0, 0, 1, 0]);
    for (name, tab, base) in [
        ("G", &PRE_G[..], ProjectivePoint::GENERATOR),
        (
            "2^128*G",
            &PRE_G_128[..],
            ProjectivePoint::GENERATOR * two128,
        ),
    ] {
        assert_eq!(tab.len(), n);
        let two_b = base.double();
        let mut walk = Vec::with_capacity(n);
        let mut cur = base;
        for _ in 0..n {
            walk.push(cur);
            cur += two_b;
        }
        // k256's array impl needs no alloc feature, unlike its slice impl.
        let mut aff = Vec::with_capacity(n);
        for chunk in walk.chunks(256) {
            let arr: [ProjectivePoint; 256] = chunk.try_into().expect("n is a multiple of 256");
            let out = <ProjectivePoint as BatchNormalize<[ProjectivePoint; 256]>>::batch_normalize_vartime(&arr);
            aff.extend_from_slice(&out);
        }
        for (j, (e, a)) in tab.iter().zip(&aff).enumerate() {
            assert!(!ge4(&e.x, &P), "{name} entry {j}: x limbs >= p");
            assert!(!ge4(&e.y, &P), "{name} entry {j}: y limbs >= p");
            assert_eq!(storage_to_be(e), kaff_be(a), "{name} entry {j} != k256");
        }
        assert_eq!(
            storage_to_be(&tab[0]),
            kaff_be(&base.to_affine()),
            "{name} entry 0"
        );
        let last = (base * KScalar::from((1u64 << (WINDOW_G - 1)) - 1)).to_affine();
        assert_eq!(
            storage_to_be(&tab[n - 1]),
            kaff_be(&last),
            "{name} last entry"
        );
    }
}

/// The window and the tables agree (each 2^(w-2) entries, the window
/// within the `i16` digits' range), and every digit the generator's wNAF
/// can give indexes inside them: |digit| <= 2^(w-1) - 1, so (|digit| -
/// 1)/2 < 2^(w-2).
#[test]
fn window_and_table_lengths_agree() {
    use crate::wnaf::Digit;
    assert!((2..=i16::MAX_W).contains(&WINDOW_G));
    assert_eq!(PRE_G.len(), 1 << (WINDOW_G - 2));
    assert_eq!(PRE_G_128.len(), PRE_G.len());
    let top = (1usize << (WINDOW_G - 1)) - 1;
    assert_eq!((top - 1) / 2, PRE_G.len() - 1);
}
