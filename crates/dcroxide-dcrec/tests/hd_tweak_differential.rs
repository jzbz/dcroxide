// SPDX-License-Identifier: ISC
//! The secp256k1 entry points of HD key derivation (hdkeychain v3.1.3's
//! `NewMaster`, `NewKeyFromString`, `Child` and `pubKeyBytes`), judged by
//! dcrd's own secp256k1 code through `tools/oracle`:
//!
//! - `check_scalar` and the reduction of 32 bytes, against
//!   `ModNScalar.SetByteSlice`'s value and its `overflow` and `IsZero`
//!   flags (`modn_set_bytes`);
//! - `ReducedPrivateKey::from_bytes`, its `serialize` and its public
//!   point, against `PrivKeyFromBytes`, `Serialize` and
//!   `PubKey().SerializeCompressed()` (`privkey_from_bytes`), for slices of
//!   every length from 0 to 40;
//! - `add_private_tweak`, against hdkeychain's private child sum composed
//!   of `SetByteSlice`, `IsZero` and `ModNScalar.Add`
//!   (`privkey_tweak_add`);
//! - `check_scalar`, `PublicKey::parse` and `add_public_tweak` in
//!   hdkeychain's order, against its public child composed of
//!   `ScalarBaseMultNonConst`, `ParsePubKey` and `AddNonConst`
//!   (`pubkey_tweak_add`).
//!
//! Each answer is reduced to one line of text, the same for both sides, so
//! that the edge cases can be committed with dcrd's answers in
//! `tests/data/hd_tweak_vectors.txt`: one test checks the file everywhere,
//! without Go, and one rebuilds it with dcrd and compares it byte for
//! byte.  Random cases are compared live.  A zero private key and a sum at
//! infinity are named in our answers (`zero`, `infinity`) and recognised in
//! dcrd's by their bytes, so each is reported exactly where dcrd returns
//! one.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "byte offsets and lengths within short buffers"
)]

mod common;

use std::fmt::Write as _;

use common::{add, data_lines, require_regenerated, small, sub};
use dcroxide_dcrec::secp256k1::{
    FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PrivateKey, PublicKey, PublicPoint, ReducedPrivateKey,
    ScalarError, add_private_tweak, add_public_tweak, check_scalar,
};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};

/// The committed vectors.
const COMMITTED: &str = include_str!("data/hd_tweak_vectors.txt");

/// The oracle's commands.
const MODN: &str = "modn_set_bytes";
const FROM_BYTES: &str = "privkey_from_bytes";
const PRIV_TWEAK: &str = "privkey_tweak_add";
const PUB_TWEAK: &str = "pubkey_tweak_add";

/// dcrd's compressed serialization of the point at infinity.
fn infinity_hex() -> String {
    format!("02{}", "00".repeat(32))
}

/// N - 1, N + 1 and 2^256 - 1, big-endian.
fn n_minus(v: u64) -> [u8; 32] {
    sub(&GROUP_ORDER_BYTES, &small(v))
}
fn n_plus(v: u64) -> [u8; 32] {
    add(&GROUP_ORDER_BYTES, &small(v))
}
const ALL_ONES: [u8; 32] = [0xff; 32];

/// The tweaks the task's edges name: 0, 1, N-1, N, N+1, 2^256-1.
fn edge_tweaks() -> Vec<[u8; 32]> {
    vec![
        small(0),
        small(1),
        n_minus(1),
        GROUP_ORDER_BYTES,
        n_plus(1),
        ALL_ONES,
    ]
}

/// The verdict of `check_scalar`, as text.
fn verdict(r: Result<(), ScalarError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(ScalarError::Overflow) => "overflow",
        Err(ScalarError::Zero) => "zero",
    }
}

/// A reduced private key's bytes and public key, as text, the variant
/// named.  Zero must serialize to zeros and have dcrd's infinity bytes.
fn reduced_text(key: &ReducedPrivateKey) -> String {
    let bytes = hex(&key.serialize()[..]);
    let point = key.public_point();
    let public = hex(&point.serialize_compressed());
    match key {
        ReducedPrivateKey::Key(k) => {
            assert_eq!(point, PublicPoint::Key(k.public_key()));
            assert!(PrivateKey::from_bytes(&k.serialize()).is_some());
            format!("key {bytes} {public}")
        }
        ReducedPrivateKey::Zero => {
            assert_eq!(point, PublicPoint::Infinity);
            assert_eq!(bytes, "00".repeat(32));
            assert_eq!(public, infinity_hex());
            format!("zero {bytes} {public}")
        }
    }
}

/// Our answer for one case of one command.
fn ours(cmd: &str, data: &[u8]) -> String {
    match cmd {
        MODN => {
            let b: &[u8; 32] = data.try_into().expect("modn cases are 32 bytes");
            let reduced = ReducedPrivateKey::from_bytes(b);
            format!(
                "{} {}",
                hex(&reduced.serialize()[..]),
                verdict(check_scalar(b))
            )
        }
        FROM_BYTES => reduced_text(&ReducedPrivateKey::from_bytes(data)),
        PRIV_TWEAK => {
            let tweak: &[u8; 32] = data[..32].try_into().expect("32 bytes");
            match add_private_tweak(tweak, &data[32..]) {
                Ok(key) => format!("ok {}", reduced_text(&key)),
                Err(e) => format!("err {}", verdict(Err(e))),
            }
        }
        PUB_TWEAK => {
            // `add_public_tweak` runs on every tweak whose parent parses, Il
            // valid or not, and must refuse exactly what `check_scalar`
            // refuses, so its own range check is pinned too.  The answer
            // keeps hdkeychain's order: Il's range check, then the parent's
            // parse, then the sum.
            let tweak: &[u8; 32] = data[..32].try_into().expect("32 bytes");
            let il = check_scalar(tweak);
            let parsed = PublicKey::parse(&data[32..]);
            let sum = parsed.as_ref().ok().map(|p| add_public_tweak(tweak, p));
            if let Some(sum) = &sum {
                assert_eq!(
                    sum.as_ref().err().copied(),
                    il.err(),
                    "add_public_tweak's refusal is check_scalar's: {}",
                    hex(data)
                );
            }
            if let Err(e) = il {
                return format!("err {}", verdict(Err(e)));
            }
            if let Err(e) = parsed {
                return format!("err {}", e.kind_name());
            }
            let point = sum.expect("the parent parsed").expect("Il checked");
            let bytes = hex(&point.serialize_compressed());
            match point {
                PublicPoint::Key(_) => format!("ok key {bytes}"),
                PublicPoint::Infinity => {
                    assert_eq!(bytes, infinity_hex());
                    format!("ok infinity {bytes}")
                }
            }
        }
        _ => panic!("unknown command {cmd}"),
    }
}

/// dcrd's answer for one case of one command, as [`ours`] words it.
fn dcrd(oracle: &mut Oracle, cmd: &str, data: &[u8]) -> String {
    let resp = oracle.call(cmd, data);
    let result = || resp["result"].as_str().expect("result").to_owned();
    let compressed = || resp["compressed"].as_str().expect("compressed").to_owned();
    let key_text = |bytes: String, public: String| {
        if bytes == "00".repeat(32) {
            format!("zero {bytes} {public}")
        } else {
            format!("key {bytes} {public}")
        }
    };
    match cmd {
        MODN => {
            let overflow = resp["detail"]["overflow"].as_bool().expect("overflow");
            let zero = resp["detail"]["zero"].as_bool().expect("zero");
            let v = if overflow {
                "overflow"
            } else if zero {
                "zero"
            } else {
                "ok"
            };
            format!("{} {v}", result())
        }
        FROM_BYTES => key_text(result(), compressed()),
        PRIV_TWEAK | PUB_TWEAK => {
            if resp.get("error").is_some() {
                let kind = resp["kind"].as_str().expect("an error kind");
                return format!("err {kind}");
            }
            if cmd == PRIV_TWEAK {
                format!("ok {}", key_text(result(), compressed()))
            } else if result() == infinity_hex() {
                format!("ok infinity {}", result())
            } else {
                format!("ok key {}", result())
            }
        }
        _ => panic!("unknown command {cmd}"),
    }
}

/// The compressed public key of a private scalar in [1, N-1].
fn pub_of(d: &[u8; 32]) -> Vec<u8> {
    PrivateKey::from_bytes(d)
        .expect("a key")
        .public_key()
        .serialize_compressed()
        .to_vec()
}

/// The uncompressed public key of a private scalar in [1, N-1].
fn pub_of_uncompressed(d: &[u8; 32]) -> Vec<u8> {
    PrivateKey::from_bytes(d)
        .expect("a key")
        .public_key()
        .serialize_uncompressed()
        .to_vec()
}

/// tweak || parent.
fn cat(tweak: &[u8; 32], parent: &[u8]) -> Vec<u8> {
    let mut v = tweak.to_vec();
    v.extend_from_slice(parent);
    v
}

/// A scalar in [1, N-1] drawn from `rng`.
fn rand_key(rng: &mut SplitMix64) -> [u8; 32] {
    loop {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        if check_scalar(&b).is_ok() {
            return b;
        }
    }
}

/// The edge cases, (label, command, data), in the committed file's order.
fn edge_cases() -> Vec<(String, &'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rng = SplitMix64(0x6864_7477_6561_6b30);

    // The range check and the reduction of 32 bytes.
    let mut two_255 = [0u8; 32];
    two_255[0] = 0x80;
    let modn: Vec<(&str, [u8; 32])> = vec![
        ("0", small(0)),
        ("1", small(1)),
        ("N-1", n_minus(1)),
        ("N", GROUP_ORDER_BYTES),
        ("N+1", n_plus(1)),
        ("2^255", two_255),
        ("P", FIELD_PRIME_BYTES),
        ("2^256-1", ALL_ONES),
        ("random", rand_key(&mut rng)),
    ];
    for (label, v) in modn {
        out.push((label.to_owned(), MODN, v.to_vec()));
    }

    // The reducing constructor: every length from 0 to 40, each with
    // all-0xff bytes, N's leading bytes followed by 0xff, and seeded bytes;
    // and N and N + 1 followed by extra bytes, which are truncated away.
    for len in 0..=40usize {
        out.push((format!("ff*{len}"), FROM_BYTES, vec![0xff; len]));
        let mut n_prefix: Vec<u8> = GROUP_ORDER_BYTES.iter().copied().take(len).collect();
        n_prefix.resize(len, 0xff);
        out.push((format!("N-prefix*{len}"), FROM_BYTES, n_prefix));
        let mut seeded = vec![0u8; len];
        rng.fill(&mut seeded);
        out.push((format!("seeded*{len}"), FROM_BYTES, seeded));
    }
    for (label, head) in [("N", GROUP_ORDER_BYTES), ("N+1", n_plus(1))] {
        for extra in [1usize, 8] {
            let mut v = head.to_vec();
            v.extend(std::iter::repeat_n(0x5a, extra));
            out.push((format!("{label}+{extra}"), FROM_BYTES, v));
        }
    }
    out.push(("zeros*32".to_owned(), FROM_BYTES, vec![0; 32]));

    // The private child: every edge tweak against parents 1 and N-1, a
    // zero parent (empty and 32 zero bytes), a stripped parent, and
    // parents at and above N, which reduce; sums of exactly 0 and N-1; a
    // parent longer than 32 bytes.
    let parents: Vec<(&str, Vec<u8>)> = vec![
        ("1", small(1).to_vec()),
        ("N-1", n_minus(1).to_vec()),
        ("empty", Vec::new()),
        ("zeros*32", vec![0; 32]),
        ("stripped-05", vec![0x05]),
        ("N", GROUP_ORDER_BYTES.to_vec()),
        ("2^256-1", ALL_ONES.to_vec()),
    ];
    for (i, t) in edge_tweaks().iter().enumerate() {
        for (label, p) in &parents {
            out.push((format!("tweak{i}/{label}"), PRIV_TWEAK, cat(t, p)));
        }
    }
    let t = rand_key(&mut rng);
    for (label, tweak, parent) in [
        ("sum0/N-1+1", n_minus(1), small(1).to_vec()),
        ("sum0/1+N-1", small(1), n_minus(1).to_vec()),
        ("sum0/random", t, sub(&GROUP_ORDER_BYTES, &t).to_vec()),
        ("sumN-1/N-2+1", n_minus(2), small(1).to_vec()),
        ("sumN-1/1+N-2", small(1), n_minus(2).to_vec()),
        ("sumN-1/random", t, sub(&n_minus(1), &t).to_vec()),
        ("sum1/N-1+2", n_minus(1), small(2).to_vec()),
    ] {
        out.push((label.to_owned(), PRIV_TWEAK, cat(&tweak, &parent)));
    }
    let mut long = n_minus(1).to_vec();
    long.extend([0xab; 4]);
    out.push(("long-parent".to_owned(), PRIV_TWEAK, cat(&small(1), &long)));

    // The public child: every edge tweak against the keys of 1 and N-1;
    // sums at infinity (parent = -Il*G) and doublings (parent = Il*G); an
    // uncompressed parent; parents that do not parse, with Il valid and
    // with Il refused, which hdkeychain checks first.
    for (i, t) in edge_tweaks().iter().enumerate() {
        for (label, d) in [("1", small(1)), ("N-1", n_minus(1))] {
            out.push((
                format!("tweak{i}/pub{label}"),
                PUB_TWEAK,
                cat(t, &pub_of(&d)),
            ));
        }
    }
    for (label, tweak) in [("2", small(2)), ("N-2", n_minus(2)), ("random", t)] {
        let neg = sub(&GROUP_ORDER_BYTES, &tweak);
        out.push((
            format!("infinity/{label}"),
            PUB_TWEAK,
            cat(&tweak, &pub_of(&neg)),
        ));
        out.push((
            format!("double/{label}"),
            PUB_TWEAK,
            cat(&tweak, &pub_of(&tweak)),
        ));
    }
    let d = rand_key(&mut rng);
    out.push((
        "uncompressed".to_owned(),
        PUB_TWEAK,
        cat(&t, &pub_of_uncompressed(&d)),
    ));
    let infinity = unhex(&infinity_hex());
    let mut x_too_big = vec![0x02];
    x_too_big.extend_from_slice(&FIELD_PRIME_BYTES);
    for (label, parent) in [
        ("infinity-bytes", infinity),
        ("empty", Vec::new()),
        ("x>=P", x_too_big),
    ] {
        out.push((format!("bad-parent/{label}"), PUB_TWEAK, cat(&t, &parent)));
        out.push((
            format!("bad-parent-zero-tweak/{label}"),
            PUB_TWEAK,
            cat(&small(0), &parent),
        ));
    }
    out
}

/// The committed file's text with dcrd's answers.
fn file_text(oracle: &mut Oracle) -> String {
    let mut s = String::new();
    for line in [
        "# The secp256k1 entry points of HD key derivation at their edges,",
        "# judged by dcrd: as tests/hd_tweak_differential.rs constructs them,",
        "# each answer given by dcrd's dcrec/secp256k1/v4 at the parity pin",
        "# 46e9df48 through tools/oracle (ModNScalar.SetByteSlice and its",
        "# flags; PrivKeyFromBytes, Serialize and PubKey().SerializeCompressed();",
        "# hdkeychain v3.1.3's private and public child sums composed of",
        "# ModNScalar.Add, ScalarBaseMultNonConst, ParsePubKey and AddNonConst).",
        "# committed_hd_tweak_vectors_regenerate rebuilds the file and fails on",
        "# any difference; committed_hd_tweak_vectors_hold checks it without Go.",
        "#",
        "# <label>|<command>|<data hex>|<answer>",
    ] {
        let _ = writeln!(s, "{line}");
    }
    for (label, cmd, data) in edge_cases() {
        let answer = dcrd(oracle, cmd, &data);
        let _ = writeln!(s, "{label}|{cmd}|{}|{answer}", hex(&data));
    }
    s
}

/// Each committed line is the edge case [`edge_cases`] builds at its
/// position, label, command and data alike, one line per case, so a line
/// removed, added or altered fails here; and our answer is the recorded
/// dcrd answer.  Needs no Go.  The file reaches every outcome, keyed on the
/// answer's first two words for the tweak commands, so a zero sum (`ok
/// zero`) and a zero Il (`err zero`) are required separately: each verdict
/// of the range check, zero and nonzero keys, both refusals of a tweak, a
/// zero sum, a sum at infinity and each class of parent that does not
/// parse.
#[test]
fn committed_hd_tweak_vectors_hold() {
    let cases = edge_cases();
    let lines: Vec<_> = data_lines(COMMITTED).collect();
    assert_eq!(lines.len(), cases.len(), "one committed line per edge case");
    let mut seen = std::collections::BTreeSet::new();
    for ((line, f), (label, cmd, data)) in lines.iter().zip(&cases) {
        let [l, c, d, answer] = f[..] else {
            panic!("{line}: not four fields");
        };
        // The file's inputs are the constructed cases, in order.
        assert_eq!(
            (l, c, d),
            (label.as_str(), *cmd, hex(data).as_str()),
            "{line}: not the edge case it should be"
        );
        assert_eq!(ours(cmd, data), answer, "{line}: dcrd's answer");
        let words: Vec<&str> = answer.split(' ').collect();
        let outcome = match *cmd {
            MODN => words[1].to_owned(),
            FROM_BYTES => words[0].to_owned(),
            _ => words[..2].join(" "),
        };
        seen.insert(format!("{cmd} {outcome}"));
    }
    let want = [
        "modn_set_bytes ok",
        "modn_set_bytes overflow",
        "modn_set_bytes zero",
        "privkey_from_bytes key",
        "privkey_from_bytes zero",
        "privkey_tweak_add ok key",
        "privkey_tweak_add ok zero",
        "privkey_tweak_add err zero",
        "privkey_tweak_add err overflow",
        "pubkey_tweak_add ok key",
        "pubkey_tweak_add ok infinity",
        "pubkey_tweak_add err zero",
        "pubkey_tweak_add err overflow",
        "pubkey_tweak_add err ErrPubKeyInvalidLen",
        "pubkey_tweak_add err ErrPubKeyNotOnCurve",
        "pubkey_tweak_add err ErrPubKeyXTooBig",
    ];
    for w in want {
        assert!(seen.contains(w), "no committed line reaches {w}: {seen:?}");
    }
}

/// The committed file is the edge cases with dcrd's answers, byte for
/// byte.  With `DCROXIDE_REGEN_HD_TWEAKS=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_hd_tweak_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    require_regenerated(
        &file_text(&mut oracle),
        COMMITTED,
        "DCROXIDE_REGEN_HD_TWEAKS",
        "tests/data/hd_tweak_vectors.txt",
    );
}

/// Random cases of every command against dcrd, live: 32-byte values near
/// and below N, slices of random length, random tweaks against random,
/// stripped and zero parents, and random public children, with sums made
/// to land at zero, at infinity and on a doubling now and then.
#[test]
fn random_cases_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("hd tweak differential");
    fn check(oracle: &mut Oracle, cmd: &str, data: Vec<u8>) {
        assert_eq!(
            ours(cmd, &data),
            dcrd(oracle, cmd, &data),
            "{cmd} {}",
            hex(&data)
        );
    }
    for i in 0..1_000 {
        let mut v = [0u8; 32];
        rng.fill(&mut v);
        match i % 4 {
            // Within 2^64 of N, either side.
            1 => {
                let d = small(rng.next_u64());
                v = if rng.below(2) == 0 {
                    sub(&GROUP_ORDER_BYTES, &d)
                } else {
                    add(&GROUP_ORDER_BYTES, &d)
                };
            }
            2 => v[..20].fill(0),
            3 => v[..16].fill(0xff),
            _ => {}
        }
        check(&mut oracle, MODN, v.to_vec());
    }
    for _ in 0..1_000 {
        let len = rng.below(41) as usize;
        let mut data = vec![0u8; len];
        rng.fill(&mut data);
        if len > 0 && rng.below(4) == 0 {
            data[0] = 0xff;
        }
        check(&mut oracle, FROM_BYTES, data);
    }
    for i in 0..1_000 {
        let mut tweak = [0u8; 32];
        rng.fill(&mut tweak);
        let mut parent = rand_key(&mut rng).to_vec();
        match i % 8 {
            // A stripped parent.
            1 => parent = parent[1 + rng.below(31) as usize..].to_vec(),
            // A sum of zero.
            2 => {
                let t = rand_key(&mut rng);
                tweak = t;
                parent = sub(&GROUP_ORDER_BYTES, &t).to_vec();
            }
            3 => parent.clear(),
            4 => tweak = add(&GROUP_ORDER_BYTES, &small(rng.below(1 << 20))),
            _ => {}
        }
        check(&mut oracle, PRIV_TWEAK, cat(&tweak, &parent));
    }
    for i in 0..500 {
        let t = rand_key(&mut rng);
        let d = match i % 8 {
            1 => sub(&GROUP_ORDER_BYTES, &t),
            2 => t,
            _ => rand_key(&mut rng),
        };
        let parent = if i % 5 == 0 {
            pub_of_uncompressed(&d)
        } else {
            pub_of(&d)
        };
        check(&mut oracle, PUB_TWEAK, cat(&t, &parent));
    }
}

/// HD derivation's invariant, without Go: the public key of a private
/// child is the public child of the parent's public key, for random
/// tweaks and parents, the zero sum included (its public key is the
/// infinity the public sum gives), and through stripped parents.
#[test]
fn private_and_public_children_agree() {
    let mut rng = SplitMix64(0x6864_7477_6561_6b31);
    let mut zero = 0;
    for i in 0..512 {
        let t = rand_key(&mut rng);
        let d = if i % 16 == 0 {
            sub(&GROUP_ORDER_BYTES, &t)
        } else {
            rand_key(&mut rng)
        };
        let parent = PrivateKey::from_bytes(&d).expect("a key");
        let stripped: &[u8] = {
            let lead = d.iter().take_while(|&&b| b == 0).count();
            &d[lead..]
        };
        let child = add_private_tweak(&t, stripped).expect("a valid tweak");
        assert_eq!(
            child.serialize(),
            add_private_tweak(&t, &d)
                .expect("a valid tweak")
                .serialize()
        );
        let public = add_public_tweak(&t, &parent.public_key()).expect("a valid tweak");
        assert_eq!(child.public_point(), public);
        zero += usize::from(matches!(child, ReducedPrivateKey::Zero));
    }
    assert_eq!(zero, 32);
}

/// The zero key's shapes, without Go: every empty or zero slice and every
/// slice whose first 32 bytes are N reduce to `Zero`, which serializes to
/// zeros, whose public point is infinity, written 0x02 and 32 zero bytes,
/// which `PublicKey::parse` refuses as dcrd's `ParsePubKey` does.
#[test]
fn zero_key_shapes() {
    let mut n_long = GROUP_ORDER_BYTES.to_vec();
    n_long.push(7);
    for b in [
        &[][..],
        &[0; 1],
        &[0; 32],
        &[0; 40],
        &GROUP_ORDER_BYTES,
        &n_long,
    ] {
        let key = ReducedPrivateKey::from_bytes(b);
        assert!(matches!(key, ReducedPrivateKey::Zero), "{}", hex(b));
        assert_eq!(*key.serialize(), [0; 32]);
        assert_eq!(key.public_point(), PublicPoint::Infinity);
    }
    let infinity = PublicPoint::Infinity.serialize_compressed();
    assert_eq!(hex(&infinity), infinity_hex());
    assert_eq!(
        PublicKey::parse(&infinity).map_err(|e| e.kind_name()),
        Err("ErrPubKeyNotOnCurve")
    );
    // A key is never `Zero` and keeps its leading zeros.
    let one = ReducedPrivateKey::from_bytes(&[1]);
    assert_eq!(*one.serialize(), small(1));
    assert!(matches!(one, ReducedPrivateKey::Key(_)));
    assert_eq!(format!("{one:?}"), "Key(PrivateKey(..))");
    assert_eq!(format!("{:?}", ReducedPrivateKey::Zero), "Zero");
    // `add_public_tweak` refuses Il outside [1, N-1] itself, with
    // `check_scalar`'s verdict, for a valid parent.
    let q = PrivateKey::from_bytes(&small(7))
        .expect("a key")
        .public_key();
    assert_eq!(add_public_tweak(&small(0), &q), Err(ScalarError::Zero));
    for t in [GROUP_ORDER_BYTES, n_plus(1), ALL_ONES] {
        assert_eq!(add_public_tweak(&t, &q), Err(ScalarError::Overflow));
        assert_eq!(
            add_private_tweak(&t, &small(7)).err(),
            Some(ScalarError::Overflow)
        );
    }
    assert_eq!(
        add_private_tweak(&small(0), &small(7)).err(),
        Some(ScalarError::Zero)
    );
    // The refusals of a scalar, and their text.
    assert_eq!(check_scalar(&GROUP_ORDER_BYTES), Err(ScalarError::Overflow));
    assert_eq!(check_scalar(&small(0)), Err(ScalarError::Zero));
    assert_eq!(
        ScalarError::Overflow.to_string(),
        "scalar is not below the group order"
    );
    assert_eq!(ScalarError::Zero.to_string(), "scalar is zero");
    // `PrivateKey::serialize` is the key's 32 bytes, leading zeros kept.
    let key = PrivateKey::from_bytes(&small(5)).expect("a key");
    assert_eq!(*key.serialize(), small(5));
}
