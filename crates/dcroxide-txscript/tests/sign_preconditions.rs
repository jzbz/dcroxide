// SPDX-License-Identifier: ISC
//! `sign_tx_output` where dcrd's `SignTxOutput` hands back a lookup's own
//! error, and where it has no defined behaviour, against dcrd through the
//! oracle's `sign_tx_output` (which answers a panic with kind `panic`):
//!
//! * a `KeyDb` or `ScriptDb` error comes back unchanged, its type intact
//!   for downcasting and its text dcrd's;
//! * an input index past the inputs signs as dcrd does where dcrd has
//!   defined behaviour (every hash type without `SigHashAnyOneCanPay`, and
//!   `SigHashSingle` with no output at the index), and is an error where
//!   dcrd panics (QK-0035), with the same holding for `raw_tx_in_signature`
//!   through the oracle's `raw_txin_sig`, including dcrd's order of checking
//!   that the script parses before it slices the inputs;
//! * a pay-to-pubkey script whose key does not parse, signed directly or
//!   as a redeem script, is an error where dcrd panics (QK-0034);
//! * a merge into a nested pay-to-script-hash signature script is an error
//!   where dcrd recurses until its stack overflows, which kills an oracle
//!   started with a low stack limit (QK-0036), and signs as dcrd does in
//!   the nested cases dcrd returns from.
//!
//! The parts that need no Go run without the oracle; the rest skip
//! without one unless `DCROXIDE_REQUIRE_ORACLE` is set.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_bin, oracle_or_skip};
use dcroxide_txscript::sign::{SignError, SignatureType, raw_tx_in_signature, sign_tx_output};
use dcroxide_txscript::stdaddr::{self, Address};
use dcroxide_txscript::stdscript::{self, ScriptType};
use dcroxide_txscript::{SigHashType, opcode_by_name};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// dcroxide's text where dcrd indexes an empty address list.
const INVALID_PUBKEY: &str = "cannot sign a pay-to-pubkey script whose public key is not valid";
/// dcroxide's text where dcrd's merge recurses without end.
const NESTED_MERGE: &str = "cannot merge signature scripts of a pay-to-script-hash input whose \
                            redeem script is itself pay-to-script-hash";
/// The start of dcroxide's text where dcrd slices past the inputs.
const INDEX_OUT_OF_RANGE: &str = "cannot sign input ";

/// dcroxide's whole text where dcrd slices input `idx` out of a
/// transaction's `n_in` inputs.
fn index_error(idx: usize, n_in: usize) -> String {
    format!(
        "cannot sign input {idx} of a transaction with {n_in} inputs: the input index is out of \
         range"
    )
}

/// Sends `case`, on which dcrd recurses without end, to an oracle of its
/// own whose stack is limited to 16 MiB, so that it dies of the overflow at
/// once, and checks that it died as Go's runtime ends a stack overflow:
/// "fatal error: stack overflow" on its standard error, which is kept in a
/// file rather than shown, since Go adds a dump of every goroutine to it,
/// and exit status 2.  Callers have an oracle already, so this one is
/// required.
fn assert_dcrd_overflows(case: &Case) {
    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "sign-overflow-{}-{}.log",
        std::process::id(),
        case.name.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
    ));
    let stderr = std::fs::File::create(&log).expect("create the oracle's log");
    let mut limited = Oracle::from_command(
        std::process::Command::new(oracle_bin())
            .env("DCROXIDE_ORACLE_MAX_STACK", "16777216")
            .stderr(stderr),
    );
    let why = limited
        .try_call_line("sign_tx_output", &request(case))
        .expect_err("dcrd must not answer")
        .to_string();
    drop(limited);
    let text = std::fs::read_to_string(&log).expect("read the oracle's log");
    let _ = std::fs::remove_file(&log);
    // Rust's ExitStatus reads "exit status: 2" on Unix and "exit code: 2"
    // on Windows.
    assert!(
        why.contains("exit status: 2") || why.contains("exit code: 2"),
        "{}: {why}",
        case.name
    );
    assert!(
        text.contains("fatal error: stack overflow"),
        "{}: the oracle wrote {:?}",
        case.name,
        text.lines().take(3).collect::<Vec<_>>()
    );
}

/// The network every case is built for.
const NET: &str = "simnet";

/// A lookup's own error, as the oracle's closures make theirs: `no key
/// for <address>` and `no script for <address>`.
#[derive(Debug, PartialEq, Eq)]
struct Missing {
    what: &'static str,
    addr: String,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no {} for {}", self.what, self.addr)
    }
}

impl std::error::Error for Missing {}

/// A key: its bytes as `KeyDb` hands them over, type and compressedness.
#[derive(Clone)]
struct KeyEntry {
    key: Vec<u8>,
    sig_type: SignatureType,
    compressed: bool,
}

type KeyMap = BTreeMap<String, KeyEntry>;
type ScriptMap = BTreeMap<String, Vec<u8>>;

/// One `sign_tx_output` call.
struct Case {
    name: String,
    tx: MsgTx,
    idx: usize,
    pk_script: Vec<u8>,
    hash_type: SigHashType,
    keys: KeyMap,
    scripts: ScriptMap,
    prev: Vec<u8>,
    treasury: bool,
}

/// What dcrd did.
#[derive(Debug)]
enum Go {
    Signed(String),
    Failed(String),
    Panicked(String),
}

/// The lookups dcroxide made, by kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Lookups {
    keys: usize,
    scripts: usize,
}

fn ours(case: &Case) -> (Result<Vec<u8>, SignError>, Lookups) {
    let key_lookups = Cell::new(0);
    let script_lookups = Cell::new(0);
    let mut kdb = |addr: &Address| -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        key_lookups.set(key_lookups.get() + 1);
        match case.keys.get(&addr.encode()) {
            Some(e) => Ok((e.key.clone(), e.sig_type, e.compressed)),
            None => Err(SignError::other(Missing {
                what: "key",
                addr: addr.encode(),
            })),
        }
    };
    let mut sdb = |addr: &Address| -> Result<Vec<u8>, SignError> {
        script_lookups.set(script_lookups.get() + 1);
        match case.scripts.get(&addr.encode()) {
            Some(s) => Ok(s.clone()),
            None => Err(SignError::other(Missing {
                what: "script",
                addr: addr.encode(),
            })),
        }
    };
    let params = simnet_params();
    let result = sign_tx_output(
        &params,
        &case.tx,
        case.idx,
        &case.pk_script,
        case.hash_type,
        &mut kdb,
        &mut sdb,
        &case.prev,
        case.treasury,
    );
    let lookups = Lookups {
        keys: key_lookups.get(),
        scripts: script_lookups.get(),
    };
    (result, lookups)
}

fn sig_type_byte(sig_type: SignatureType) -> u8 {
    match sig_type {
        SignatureType::EcdsaSecp256k1 => 0,
        SignatureType::Ed25519 => 1,
        SignatureType::SchnorrSecp256k1 => 2,
    }
}

/// The oracle's `sign_tx_output` request for `case`.
fn request(case: &Case) -> Vec<u8> {
    let mut req = vec![NET.len() as u8];
    req.extend_from_slice(NET.as_bytes());
    req.push(case.hash_type.0);
    req.push(u8::from(case.treasury));
    req.extend_from_slice(&(case.idx as u32).to_be_bytes());
    req.extend_from_slice(&(case.pk_script.len() as u32).to_be_bytes());
    req.extend_from_slice(&case.pk_script);
    req.extend_from_slice(&(case.prev.len() as u32).to_be_bytes());
    req.extend_from_slice(&case.prev);
    req.push(case.keys.len() as u8);
    for (addr, e) in &case.keys {
        req.push(addr.len() as u8);
        req.extend_from_slice(addr.as_bytes());
        req.push(sig_type_byte(e.sig_type));
        req.push(u8::from(e.compressed));
        req.push(e.key.len() as u8);
        req.extend_from_slice(&e.key);
    }
    req.push(case.scripts.len() as u8);
    for (addr, s) in &case.scripts {
        req.push(addr.len() as u8);
        req.extend_from_slice(addr.as_bytes());
        req.extend_from_slice(&(s.len() as u16).to_be_bytes());
        req.extend_from_slice(s);
    }
    req.extend_from_slice(&case.tx.serialize());
    req
}

fn theirs(oracle: &mut Oracle, case: &Case) -> Go {
    let resp = oracle.call("sign_tx_output", &request(case));
    match (resp["error"].as_str(), resp["kind"].as_str()) {
        (Some(err), Some("panic")) => Go::Panicked(err.to_owned()),
        (Some(err), _) => Go::Failed(err.to_owned()),
        // An empty signature script is omitted from the response.
        (None, _) => Go::Signed(resp["result"].as_str().unwrap_or("").to_owned()),
    }
}

/// A transaction with `n_in` inputs and `n_out` outputs, its fields drawn
/// from `rng`.
fn tx(rng: &mut SplitMix64, n_in: usize, n_out: usize) -> MsgTx {
    let mut hash = [0u8; 32];
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: (0..n_in)
            .map(|i| {
                rng.fill(&mut hash);
                TxIn {
                    previous_out_point: OutPoint {
                        hash: Hash(hash),
                        index: i as u32,
                        tree: 0,
                    },
                    sequence: rng.next_u64() as u32,
                    value_in: 0,
                    block_height: 0,
                    block_index: 0,
                    signature_script: Vec::new(),
                }
            })
            .collect(),
        tx_out: (0..n_out)
            .map(|_| TxOut {
                value: (rng.next_u64() >> 20) as i64,
                version: 0,
                pk_script: rng.bytes(25),
            })
            .collect(),
        lock_time: 0,
        expiry: 0,
    }
}

fn secp_key(rng: &mut SplitMix64) -> [u8; 32] {
    loop {
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        if dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&k).is_some() {
            return k;
        }
    }
}

fn secp_pub(key: &[u8; 32]) -> [u8; 33] {
    dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(key)
        .expect("valid key")
        .public_key()
        .serialize_compressed()
}

fn entry(key: &[u8], sig_type: SignatureType) -> KeyEntry {
    KeyEntry {
        key: key.to_vec(),
        sig_type,
        compressed: true,
    }
}

fn p2pkh(key: &[u8; 32], params: &Params) -> Address {
    stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&stdaddr::hash160(&secp_pub(key)), params)
        .expect("20 bytes")
}

fn p2sh(redeem: &[u8], params: &Params) -> Address {
    stdaddr::new_address_script_hash_v0(redeem, params).expect("hash")
}

fn multisig(keys: &[[u8; 32]], required: i64) -> Vec<u8> {
    let pubs: Vec<[u8; 33]> = keys.iter().map(secp_pub).collect();
    let refs: Vec<&[u8]> = pubs.iter().map(|p| p.as_slice()).collect();
    stdscript::multi_sig_script_v0(required, &refs).expect("multisig")
}

fn multisig_entries(keys: &[[u8; 32]], params: &Params) -> KeyMap {
    keys.iter()
        .map(|k| {
            let addr = stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(secp_pub(k), params);
            (addr.encode(), entry(k, SignatureType::EcdsaSecp256k1))
        })
        .collect()
}

fn case(name: impl Into<String>, tx: MsgTx, idx: usize, pk_script: Vec<u8>) -> Case {
    Case {
        name: name.into(),
        tx,
        idx,
        pk_script,
        hash_type: SigHashType(0x01),
        keys: KeyMap::new(),
        scripts: ScriptMap::new(),
        prev: Vec::new(),
        treasury: true,
    }
}

// ---------------------------------------------------------------------
// Lookup errors.
// ---------------------------------------------------------------------

/// Cases whose first failing step is a lookup: every shape `sign` looks a
/// key or script up for, with that key or script missing.
fn lookup_cases(rng: &mut SplitMix64) -> Vec<(Case, Missing)> {
    let params = simnet_params();
    let mut out = Vec::new();
    let k = secp_key(rng);
    let t = tx(rng, 1, 1);
    let pkh = p2pkh(&k, &params);
    let missing_key = |addr: &Address| Missing {
        what: "key",
        addr: addr.encode(),
    };
    let missing_script = |addr: &Address| Missing {
        what: "script",
        addr: addr.encode(),
    };

    // P2PK in each suite, and P2PKH.
    let pk_addrs = [
        stdaddr::new_address_pub_key_ecdsa_secp256k1_v0(secp_pub(&k), &params),
        stdaddr::new_address_pub_key_schnorr_secp256k1_v0_raw(&secp_pub(&k), &params).expect("key"),
        stdaddr::new_address_pub_key_ed25519_v0_raw(
            &dcroxide_dcrec::edwards::SecretKey::from_seed(k)
                .public_key()
                .serialize(),
            &params,
        )
        .expect("key"),
        pkh.clone(),
    ];
    for addr in pk_addrs {
        let (_, script) = addr.payment_script();
        out.push((
            case(
                format!("missing key, {}", addr.go_type_name()),
                t.clone(),
                0,
                script,
            ),
            missing_key(&addr),
        ));
    }
    // Stake-tagged P2PKH outputs.
    for (i, tagged) in [
        pkh.voting_rights_script(),
        pkh.stake_change_script(),
        pkh.pay_vote_commitment_script(),
        pkh.pay_revoke_commitment_script(),
        pkh.pay_from_treasury_script(),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, script) = tagged.expect("stake script");
        out.push((
            case(format!("missing key, stake tag {i}"), t.clone(), 0, script),
            missing_key(&pkh),
        ));
    }
    // P2SH, plain and stake-tagged, without its script; then with it but
    // without the redeem script's key.
    let (_, redeem) = pkh.payment_script();
    let sh = p2sh(&redeem, &params);
    for (label, (_, script)) in [
        ("plain", sh.payment_script()),
        ("stake", sh.voting_rights_script().expect("stake script")),
    ] {
        out.push((
            case(
                format!("missing script, {label} p2sh"),
                t.clone(),
                0,
                script.clone(),
            ),
            missing_script(&sh),
        ));
        let mut c = case(
            format!("missing redeem key, {label} p2sh"),
            t.clone(),
            0,
            script,
        );
        c.scripts.insert(sh.encode(), redeem.clone());
        out.push((c, missing_key(&pkh)));
    }
    out
}

/// A lookup's own error comes back from `sign_tx_output` unchanged: the
/// same value, downcastable, with no text of the sign package's added.
#[test]
fn lookup_errors_come_back_unchanged() {
    let mut rng = SplitMix64(0x6c6f_6f6b_7570);
    for (case, want) in lookup_cases(&mut rng) {
        let (result, _) = ours(&case);
        let err = result.expect_err(&case.name);
        assert_eq!(err.to_string(), want.to_string(), "{}", case.name);
        assert_eq!(
            err.get_ref().and_then(|e| e.downcast_ref::<Missing>()),
            Some(&want),
            "{}",
            case.name
        );
        // Missing has no source, so neither has the wrapper: it is
        // transparent rather than a layer of its own over the error.
        assert!(std::error::Error::source(&err).is_none(), "{}", case.name);
        let inner = err.into_inner().expect("the lookup's error");
        assert_eq!(*inner.downcast::<Missing>().expect("Missing"), want);
    }
    // The sign package's own errors carry no caller error.
    let mut c = case("nulldata", tx(&mut rng, 1, 1), 0, vec![0x6a]);
    c.treasury = false;
    let err = ours(&c).0.expect_err("nulldata");
    assert_eq!(err.to_string(), "can't sign NULLDATA transactions");
    assert!(err.get_ref().is_none());
    assert!(std::error::Error::source(&err).is_none());
}

/// A caller's error that wraps another, as a wallet's database error
/// carries the failure beneath it.
#[derive(Debug)]
struct Wrapped(Missing);

impl fmt::Display for Wrapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wallet lookup failed")
    }
}

impl std::error::Error for Wrapped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// `SignError::source` is the caller's error's own source, not the
/// caller's error: the wrapper is transparent, so walking the chain from
/// a lookup's error that has a source reaches that source, and from one
/// that has none ends.  Checked on a `SignError::other` built directly and
/// on one `sign_tx_output` hands back from a key lookup.
#[test]
fn a_lookup_errors_source_is_its_own() {
    let missing = || Missing {
        what: "key",
        addr: "inner".to_owned(),
    };
    let direct = SignError::other(Wrapped(missing()));
    assert_eq!(direct.to_string(), "wallet lookup failed");
    let source = std::error::Error::source(&direct).expect("the wrapped error's source");
    assert_eq!(source.downcast_ref::<Missing>(), Some(&missing()));
    assert!(std::error::Error::source(&SignError::other(missing())).is_none());

    let mut rng = SplitMix64(0x736f_7572_6365);
    let params = simnet_params();
    let (_, script) = p2pkh(&secp_key(&mut rng), &params).payment_script();
    let t = tx(&mut rng, 1, 1);
    let mut kdb = |_: &Address| -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        Err(SignError::other(Wrapped(missing())))
    };
    let mut sdb = |_: &Address| -> Result<Vec<u8>, SignError> { unreachable!("no script lookup") };
    let err = sign_tx_output(
        &params,
        &t,
        0,
        &script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        true,
    )
    .expect_err("the key lookup fails");
    assert!(err.get_ref().is_some_and(|e| e.is::<Wrapped>()));
    let source = std::error::Error::source(&err).expect("the wrapped error's source");
    assert_eq!(source.downcast_ref::<Missing>(), Some(&missing()));
}

/// A caller's error shaped as dcr-purse's `AnyError::Foreign` is: an
/// opaque `Arc<dyn Error + Send + Sync>`.  That trait object names no
/// `UnwindSafe` or `RefUnwindSafe` bound, so the error is neither, as
/// `std::io::Error` is neither for the same reason.
#[derive(Debug, Clone)]
struct Opaque(std::sync::Arc<dyn std::error::Error + Send + Sync + 'static>);

impl fmt::Display for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Opaque {}

/// `SignError` keeps the auto traits a caller sends it across threads
/// with, and the `Error` impl `?` and boxing need.  It no longer has
/// `UnwindSafe` and `RefUnwindSafe`, which it had while it was a bare
/// `String`: a lookup's error may be any `Error + Send + Sync`, which
/// names neither (PARITY.md, `txscript/sign`).
#[test]
fn sign_error_is_send_sync_error() {
    fn assert_traits<T: Send + Sync + std::error::Error + 'static>() {}
    assert_traits::<SignError>();
}

/// A lookup's error that is neither `UnwindSafe` nor `RefUnwindSafe`, as a
/// wallet's opaque error is, still goes into `SignError::other` and comes
/// back from `sign_tx_output` unchanged.  Bounding `LookupError` by the two
/// unwind traits, to keep them on `SignError`, would stop this compiling,
/// which is why the bound is not there.
#[test]
fn a_lookup_error_need_not_be_unwind_safe() {
    let opaque = Opaque(std::sync::Arc::new(fmt::Error));
    let mut rng = SplitMix64(0x756e_7769_6e64);
    let params = simnet_params();
    let (_, script) = p2pkh(&secp_key(&mut rng), &params).payment_script();
    let t = tx(&mut rng, 1, 1);
    let returned = opaque.clone();
    let mut kdb = move |_: &Address| -> Result<(Vec<u8>, SignatureType, bool), SignError> {
        Err(SignError::other(returned.clone()))
    };
    let mut sdb = |_: &Address| -> Result<Vec<u8>, SignError> { unreachable!("no script lookup") };
    let err = sign_tx_output(
        &params,
        &t,
        0,
        &script,
        SigHashType(0x01),
        &mut kdb,
        &mut sdb,
        &[],
        true,
    )
    .expect_err("the key lookup fails");
    assert_eq!(err.to_string(), opaque.to_string());
    let inner = err.into_inner().expect("the caller's error");
    let back = inner.downcast::<Opaque>().expect("an Opaque");
    assert!(std::sync::Arc::ptr_eq(&back.0, &opaque.0), "the same value");
}

/// dcrd returns the same errors, by text, for the same cases.
#[test]
fn lookup_errors_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sign lookup errors");
    for _ in 0..4 {
        for (case, want) in lookup_cases(&mut rng) {
            match theirs(&mut oracle, &case) {
                Go::Failed(text) => assert_eq!(text, want.to_string(), "{}", case.name),
                other => panic!("{}: dcrd answered {other:?}", case.name),
            }
            let text = ours(&case).0.expect_err(&case.name).to_string();
            assert_eq!(text, want.to_string(), "{}", case.name);
        }
    }
}

// ---------------------------------------------------------------------
// Input index out of range.
// ---------------------------------------------------------------------

/// The hash types the index cases sign with: the three defined ones, each
/// with and without `SigHashAnyOneCanPay`, an undefined one with and
/// without, and the bits the mask leaves out.
const HASH_TYPES: [u8; 10] = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x84, 0x41, 0xc3];

/// Index cases: each signable shape, on transactions of one to three
/// inputs and outputs, at an index inside and past the inputs.
fn index_cases(rng: &mut SplitMix64) -> Vec<Case> {
    let params = simnet_params();
    let mut out = Vec::new();
    for _ in 0..2 {
        let n_in = 1 + rng.below(3) as usize;
        let n_out = 1 + rng.below(3) as usize;
        let t = tx(rng, n_in, n_out);
        let keys: Vec<[u8; 32]> = (0..3).map(|_| secp_key(rng)).collect();
        let pkh = p2pkh(&keys[0], &params);
        let ms = multisig(&keys, 2);
        let ms_sh = p2sh(&ms, &params);
        let (_, pkh_script) = pkh.payment_script();
        let pkh_sh = p2sh(&pkh_script, &params);
        for idx in [0, n_in - 1, n_in, n_in + 1, n_in + 6] {
            for &ht in &HASH_TYPES {
                let ht = SigHashType(ht);
                let mut add = |name: &str, script: Vec<u8>, keys: KeyMap, scripts: ScriptMap| {
                    let mut c = case(
                        format!("{name} idx {idx}/{n_in}x{n_out} ht {:#x}", ht.0),
                        t.clone(),
                        idx,
                        script,
                    );
                    c.hash_type = ht;
                    c.keys = keys;
                    c.scripts = scripts;
                    out.push(c);
                };
                let one = |k: &[u8; 32]| {
                    KeyMap::from([(
                        p2pkh(k, &params).encode(),
                        entry(k, SignatureType::EcdsaSecp256k1),
                    )])
                };
                add("p2pkh", pkh_script.clone(), one(&keys[0]), ScriptMap::new());
                add(
                    "p2pkh without key",
                    pkh_script.clone(),
                    KeyMap::new(),
                    ScriptMap::new(),
                );
                let schnorr = stdaddr::new_address_pub_key_schnorr_secp256k1_v0_raw(
                    &secp_pub(&keys[1]),
                    &params,
                )
                .expect("key");
                add(
                    "schnorr p2pk",
                    schnorr.payment_script().1,
                    KeyMap::from([(
                        schnorr.encode(),
                        entry(&keys[1], SignatureType::SchnorrSecp256k1),
                    )]),
                    ScriptMap::new(),
                );
                let mut two = multisig_entries(&keys, &params);
                two.pop_first();
                add("multisig", ms.clone(), two.clone(), ScriptMap::new());
                add(
                    "multisig without keys",
                    ms.clone(),
                    KeyMap::new(),
                    ScriptMap::new(),
                );
                add(
                    "p2sh multisig",
                    ms_sh.payment_script().1,
                    two,
                    ScriptMap::from([(ms_sh.encode(), ms.clone())]),
                );
                add(
                    "p2sh p2pkh",
                    pkh_sh.payment_script().1,
                    one(&keys[0]),
                    ScriptMap::from([(pkh_sh.encode(), pkh_script.clone())]),
                );
                add(
                    "nulldata",
                    vec![0x6a, 0x01, 0x07 + 10],
                    KeyMap::new(),
                    ScriptMap::new(),
                );
            }
            // A multisig merge whose earlier signature carries
            // SigHashAnyOneCanPay, while the caller signs with SigHashAll.
            for (name, pk_script, scripts) in [
                ("merge multisig", ms.clone(), ScriptMap::new()),
                (
                    "merge p2sh multisig",
                    ms_sh.payment_script().1,
                    ScriptMap::from([(ms_sh.encode(), ms.clone())]),
                ),
            ] {
                let mut first = case("partial", t.clone(), 0, pk_script.clone());
                first.hash_type = SigHashType(0x81);
                first.keys = multisig_entries(&keys[..1], &params);
                first.scripts = scripts.clone();
                let partial = ours(&first).0.expect("partial signature");
                let mut c = case(
                    format!("{name} idx {idx}/{n_in}x{n_out}"),
                    t.clone(),
                    idx,
                    pk_script,
                );
                c.keys = multisig_entries(&keys[1..2], &params);
                c.scripts = scripts;
                c.prev = partial;
                out.push(c);
            }
        }
    }
    out
}

/// Without the oracle: every index case returns rather than panics, and
/// an index past the inputs under SigHashAnyOneCanPay, outside
/// SigHashSingle with no output there, never signs.
#[test]
fn index_cases_return_without_panicking() {
    let mut rng = SplitMix64(0x0069_6e64_6578);
    let mut refused = 0;
    for case in index_cases(&mut rng) {
        let (result, _) = ours(&case);
        if let Err(e) = &result
            && e.to_string().starts_with(INDEX_OUT_OF_RANGE)
        {
            assert!(case.idx >= case.tx.tx_in.len(), "{}", case.name);
            assert_eq!(
                e.to_string(),
                index_error(case.idx, case.tx.tx_in.len()),
                "{}",
                case.name
            );
            refused += 1;
        }
    }
    assert!(refused > 0);
}

/// Against dcrd: where dcrd signs or fails, the same script or a failure;
/// where dcrd panics, dcroxide's error.  The cases must reach all three,
/// and signing past the inputs without SigHashAnyOneCanPay must be among
/// the scripts compared.
#[test]
fn index_cases_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sign index cases");
    let (mut signed_past, mut failed, mut panicked) = (0, 0, 0);
    for case in index_cases(&mut rng) {
        let (result, _) = ours(&case);
        match (theirs(&mut oracle, &case), &result) {
            (Go::Signed(want), Ok(got)) => {
                assert_eq!(hex(got), want, "{}", case.name);
                if case.idx >= case.tx.tx_in.len() && !got.is_empty() {
                    signed_past += 1;
                }
            }
            (Go::Failed(want), Err(got)) => {
                assert_eq!(got.to_string(), want, "{}", case.name);
                failed += 1;
            }
            (Go::Panicked(why), Err(got)) => {
                assert!(why.contains("out of range"), "{}: {why}", case.name);
                assert_eq!(
                    got.to_string(),
                    index_error(case.idx, case.tx.tx_in.len()),
                    "{}",
                    case.name
                );
                assert!(case.idx >= case.tx.tx_in.len(), "{}", case.name);
                panicked += 1;
            }
            (go, ours) => panic!("{}: dcrd {go:?}, dcroxide {ours:?}", case.name),
        }
    }
    assert!(
        signed_past > 0 && failed > 0 && panicked > 0,
        "signed past the inputs {signed_past}, failed {failed}, panicked {panicked}"
    );
}

/// The index error names the transaction's input count, not its output
/// count: one input and three outputs, signed at input 2 under
/// SigHashAnyOneCanPay with an output there, so only the input slice is
/// out of range.
#[test]
fn the_index_error_counts_the_inputs() {
    let mut rng = SplitMix64(0x0069_6e70_7574);
    let params = simnet_params();
    let key = secp_key(&mut rng);
    let pkh = p2pkh(&key, &params);
    for ht in [0x81, 0x82, 0x83] {
        let mut c = case(
            "one in, three out",
            tx(&mut rng, 1, 3),
            2,
            pkh.payment_script().1,
        );
        c.hash_type = SigHashType(ht);
        c.keys = KeyMap::from([(pkh.encode(), entry(&key, SignatureType::EcdsaSecp256k1))]);
        let err = ours(&c).0.expect_err("index past the inputs");
        assert_eq!(err.to_string(), index_error(2, 1), "ht {ht:#x}");
        let err = raw_tx_in_signature(
            &c.tx,
            2,
            &[0x51],
            SigHashType(ht),
            &key,
            SignatureType::EcdsaSecp256k1,
        )
        .expect_err("index past the inputs");
        assert_eq!(err.to_string(), index_error(2, 1), "raw ht {ht:#x}");
    }
}

// ---------------------------------------------------------------------
// Raw input signatures past the inputs.
// ---------------------------------------------------------------------

/// Sub-scripts for the raw signature cases: three that do not parse, each
/// a push opcode cut short in its length bytes, then three that do.
const RAW_SUB_SCRIPTS: [&[u8]; 6] = [
    &[0x4c],
    &[0x4d, 0x01],
    &[0x4e, 0x00, 0x00, 0x00],
    &[0x51],
    &[0x76, 0xa9],
    &[0x51, 0x4c, 0x01, 0x07],
];

/// dcrd's parse error for `[0x4c]`, an `OP_PUSHDATA1` with no length byte,
/// which `CalcSignatureHash` returns before it looks at the index.
const PUSHDATA1_PARSE_ERROR: &str =
    "opcode OP_PUSHDATA1 requires 1 bytes, but script only has 0 remaining";

/// One `raw_tx_in_signature` call.
struct RawCase {
    name: String,
    tx: MsgTx,
    idx: usize,
    sub: Vec<u8>,
    hash_type: SigHashType,
    key: Vec<u8>,
    sig_type: SignatureType,
}

impl RawCase {
    fn ours(&self) -> Result<Vec<u8>, SignError> {
        raw_tx_in_signature(
            &self.tx,
            self.idx,
            &self.sub,
            self.hash_type,
            &self.key,
            self.sig_type,
        )
    }

    /// dcrd's answer through the oracle's `raw_txin_sig`, which answers
    /// a panic with kind `panic`.
    fn theirs(&self, oracle: &mut Oracle) -> Go {
        let mut req = vec![sig_type_byte(self.sig_type), self.hash_type.0];
        req.extend_from_slice(&(self.idx as u32).to_be_bytes());
        req.push(self.key.len() as u8);
        req.extend_from_slice(&self.key);
        req.extend_from_slice(&(self.sub.len() as u32).to_be_bytes());
        req.extend_from_slice(&self.sub);
        req.extend_from_slice(&self.tx.serialize());
        let resp = oracle.call("raw_txin_sig", &req);
        match (resp["error"].as_str(), resp["kind"].as_str()) {
            (Some(err), Some("panic")) => Go::Panicked(err.to_owned()),
            (Some(err), _) => Go::Failed(err.to_owned()),
            (None, _) => Go::Signed(resp["result"].as_str().unwrap_or("").to_owned()),
        }
    }
}

/// Raw signature cases: transactions with more, fewer and as many outputs
/// as inputs, at an index inside and past the inputs, under every index
/// case hash type, with each sub-script, in each signature suite in turn.
fn raw_cases(rng: &mut SplitMix64) -> Vec<RawCase> {
    let mut out = Vec::new();
    let mut suite = 0usize;
    for (n_in, n_out) in [(1, 1), (1, 3), (2, 1), (2, 4), (3, 3)] {
        let t = tx(rng, n_in, n_out);
        for idx in [0, n_in, n_in + 1, n_in + 5] {
            for &ht in &HASH_TYPES {
                for sub in RAW_SUB_SCRIPTS {
                    let k = secp_key(rng);
                    let (key, sig_type) = match suite % 3 {
                        0 => (k.to_vec(), SignatureType::EcdsaSecp256k1),
                        1 => (k.to_vec(), SignatureType::SchnorrSecp256k1),
                        _ => {
                            let public = dcroxide_dcrec::edwards::SecretKey::from_seed(k)
                                .public_key()
                                .serialize();
                            (
                                [k.as_slice(), public.as_slice()].concat(),
                                SignatureType::Ed25519,
                            )
                        }
                    };
                    suite += 1;
                    out.push(RawCase {
                        name: format!(
                            "{sig_type:?} idx {idx}/{n_in}x{n_out} ht {ht:#x} sub {}",
                            hex(sub)
                        ),
                        tx: t.clone(),
                        idx,
                        sub: sub.to_vec(),
                        hash_type: SigHashType(ht),
                        key,
                        sig_type,
                    });
                }
            }
        }
    }
    out
}

/// Without the oracle: dcrd checks that the script parses before it
/// slices the inputs (`sighash.go:451-458`, then `:248-252`), so an
/// unparsable sub-script past the inputs under SigHashAnyOneCanPay is
/// dcrd's parse error, not dcroxide's index error, whichever of the three
/// defined hash types carries the flag; a parsable one is the index error.
#[test]
fn raw_signature_parses_before_it_checks_the_index() {
    let mut rng = SplitMix64(0x7261_7770_6172);
    let key = secp_key(&mut rng);
    let t = tx(&mut rng, 1, 1);
    for ht in [0x81, 0x82, 0x83, 0xc1] {
        for idx in [1, 5] {
            let sign = |sub: &[u8]| {
                raw_tx_in_signature(
                    &t,
                    idx,
                    sub,
                    SigHashType(ht),
                    &key,
                    SignatureType::EcdsaSecp256k1,
                )
            };
            let err = sign(&[0x4c]).expect_err("unparsable");
            assert_eq!(
                err.to_string(),
                PUSHDATA1_PARSE_ERROR,
                "ht {ht:#x} idx {idx}"
            );
            if ht & 0x1f != 0x03 {
                let err = sign(&[0x51]).expect_err("past the inputs");
                assert_eq!(err.to_string(), index_error(idx, 1), "ht {ht:#x} idx {idx}");
            }
        }
    }
}

/// Against dcrd: where dcrd signs or fails, the same signature or the same
/// text; where dcrd panics, dcroxide's index error, and only for a script
/// that parses at an index past the inputs.  The cases must reach a parse
/// error past the inputs under SigHashAnyOneCanPay, a panic, and a
/// signature past the inputs.
#[test]
fn raw_signature_index_cases_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("raw signature index cases");
    let (mut parse_past, mut panicked, mut signed_past) = (0, 0, 0);
    for case in raw_cases(&mut rng) {
        let past = case.idx >= case.tx.tx_in.len();
        let acp = case.hash_type.0 & 0x80 != 0;
        let parses = !RAW_SUB_SCRIPTS[..3].contains(&case.sub.as_slice());
        match (case.theirs(&mut oracle), case.ours()) {
            (Go::Signed(want), Ok(got)) => {
                assert_eq!(hex(&got), want, "{}", case.name);
                signed_past += usize::from(past);
            }
            (Go::Failed(want), Err(got)) => {
                assert_eq!(got.to_string(), want, "{}", case.name);
                parse_past += usize::from(past && acp && !parses);
            }
            (Go::Panicked(why), Err(got)) => {
                assert!(why.contains("out of range"), "{}: {why}", case.name);
                assert!(past && acp && parses, "{}", case.name);
                assert_eq!(
                    got.to_string(),
                    index_error(case.idx, case.tx.tx_in.len()),
                    "{}",
                    case.name
                );
                panicked += 1;
            }
            (go, ours) => panic!("{}: dcrd {go:?}, dcroxide {ours:?}", case.name),
        }
    }
    assert!(
        parse_past > 0 && panicked > 0 && signed_past > 0,
        "parse errors past the inputs {parse_past}, panicked {panicked}, signed past the \
         inputs {signed_past}"
    );
}

// ---------------------------------------------------------------------
// Pay-to-pubkey scripts whose key does not parse.
// ---------------------------------------------------------------------

/// A pay-to-pubkey script in each of the four shapes `stdscript`
/// classifies by shape, carrying a key that does not parse: compressed
/// and uncompressed ECDSA, Schnorr and Ed25519.
fn invalid_pubkey_scripts(rng: &mut SplitMix64) -> Vec<(&'static str, Vec<u8>)> {
    let checksig = opcode_by_name("OP_CHECKSIG").expect("opcode");
    let checksigalt = opcode_by_name("OP_CHECKSIGALT").expect("opcode");
    let off_curve_x = |rng: &mut SplitMix64| loop {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        rng.fill(&mut k[1..]);
        if dcroxide_dcrec::secp256k1::PublicKey::parse(&k).is_err() {
            return k;
        }
    };
    let compressed = off_curve_x(rng);
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&compressed[1..]);
    rng.fill(&mut uncompressed[33..]);
    let schnorr = off_curve_x(rng);
    let ed25519 = loop {
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        if dcroxide_dcrec::edwards::parse_pub_key(&k).is_err() {
            break k;
        }
    };
    let push = |data: &[u8]| {
        let mut s = vec![data.len() as u8];
        s.extend_from_slice(data);
        s
    };
    let scripts = vec![
        (
            "compressed ecdsa",
            [push(&compressed), vec![checksig]].concat(),
        ),
        (
            "uncompressed ecdsa",
            [push(&uncompressed), vec![checksig]].concat(),
        ),
        (
            "schnorr",
            [push(&schnorr), vec![0x52, checksigalt]].concat(),
        ),
        (
            "ed25519",
            [push(&ed25519), vec![0x51, checksigalt]].concat(),
        ),
    ];
    let params = simnet_params();
    for (name, script) in &scripts {
        let (class, addrs) = stdscript::extract_addrs_v0(script, &params);
        assert!(
            matches!(
                class,
                ScriptType::PubKeyEcdsaSecp256k1
                    | ScriptType::PubKeySchnorrSecp256k1
                    | ScriptType::PubKeyEd25519
            ) && addrs.is_empty(),
            "{name}: {class:?} with {} addresses",
            addrs.len()
        );
    }
    scripts
}

/// The invalid-key scripts signed directly, and as the redeem script of
/// plain and stake-tagged pay-to-script-hash outputs.
fn invalid_pubkey_cases(rng: &mut SplitMix64) -> Vec<(Case, Lookups)> {
    let params = simnet_params();
    let t = tx(rng, 1, 1);
    let mut out = Vec::new();
    for (name, script) in invalid_pubkey_scripts(rng) {
        out.push((case(name, t.clone(), 0, script.clone()), Lookups::default()));
        let sh = p2sh(&script, &params);
        for (label, (_, pk)) in [
            ("p2sh", sh.payment_script()),
            (
                "stake p2sh",
                sh.voting_rights_script().expect("stake script"),
            ),
        ] {
            let mut c = case(format!("{label} {name}"), t.clone(), 0, pk);
            c.scripts.insert(sh.encode(), script.clone());
            out.push((
                c,
                Lookups {
                    keys: 0,
                    scripts: 1,
                },
            ));
        }
    }
    out
}

/// dcroxide's error, after exactly the lookups dcrd makes before its panic.
#[test]
fn invalid_pubkey_scripts_are_errors() {
    let mut rng = SplitMix64(0x0070_626b);
    for (case, lookups) in invalid_pubkey_cases(&mut rng) {
        let (result, made) = ours(&case);
        assert_eq!(
            result.expect_err(&case.name).to_string(),
            INVALID_PUBKEY,
            "{}",
            case.name
        );
        assert_eq!(made, lookups, "{}", case.name);
    }
}

/// dcrd panics on every one of them.
#[test]
fn invalid_pubkey_scripts_panic_in_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sign invalid pubkey");
    for (case, _) in invalid_pubkey_cases(&mut rng) {
        match theirs(&mut oracle, &case) {
            Go::Panicked(why) => assert!(
                why.contains("index out of range [0] with length 0"),
                "{}: {why}",
                case.name
            ),
            other => panic!("{}: dcrd answered {other:?}", case.name),
        }
        assert_eq!(
            ours(&case).0.expect_err(&case.name).to_string(),
            INVALID_PUBKEY
        );
    }
}

// ---------------------------------------------------------------------
// Nested pay-to-script-hash merges.
// ---------------------------------------------------------------------

/// A pay-to-script-hash output whose redeem script R1 is itself
/// pay-to-script-hash (plain or stake-tagged) of a script X, with both
/// scripts known, merged into `prev`.  Whether dcrd recurses without end
/// is the last element.
fn nested_cases(rng: &mut SplitMix64) -> Vec<(Case, bool)> {
    let params = simnet_params();
    let t = tx(rng, 1, 1);
    let k = secp_key(rng);
    let (_, x) = p2pkh(&k, &params).payment_script();
    let x_sh = p2sh(&x, &params);
    let mut out = Vec::new();
    for (r1_label, r1) in [
        ("plain", x_sh.payment_script().1),
        ("stake", x_sh.voting_rights_script().expect("stake").1),
    ] {
        let r1_sh = p2sh(&r1, &params);
        for (prev_label, prev) in [
            ("empty", vec![]),
            ("OP_1", vec![0x51]),
            ("unparsable", vec![0x4c]),
            ("a push", vec![0x02, 0xab, 0xcd]),
        ] {
            let mut c = case(
                format!("r1 {r1_label}, prev {prev_label}"),
                t.clone(),
                0,
                r1_sh.payment_script().1,
            );
            c.scripts.insert(r1_sh.encode(), r1.clone());
            c.scripts.insert(x_sh.encode(), x.clone());
            c.keys.insert(
                p2pkh(&k, &params).encode(),
                entry(&k, SignatureType::EcdsaSecp256k1),
            );
            c.prev = prev.clone();
            let recurses =
                r1_label == "plain" && prev_label != "empty" && prev_label != "unparsable";
            out.push((c, recurses));
        }
    }
    out
}

/// dcroxide's error exactly where dcrd would recurse, after both script
/// lookups, and dcrd's script everywhere else; neither overflows a stack.
#[test]
fn nested_script_hash_merges_return() {
    let mut rng = SplitMix64(0x6e65_7374);
    for (case, recurses) in nested_cases(&mut rng) {
        let (result, made) = ours(&case);
        assert_eq!(
            made,
            Lookups {
                keys: 0,
                scripts: 2
            },
            "{}",
            case.name
        );
        match result {
            Err(e) => {
                assert!(recurses, "{}: {e}", case.name);
                assert_eq!(e.to_string(), NESTED_MERGE, "{}", case.name);
            }
            Ok(_) => assert!(!recurses, "{}", case.name),
        }
    }
}

/// Against dcrd: the cases dcrd returns from sign alike, and each case on
/// which dcroxide refuses kills an oracle whose stack is limited to 16 MiB
/// with Go's stack overflow (`assert_dcrd_overflows`).
#[test]
fn nested_script_hash_merges_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sign nested p2sh");
    let mut deaths = 0;
    for (case, recurses) in nested_cases(&mut rng) {
        if !recurses {
            match (theirs(&mut oracle, &case), ours(&case).0) {
                (Go::Signed(want), Ok(got)) => assert_eq!(hex(&got), want, "{}", case.name),
                (go, ours) => panic!("{}: dcrd {go:?}, dcroxide {ours:?}", case.name),
            }
            continue;
        }
        assert_dcrd_overflows(&case);
        deaths += 1;
    }
    assert_eq!(deaths, 2);
}

// ---------------------------------------------------------------------
// Frozen battery.
// ---------------------------------------------------------------------

/// The committed battery: dcrd's verdict on each case `battery` builds.
const COMMITTED: &str = include_str!("data/sign_precondition_vectors.txt");

/// The number of cases in the battery.
const COMMITTED_CASES: usize = 238;

/// The battery's BLAKE-256 digest; regenerate it with the file through
/// `committed_sign_vectors_regenerate`.
const COMMITTED_DIGEST: &str = "324ad89a7c9418d0014e668801a56ae9a95d94e013c909c475596e0e9b2ceae7";

/// The battery's cases, built from fixed seeds: every lookup, invalid key
/// and nested case, and every fourth index case.
fn battery() -> Vec<Case> {
    let mut cases: Vec<Case> = lookup_cases(&mut SplitMix64(1))
        .into_iter()
        .map(|(c, _)| c)
        .collect();
    cases.extend(
        invalid_pubkey_cases(&mut SplitMix64(2))
            .into_iter()
            .map(|(c, _)| c),
    );
    cases.extend(index_cases(&mut SplitMix64(3)).into_iter().step_by(4));
    cases.extend(nested_cases(&mut SplitMix64(4)).into_iter().map(|(c, _)| c));
    cases
}

/// One battery line: the case's name, the BLAKE-256 digest of its oracle
/// request, and dcrd's verdict.
fn line(case: &Case, verdict: &str) -> String {
    format!(
        "{}|{}|{verdict}",
        case.name,
        hex(&dcroxide_crypto::blake256::sum256(&request(case)))
    )
}

/// dcrd's verdict on `case`, as the battery records it; a case on which
/// dcrd recurses without end is sent to its own oracle with a 16 MiB stack
/// limit, which it kills.
fn verdict(oracle: &mut Oracle, case: &Case) -> String {
    let recurses = nested_cases(&mut SplitMix64(4))
        .iter()
        .any(|(c, r)| *r && c.name == case.name && request(c) == request(case));
    if recurses {
        assert_dcrd_overflows(case);
        return "died".to_owned();
    }
    match theirs(oracle, case) {
        Go::Signed(script) => format!("signed {script}"),
        Go::Failed(text) => format!("failed {text}"),
        Go::Panicked(text) => format!("panicked {text}"),
    }
}

/// Every committed verdict is matched by dcroxide: the same script, the
/// same failure, or dcroxide's error where dcrd panics or dies.  Needs no
/// Go.
#[test]
fn committed_sign_vectors_hold() {
    assert_eq!(
        hex(&dcroxide_crypto::blake256::sum256(COMMITTED.as_bytes())),
        COMMITTED_DIGEST,
        "data/sign_precondition_vectors.txt is not the committed battery"
    );
    let lines: Vec<&str> = COMMITTED.lines().filter(|l| !l.starts_with('#')).collect();
    let cases = battery();
    assert_eq!(lines.len(), COMMITTED_CASES);
    assert_eq!(cases.len(), COMMITTED_CASES);
    let mut kinds = BTreeMap::new();
    for (case, l) in cases.iter().zip(lines) {
        let (name, rest) = l.split_once('|').expect("fields");
        let (digest, verdict) = rest.split_once('|').expect("fields");
        assert_eq!(name, case.name);
        assert_eq!(
            digest,
            hex(&dcroxide_crypto::blake256::sum256(&request(case))),
            "{name}: the case is not the one recorded"
        );
        let (kind, detail) = verdict.split_once(' ').unwrap_or((verdict, ""));
        *kinds.entry(kind.to_owned()).or_insert(0) += 1;
        let ours = ours(case).0;
        match (kind, &ours) {
            ("signed", Ok(script)) => assert_eq!(hex(script), detail, "{name}"),
            ("failed", Err(e)) => assert_eq!(e.to_string(), detail, "{name}"),
            ("panicked", Err(e)) => {
                let e = e.to_string();
                assert!(
                    e == INVALID_PUBKEY || e == index_error(case.idx, case.tx.tx_in.len()),
                    "{name}: {e}"
                );
            }
            ("died", Err(e)) => assert_eq!(e.to_string(), NESTED_MERGE, "{name}"),
            _ => panic!("{name}: dcrd {verdict}, dcroxide {ours:?}"),
        }
    }
    assert_eq!(
        kinds.keys().cloned().collect::<Vec<_>>(),
        ["died", "failed", "panicked", "signed"]
    );
}

/// The committed file is the battery with dcrd's verdicts, byte for byte.
/// With `DCROXIDE_REGEN_SIGN_VECTORS=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_sign_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut text = String::from(
        "# dcrd sign.SignTxOutput at the parity pin 46e9df48, through tools/oracle's\n\
         # sign_tx_output, on the cases tests/sign_preconditions.rs builds from fixed\n\
         # seeds (battery()): missing keys and scripts, pay-to-pubkey scripts whose\n\
         # key does not parse, input indexes inside and past the inputs, and nested\n\
         # pay-to-script-hash merges.  Each verdict is \"signed <script hex>\",\n\
         # \"failed <dcrd's error>\", \"panicked <the panic>\", or \"died\" where the\n\
         # oracle, limited to a 16 MiB stack, died of the overflow.\n\
         # committed_sign_vectors_regenerate rebuilds this file and fails on any\n\
         # difference; committed_sign_vectors_hold checks it without Go.\n\
         #\n\
         # <case>|<BLAKE-256 of the oracle request>|<verdict>\n",
    );
    for case in battery() {
        let v = verdict(&mut oracle, &case);
        text.push_str(&line(&case, &v));
        text.push('\n');
    }
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_SIGN_VECTORS") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/sign_precondition_vectors.txt differs from its construction");
    }
}
