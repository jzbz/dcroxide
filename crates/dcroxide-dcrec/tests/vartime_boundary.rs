// SPDX-License-Identifier: ISC
//! Who may reach `dcroxide-secp256k1-vartime` (ADR-0016).  Its arithmetic
//! is variable time, for public values only, so the guards are where it
//! is named:
//!
//! - among the workspace members and the fuzz crate, only dcroxide-dcrec,
//!   dcroxide-bench and the fuzz crate may take it as a dependency other
//!   than a dev-dependency, and no manifest may rename it, which would
//!   hide it from the source scans below;
//! - inside dcroxide-dcrec only `src/secp256k1/backend.rs`, the seam, may
//!   name it, and only the functions in [`MAY_USE_SEAM`] (verification and
//!   recovery) may name the seam, so the signing functions (`sign*`,
//!   `PrivateKey::public_key`, the nonce) reach neither;
//! - the crate itself takes no dependency at all, and its code outside the
//!   tests names neither `alloc` nor `std`.
//!
//! dcroxide-sigdiff, whose models must stay independent of the code under
//! test, has its own rule against naming it (its `tests/independence.rs`);
//! the rename rule here covers its manifest too.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "byte offsets and counters within one source file's length"
)]

use std::path::{Path, PathBuf};

/// The crate's package name, as manifests write it.
const PACKAGE: &str = "dcroxide-secp256k1-vartime";

/// The crate's name in Rust source.
const IDENT: &str = "dcroxide_secp256k1_vartime";

/// The manifests that may take it as a normal dependency.
const MAY_DEPEND: [&str; 3] = [
    "crates/dcroxide-dcrec/Cargo.toml",
    "crates/dcroxide-bench/Cargo.toml",
    "fuzz/Cargo.toml",
];

/// The functions of dcrec's `src/` that may name the seam module, `backend`
/// (file under `src/`, function name).  Each must exist and name it.
const MAY_USE_SEAM: [(&str, &str); 2] = [
    ("secp256k1/ecdsa.rs", "verify_detailed"),
    ("secp256k1/ecdsa.rs", "recover_compact"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The workspace members the root manifest lists.
fn members(root: &Path) -> Vec<String> {
    let text = read(&root.join("Cargo.toml"));
    let start = text.find("members = [").expect("a members list");
    let rest = &text[start..];
    let end = rest.find(']').expect("the members list ends");
    rest[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim().trim_end_matches(',');
            l.strip_prefix('"')
                .and_then(|l| l.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

/// Whether a manifest line, spaces removed, renames the crate
/// (`package = "dcroxide-secp256k1-vartime"`, inline or in a table).
fn renames(line: &str) -> bool {
    let t: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    t.contains(&format!("package=\"{PACKAGE}\"")) || t.contains(&format!("package='{PACKAGE}'"))
}

/// The kinds of dependency a manifest takes the crate as: "normal" for
/// `[dependencies]`, `[build-dependencies]` and their `[target.*]` forms,
/// "dev" for `[dev-dependencies]` and theirs, with the table form
/// (`[dependencies.dcroxide-secp256k1-vartime]`) and renamed entries
/// included.
fn dependency_kinds(manifest: &str) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.trim_matches(|c| c == '[' || c == ']').to_owned();
            if section.ends_with(&format!(".{PACKAGE}")) {
                kinds.push(kind_of(&section));
            }
            continue;
        }
        let key = t.split(['=', ' ', '.']).next().unwrap_or("");
        if key == PACKAGE || renames(t) {
            kinds.push(kind_of(&section));
        }
    }
    kinds
}

fn kind_of(section: &str) -> &'static str {
    if section.contains("dev-dependencies") {
        "dev"
    } else if section.contains("dependencies") {
        "normal"
    } else {
        "other"
    }
}

/// The dependencies other than dev-dependencies a manifest declares: every
/// table whose name says dependencies but not dev-dependencies
/// (`[dependencies]`, `[dependencies.foo]`, `[build-dependencies]`, the
/// `[target.*]` forms), with an entry in it, and every such dotted key at
/// the top level.
fn normal_dependencies(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut section: Option<String> = None;
    for line in manifest.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let name = t.trim_matches(|c| c == '[' || c == ']').to_owned();
            if kind_of(&name) == "normal" {
                out.push(name.clone());
            }
            section = Some(name);
            continue;
        }
        if section.is_none() {
            let key = t.split('=').next().unwrap_or("");
            if kind_of(key) == "normal" {
                out.push(key.trim().to_owned());
            }
        }
    }
    out
}

/// Every `.rs` file under `dir`, relative to it, sorted.
fn rust_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read a source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path.strip_prefix(dir).expect("under the directory");
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

/// Rust source with every comment, string and character literal blanked
/// to spaces, newlines kept, so that what is left is code and its line
/// numbers are the file's.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        let rest = &b[i..];
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|&c| c == b'\n')
                .map_or(b.len(), |p| i + p);
            blank(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let (mut j, mut depth) = (i + 2, 1);
            while j < b.len() && depth > 0 {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if b[i] == b'r' && (i == 0 || !ident(b[i - 1])) && {
            let hashes = rest[1..].iter().take_while(|&&c| c == b'#').count();
            rest.get(1 + hashes) == Some(&b'"')
        } {
            let hashes = rest[1..].iter().take_while(|&&c| c == b'#').count();
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = i + 2 + hashes;
            let end = b[body..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |p| body + p + close.len());
            blank(&mut out, i, end);
            i = end;
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            blank(&mut out, i, end);
            i = end;
        } else if b[i] == b'\'' {
            // A character literal ('x', '\n', '\u{..}'), not a lifetime.
            let end = if rest.get(1) == Some(&b'\\') {
                rest[2..]
                    .iter()
                    .position(|&c| c == b'\'')
                    .map(|p| i + 3 + p)
            } else {
                let ch = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                (rest.get(1 + ch) == Some(&b'\'')).then_some(i + 2 + ch)
            };
            match end {
                Some(end) => {
                    blank(&mut out, i, end);
                    i = end;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8")
}

/// The byte offsets of `word` in `code` as a whole identifier.
fn word_offsets(code: &str, word: &str) -> Vec<usize> {
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = code.as_bytes();
    code.match_indices(word)
        .map(|(i, _)| i)
        .filter(|&i| {
            (i == 0 || !ident(b[i - 1])) && b.get(i + word.len()).is_none_or(|&c| !ident(c))
        })
        .collect()
}

/// Every function in `code` (comments and literals blanked) as (name,
/// byte range of its body, braces included).
fn functions(code: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for at in word_offsets(code, "fn") {
        let name: String = code[at + 2..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue; // a `fn(..)` pointer type
        }
        // The body opens at the first `{` outside parentheses and brackets
        // (the parameters, an array type); a `;` first means a declaration
        // without one.
        let mut depth = 0i32;
        let mut open = None;
        for (k, &c) in b.iter().enumerate().skip(at) {
            match c {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b'{' if depth == 0 => {
                    open = Some(k);
                    break;
                }
                b';' if depth == 0 => break,
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        let mut level = 0u32;
        let mut close = None;
        for (k, &c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => level += 1,
                b'}' => {
                    level -= 1;
                    if level == 0 {
                        close = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("a function body closes");
        out.push((name, open..close + 1));
    }
    out
}

/// Where dcrec's `src/` names the seam module outside the functions that
/// may (`MAY_USE_SEAM`) and outside `mod backend;`, as "file:line"; and
/// each allowed function with how many times it names it.
fn seam_uses(src: &Path, files: &[String]) -> (Vec<String>, Vec<(String, usize)>) {
    let mut stray = Vec::new();
    let mut allowed: Vec<(String, usize)> = MAY_USE_SEAM
        .iter()
        .map(|(f, n)| (format!("{f}::{n}"), 0))
        .collect();
    for f in files.iter().filter(|f| *f != "secp256k1/backend.rs") {
        let code = code_only(&read(&src.join(f)));
        let fns = functions(&code);
        for at in word_offsets(&code, "backend") {
            let line = code[..at].matches('\n').count() + 1;
            let decl = code[..at].trim_end().ends_with("mod")
                && code[at + "backend".len()..].trim_start().starts_with(';');
            if decl && f == "secp256k1.rs" {
                continue;
            }
            // The innermost function around this use.
            let inner = fns
                .iter()
                .filter(|(_, r)| r.contains(&at))
                .min_by_key(|(_, r)| r.len());
            let key = inner.map(|(n, _)| format!("{f}::{n}"));
            match allowed.iter_mut().find(|(k, _)| Some(k) == key.as_ref()) {
                Some((_, n)) => *n += 1,
                None => stray.push(format!("{f}:{line}")),
            }
        }
    }
    (stray, allowed)
}

#[test]
fn only_dcrec_bench_and_fuzz_depend_on_the_vartime_crate() {
    let root = repo_root();
    let mut manifests: Vec<String> = members(&root)
        .into_iter()
        .map(|m| format!("{m}/Cargo.toml"))
        .collect();
    assert!(
        manifests.len() > 30,
        "the members list is too short: {manifests:?}"
    );
    assert!(manifests.contains(&format!("crates/{PACKAGE}/Cargo.toml")));
    manifests.push("fuzz/Cargo.toml".to_owned());
    let mut normal = Vec::new();
    for m in &manifests {
        let text = read(&root.join(m));
        assert!(
            !text.lines().any(renames),
            "{m} renames {PACKAGE}, which would hide it from the source scans"
        );
        let kinds = dependency_kinds(&text);
        assert!(
            !kinds.contains(&"other"),
            "{m} names {PACKAGE} outside a dependency table"
        );
        if kinds.contains(&"normal") {
            normal.push(m.clone());
        }
    }
    for m in &normal {
        assert!(
            MAY_DEPEND.contains(&m.as_str()),
            "{m} depends on {PACKAGE}; only {MAY_DEPEND:?} may"
        );
    }
    assert!(
        normal.contains(&"crates/dcroxide-dcrec/Cargo.toml".to_owned()),
        "dcrec depends on {PACKAGE}"
    );
    let own = read(&root.join("crates").join(PACKAGE).join("Cargo.toml"));
    assert_eq!(
        normal_dependencies(&own),
        Vec::<String>::new(),
        "{PACKAGE} takes no dependency"
    );
}

#[test]
fn only_the_seam_names_the_vartime_crate_in_dcrec() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&src);
    assert!(
        files.contains(&"secp256k1/ecdsa.rs".to_owned()),
        "{files:?}"
    );
    let naming: Vec<&String> = files
        .iter()
        .filter(|f| read(&src.join(f)).contains(IDENT))
        .collect();
    assert_eq!(naming, ["secp256k1/backend.rs"], "files naming {IDENT}");
}

/// Only verification and recovery reach the seam: every use of `backend`
/// in dcrec's code is `mod backend;` or inside a function of
/// `MAY_USE_SEAM`, and each of those exists and uses it, so a signing
/// function that called the seam, or an import that let it do so
/// without naming it, fails here.
#[test]
fn only_verification_and_recovery_reach_the_seam() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let (stray, allowed) = seam_uses(&src, &rust_files(&src));
    assert!(
        stray.is_empty(),
        "the seam is named outside {MAY_USE_SEAM:?}: {stray:?}"
    );
    for (f, n) in &allowed {
        assert!(
            *n > 0,
            "{f} does not name the seam (renamed, or the list is stale)"
        );
    }
    let ecdsa = code_only(&read(&src.join("secp256k1/ecdsa.rs")));
    let names: Vec<String> = functions(&ecdsa).into_iter().map(|(n, _)| n).collect();
    for signer in ["sign", "sign_compact", "sign_with_nonce"] {
        assert!(
            names.iter().any(|n| n == signer),
            "ecdsa.rs has no fn {signer}"
        );
    }
}

/// The crate's code outside its tests names neither `alloc` nor `std`, so
/// it builds on `core` alone, as ADR-0016 and its crate doc say.
#[test]
fn the_vartime_crate_needs_core_alone() {
    let src = repo_root().join("crates").join(PACKAGE).join("src");
    let files: Vec<String> = rust_files(&src)
        .into_iter()
        .filter(|f| !f.starts_with("tests/"))
        .collect();
    assert!(files.contains(&"lib.rs".to_owned()), "{files:?}");
    assert!(read(&src.join("lib.rs")).contains("#![cfg_attr(not(test), no_std)]"));
    for f in &files {
        let code = code_only(&read(&src.join(f)));
        for word in ["alloc", "std"] {
            let lines: Vec<usize> = word_offsets(&code, word)
                .into_iter()
                .map(|at| code[..at].matches('\n').count() + 1)
                .collect();
            assert!(lines.is_empty(), "{f} names {word} on lines {lines:?}");
        }
    }
}

/// The detector reads both dependency forms and both kinds, renames, and
/// the no-dependency rule's table forms.
#[test]
fn the_manifest_reader_sees_every_form() {
    let normal = "[dependencies]\ndcroxide-secp256k1-vartime = { path = \"x\" }\n";
    let dev = "[dev-dependencies]\ndcroxide-secp256k1-vartime = { path = \"x\" }\n";
    let table = "[dependencies.dcroxide-secp256k1-vartime]\npath = \"x\"\n";
    let target = "[target.'cfg(unix)'.dependencies]\ndcroxide-secp256k1-vartime.path = \"x\"\n";
    let other = "[dependencies]\ndcroxide-secp256k1-vartime-extra = \"1\"\n";
    let renamed =
        "[dependencies]\nvt = { package = \"dcroxide-secp256k1-vartime\", path = \"x\" }\n";
    let renamed_table = "[dependencies.vt]\npackage='dcroxide-secp256k1-vartime'\npath = \"x\"\n";
    assert_eq!(dependency_kinds(normal), ["normal"]);
    assert_eq!(dependency_kinds(dev), ["dev"]);
    assert_eq!(dependency_kinds(table), ["normal"]);
    assert_eq!(dependency_kinds(target), ["normal"]);
    assert!(dependency_kinds(other).is_empty());
    assert_eq!(dependency_kinds(renamed), ["normal"]);
    assert_eq!(dependency_kinds(renamed_table), ["normal"]);
    assert!(renamed.lines().any(renames) && renamed_table.lines().any(renames));
    assert!(!normal.lines().any(renames));

    let own = "[package]\nname = \"x\"\n\n[dev-dependencies]\nk256 = \"1\"\n\n[features]\ninternals = []\n";
    assert!(normal_dependencies(own).is_empty());
    for (text, want) in [
        ("[dependencies]\n", "dependencies"),
        ("[dependencies.foo]\nversion = \"1\"\n", "dependencies.foo"),
        ("[build-dependencies]\ncc = \"1\"\n", "build-dependencies"),
        (
            "[target.'cfg(unix)'.dependencies]\nlibc = \"1\"\n",
            "target.'cfg(unix)'.dependencies",
        ),
        ("dependencies.foo = \"1\"\n[package]\n", "dependencies.foo"),
    ] {
        assert_eq!(normal_dependencies(text), [want], "{text}");
    }
}

/// The source reader blanks comments and literals, finds whole words and
/// function bodies, and places a seam use in its function.
#[test]
fn the_source_reader_sees_code_only() {
    let src = "// backend\nfn a() { let s = \"backend}\"; let c = '}'; }\n\
               /* fn b() { backend } */ fn c<'x>(v: &'x [u8; 2]) -> u8 { backend::f(v) }\n\
               fn d(); fn e() { r#\"backend\"#; mybackend(); }\n";
    let code = code_only(src);
    assert_eq!(code.len(), src.len());
    assert_eq!(code.matches('\n').count(), src.matches('\n').count());
    let uses = word_offsets(&code, "backend");
    assert_eq!(uses.len(), 1, "{code}");
    let fns = functions(&code);
    let names: Vec<&str> = fns.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a", "c", "e"]);
    let (_, c_body) = &fns[1];
    assert!(c_body.contains(&uses[0]));
    assert!(!fns[0].1.contains(&uses[0]) && !fns[2].1.contains(&uses[0]));
}
