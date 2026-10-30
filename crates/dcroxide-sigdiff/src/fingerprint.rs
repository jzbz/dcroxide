// SPDX-License-Identifier: ISC
//! The generator fingerprint, and the check that a binary's source is the
//! checkout's.
//!
//! Every file under `src/` is in exactly one of three lists:
//!
//! - [`FROZEN`]: everything that decides a case's inputs, dcrd's
//!   normalized answer, the comparison, the status and the digest leaf, and
//!   the canaries that stand in for dcroxide.
//!   These do not change between the baseline soak and the gate soak, and
//!   [`fingerprint`] is a digest of them.
//! - [`ADAPTER`]: `src/ours.rs`, which reaches the code under test and
//!   changes as its API grows.
//! - [`PLUMBING`]: modules that decide no soak case's input, answer,
//!   comparison or status (the pipe, the run loop, the record, the CLI).
//!   The fuzz entry (`src/fuzz.rs`) is plumbing too: it decides those
//!   things for fuzz inputs only, and no soak run, digest, witness or gate
//!   run passes through it.
//!
//! Each file's bytes are embedded at compile time, so the fingerprint
//! describes the binary that runs, needs no git and cannot be stale.  The
//! repository's `.gitattributes` forces LF line endings, so it is the same
//! on every OS.  A unit test fails, naming the file, when a file under
//! `src/` is in no list or a listed file is gone: a new module has to be
//! placed in one before anything builds on it.

use std::path::Path;

use dcroxide_crypto::blake256::Blake256;

/// One source file of this crate, as compiled into the binary.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    /// Its path below the crate's directory, `/`-separated.
    pub path: &'static str,
    /// Its bytes.
    pub bytes: &'static [u8],
}

macro_rules! sources {
    ($($path:literal),* $(,)?) => {
        &[$(Source {
            path: $path,
            bytes: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/", $path)),
        }),*]
    };
}

/// The frozen modules, which the fingerprint covers.
pub static FROZEN: &[Source] = sources![
    "src/answer.rs",
    "src/arith.rs",
    "src/canary.rs",
    "src/class.rs",
    "src/cmd.rs",
    "src/compare.rs",
    "src/digest.rs",
    "src/entropy.rs",
    "src/gen/der.rs",
    "src/gen/ecdsa.rs",
    "src/gen/ed25519.rs",
    "src/gen/kwrap_points.rs",
    "src/gen/mod.rs",
    "src/gen/pubkey.rs",
    "src/gen/recover.rs",
    "src/gen/schnorr.rs",
    "src/model/ecdsa.rs",
    "src/model/ed25519.rs",
    "src/model/mod.rs",
    "src/model/schnorr.rs",
    "src/reply.rs",
];

/// The adapter to the code under test.
pub static ADAPTER: &[Source] = sources!["src/ours.rs"];

/// The plumbing.
pub static PLUMBING: &[Source] = sources![
    "src/bin/sigsoak.rs",
    "src/fingerprint.rs",
    "src/fuzz.rs",
    "src/lib.rs",
    "src/manifest.rs",
    "src/pipe.rs",
    "src/record.rs",
    "src/run.rs",
    "src/witness.rs",
];

/// Every embedded file, frozen, adapter and plumbing.
pub fn all_sources() -> impl Iterator<Item = &'static Source> {
    FROZEN.iter().chain(ADAPTER).chain(PLUMBING)
}

/// The generator fingerprint: BLAKE-256 over `"sigdiff-fingerprint-1"`
/// followed, for each [`FROZEN`] file in byte order of its path, by
/// `u16be(len path) ‖ path ‖ u32be(len bytes) ‖ bytes`.
pub fn fingerprint() -> [u8; 32] {
    fingerprint_of(FROZEN)
}

fn fingerprint_of(files: &[Source]) -> [u8; 32] {
    let mut sorted: Vec<&Source> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut h = Blake256::new();
    h.update(b"sigdiff-fingerprint-1");
    for file in sorted {
        h.update(
            &u16::try_from(file.path.len())
                .expect("a short path")
                .to_be_bytes(),
        );
        h.update(file.path.as_bytes());
        h.update(
            &u32::try_from(file.bytes.len())
                .expect("a source under 4 GiB")
                .to_be_bytes(),
        );
        h.update(file.bytes);
    }
    h.finalize()
}

/// The `.rs` files under `crate_dir/src`, as `/`-separated paths below
/// `crate_dir`, sorted.
pub fn source_files(crate_dir: &Path) -> std::io::Result<Vec<String>> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = format!("{prefix}/{name}");
            if entry.file_type()?.is_dir() {
                walk(&entry.path(), &path, out)?;
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(&crate_dir.join("src"), "src", &mut out)?;
    out.sort();
    Ok(out)
}

/// The embedded files that differ from the same paths under `crate_dir`
/// (this crate's directory in a checkout), and the source files there the
/// binary does not embed, each with why.  Empty when the binary was built
/// from that checkout as it stands.
pub fn source_differences(crate_dir: &Path) -> Vec<String> {
    let mut differs = Vec::new();
    for file in all_sources() {
        match std::fs::read(crate_dir.join(file.path)) {
            Ok(bytes) if bytes == file.bytes => {}
            Ok(_) => differs.push(format!("{} differs", file.path)),
            Err(e) => differs.push(format!("{} unreadable: {e}", file.path)),
        }
    }
    match source_files(crate_dir) {
        Ok(files) => {
            for path in files {
                if !all_sources().any(|file| file.path == path) {
                    differs.push(format!("{path} is not in the binary"));
                }
            }
        }
        Err(e) => differs.push(format!("src/ unreadable: {e}")),
    }
    differs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every file under `src/` is in exactly one list, so a new module has
    /// to be classified before anything builds on it.
    #[test]
    fn the_lists_partition_the_sources() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let on_disk: BTreeSet<String> = source_files(crate_dir)
            .expect("read src/")
            .into_iter()
            .collect();
        let mut listed = BTreeSet::new();
        for file in all_sources() {
            assert!(
                listed.insert(file.path.to_owned()),
                "{} is listed twice",
                file.path
            );
        }
        let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
        assert!(
            unlisted.is_empty(),
            "{unlisted:?} in no list of src/fingerprint.rs: classify them"
        );
        let gone: Vec<&String> = listed.difference(&on_disk).collect();
        assert!(
            gone.is_empty(),
            "{gone:?} listed in src/fingerprint.rs but gone"
        );
    }

    /// The lists are the freeze rule: every file under `src/gen/` and
    /// `src/model/` and each top-level module that decides an input, an
    /// answer as compared, a status or a leaf is frozen, and nothing else
    /// is; `src/ours.rs` alone is the adapter.  Moving a frozen file to
    /// another list, which would leave it out of the fingerprint, fails
    /// here.
    #[test]
    fn the_lists_are_the_freeze_rule() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let top_level = [
            "src/answer.rs",
            "src/arith.rs",
            "src/canary.rs",
            "src/class.rs",
            "src/cmd.rs",
            "src/compare.rs",
            "src/digest.rs",
            "src/entropy.rs",
            "src/reply.rs",
        ];
        let want: BTreeSet<String> = source_files(crate_dir)
            .expect("read src/")
            .into_iter()
            .filter(|path| {
                path.starts_with("src/gen/")
                    || path.starts_with("src/model/")
                    || top_level.contains(&path.as_str())
            })
            .collect();
        let frozen: BTreeSet<String> = FROZEN.iter().map(|f| f.path.to_owned()).collect();
        assert_eq!(frozen, want);
        assert!(top_level.iter().all(|path| frozen.contains(*path)));
        let adapter: Vec<&str> = ADAPTER.iter().map(|f| f.path).collect();
        assert_eq!(adapter, ["src/ours.rs"]);
    }

    /// The test binary was built from this tree, so its embedded source
    /// matches it, and the fingerprint is the documented digest of the
    /// frozen files as they are on disk.
    #[test]
    fn the_fingerprint_covers_the_frozen_files() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(source_differences(crate_dir), Vec::<String>::new());
        let mut h = Blake256::new();
        h.update(b"sigdiff-fingerprint-1");
        let mut paths: Vec<&str> = FROZEN.iter().map(|f| f.path).collect();
        paths.sort_unstable();
        for path in paths {
            let bytes = std::fs::read(crate_dir.join(path)).expect("read a frozen file");
            h.update(&u16::try_from(path.len()).expect("short").to_be_bytes());
            h.update(path.as_bytes());
            h.update(&u32::try_from(bytes.len()).expect("small").to_be_bytes());
            h.update(&bytes);
        }
        assert_eq!(fingerprint(), h.finalize());
        // Order-independent in the list, dependent on every byte.
        let reversed: Vec<Source> = FROZEN.iter().rev().copied().collect();
        assert_eq!(fingerprint_of(&reversed), fingerprint());
        assert_ne!(fingerprint_of(&FROZEN[1..]), fingerprint());
    }
}
