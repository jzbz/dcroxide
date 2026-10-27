// SPDX-License-Identifier: ISC
//! The witness file `dcroxide-dcrec` keeps
//! (`crates/dcroxide-dcrec/tests/data/sigdiff_witness_vectors.txt`) held
//! to this crate.  Without the oracle: each vector line's variant and
//! request are what its class generates at the witness seed, so the
//! generators cannot drift from the file unnoticed; every witness class
//! has exactly its listed lines; and the header names the seed and the
//! parity pin, so a pin move that leaves the file behind fails.  With the
//! oracle: emitting the lines again gives the file's.

use std::collections::BTreeSet;

use dcroxide_sigdiff::class::{find_class, generate};
use dcroxide_sigdiff::pipe::PipeConfig;
use dcroxide_sigdiff::witness::{
    WITNESS_CLASSES, WITNESS_SEED, WitnessLine, bucket, emit, vector_lines,
};
use dcroxide_testutil::{DCRD_PARITY_COMMIT, oracle_bin_or_skip};

/// The committed file.
const FILE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dcroxide-dcrec/tests/data/sigdiff_witness_vectors.txt"
));

#[test]
fn the_vector_lines_are_the_generators() {
    let mut lines = Vec::new();
    for text in vector_lines(FILE) {
        let line = WitnessLine::parse(text).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(line.to_string(), text, "the line reads back as written");
        let class = find_class(line.class).expect("a registered class");
        let case = generate(class, WITNESS_SEED, line.index);
        assert_eq!(line.variant, case.variant, "{text}");
        let [request] = &case.requests[..] else {
            panic!("{text}: the case has {} requests", case.requests.len());
        };
        assert_eq!(
            (line.cmd, &line.data),
            (request.cmd, &request.data),
            "{text}"
        );
        lines.push(line);
    }

    // Each class's lines are its listed pairs, one each, by case index.
    for witness in WITNESS_CLASSES {
        let of_class: Vec<&WitnessLine> =
            lines.iter().filter(|l| l.class == witness.name).collect();
        let pairs: BTreeSet<(&str, bool)> = of_class
            .iter()
            .map(|l| {
                let accepts = l.answer == "true" || l.answer.starts_with("ok:");
                (bucket(&l.variant), accepts)
            })
            .collect();
        let listed: BTreeSet<(&str, bool)> = witness.lines.iter().copied().collect();
        assert_eq!(pairs, listed, "{}", witness.name);
        assert_eq!(of_class.len(), witness.lines.len(), "{}", witness.name);
        assert!(
            of_class.is_sorted_by_key(|l| l.index),
            "{}: by case index",
            witness.name
        );
    }
    assert!(
        lines
            .iter()
            .all(|l| WITNESS_CLASSES.iter().any(|w| w.name == l.class)),
        "a line of a class that is no witness class"
    );

    let header: Vec<&str> = FILE
        .lines()
        .take_while(|l| l.starts_with('#'))
        .flat_map(|l| l.trim_start_matches('#').split_whitespace())
        .collect();
    let header = header.join(" ");
    assert!(
        header.contains(&format!(
            "at the parity pin {DCRD_PARITY_COMMIT} through tools/oracle"
        )),
        "the header names the pin {DCRD_PARITY_COMMIT}:\n{header}"
    );
    assert!(
        header.contains(&format!(
            "`sigsoak emit-corpus --seed {WITNESS_SEED:#018x}`"
        )),
        "the header names the seed:\n{header}"
    );
}

/// The lines `sigsoak emit-corpus` writes, emitted in memory through its
/// code path, are the committed file's vector lines; neither the header
/// nor a line ending can make this fail.
#[test]
fn witness_file_regenerates() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let emitted: Vec<String> = emit(WITNESS_SEED, &PipeConfig::new(oracle))
        .unwrap_or_else(|e| panic!("{e}"))
        .iter()
        .map(ToString::to_string)
        .collect();
    let committed: Vec<&str> = vector_lines(FILE).collect();
    assert_eq!(emitted, committed);
}
