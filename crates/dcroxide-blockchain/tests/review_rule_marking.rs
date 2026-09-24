// SPDX-License-Identifier: ISC
//! Only consensus rule violations brand a block invalid (review
//! finding B2-p#3).
//!
//! dcrd's reorganization and acceptance paths call
//! `MarkBlockFailedValidation` only when `errors.As(err, &RuleError)`
//! (`chain.go:1220-1243`, `process.go:377-381`).  A corrupt spend
//! journal row is `database.ErrCorruption`, not a `RuleError`, so the
//! reorg fails but the block stays a candidate and is retried once the
//! row is repaired.  The port carries that failure as
//! `ErrUtxoBackendCorruption`, a kind `is_rule_violation` excludes, but
//! marked the block -- and every descendant -- invalid on any error.

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

#[test]
fn a_corrupt_parent_journal_does_not_brand_the_disapproving_child() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let mut now = 0;
    let mut by_label = std::collections::BTreeMap::new();
    let mut bdt6 = None;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                by_label.insert(f[1].to_string(), block.header.block_hash());
                if f[1] == "bdt6" {
                    bdt6 = Some(block);
                    break;
                }
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }
    let bdt6 = bdt6.expect("bdt6 in the battery");

    // bdt4 disapproves brt7, so connecting it reads brt7's spend
    // journal to restore the disapproved regular tree.  Damage that row.
    let brt7 = by_label["brt7"];
    let row = chain
        .spend_journal
        .get_mut(&brt7.0)
        .expect("brt7's journal row");
    assert!(row.len() > 1, "brt7 spends outputs");
    row.truncate(row.len() / 2);

    // bdt6 makes the disapproving branch the most-work chain, so the
    // reorg attaches bdt4 and hits the damaged row.
    let (_, errs) = chain.process_block(&bdt6, now, &params);
    assert!(
        errs.iter()
            .any(|e| e.kind == RuleErrorKind::UtxoBackendCorruption),
        "the reorg must fail on the corrupt row: {errs:?}"
    );

    let status = |label: &str| {
        let node = chain.index.lookup_node(&by_label[label]).expect("node");
        chain.store.node(node).status
    };
    assert!(
        !status("bdt4").known_invalid(),
        "local corruption branded the valid disapproving block invalid"
    );
    assert!(
        !status("bdt5").known_invalid() && !status("bdt6").known_invalid(),
        "the valid block's descendants were marked with an invalid ancestor"
    );
}
