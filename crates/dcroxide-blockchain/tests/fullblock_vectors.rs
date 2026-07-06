// SPDX-License-Identifier: ISC
//! Replay of dcrd's full block test battery
//! (`data/fullblock_vectors.txt`): every test instance produced by
//! dcrd's own `fullblocktests.Generate` — a scripted regression
//! network chain of fully signed blocks with real tickets, votes,
//! revocations, and reorganizations alongside hundreds of
//! specifically invalid variants with their expected rejection
//! kinds — driven through the chain engine with full validation
//! including script execution, exactly like dcrd's own
//! `TestFullBlocks` driver.  This is the single broadest
//! cross-validation of the consensus engine in the repository.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

#[test]
fn fullblock_vectors() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/fullblock_vectors.txt");
    // The battery is generated relative to the wall clock (the
    // too-far-in-the-future block), so the dump records its
    // generation time for the replay to use as its current time.
    let mut now: i64 = 0;
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                // accept <name> <mainchain> <orphan> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (fork_len, errs) = chain.process_block(&block, now, &params);
                // dcrd's driver treats a missing parent as an
                // accepted orphan.
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(
                    errs.is_empty() || is_orphan,
                    "block {name} should have been accepted: {errs:?}"
                );
                let is_main_chain = !is_orphan && fork_len == 0;
                assert_eq!(is_main_chain.to_string(), f[2], "{name}: main chain flag");
                assert_eq!(is_orphan.to_string(), f[3], "{name}: orphan flag");
                counts[0] += 1;
            }
            "reject" => {
                // reject <name> <kind> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(!errs.is_empty(), "block {name} should have been rejected");
                assert_eq!(
                    errs[0].kind.kind_name(),
                    f[2],
                    "{name}: reject kind ({})",
                    errs[0].description
                );
                counts[1] += 1;
            }
            "orphanorreject" => {
                // orphanorreject <name> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(
                    !errs.is_empty(),
                    "block {name} should have been an orphan or rejected"
                );
                counts[2] += 1;
            }
            "tip" => {
                // tip <name> <hash>
                let tip = chain.best_chain.tip().expect("tip");
                assert_eq!(
                    chain.store.node(tip).hash,
                    parse_hash(f[2]),
                    "{}: expected tip",
                    f[1]
                );
                counts[3] += 1;
            }
            "skipnano" => {
                // skipnano <name> <kind>: the nanosecond-precision
                // timestamp rejection only exists for in-memory
                // blocks — the wire encoding stores whole seconds —
                // so the instance cannot be replayed from serialized
                // bytes.
                assert_eq!(f[2], "ErrInvalidTime", "{}: skip kind", f[1]);
                counts[5] += 1;
            }
            "noncanon" => {
                // noncanon <name> <rawhex>
                assert!(
                    MsgBlock::from_bytes(&unhex(f[2])).is_err(),
                    "{}: non-canonical block should fail to decode",
                    f[1]
                );
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [204, 350, 3, 14, 1, 1], "row counts");
}
