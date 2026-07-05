// SPDX-License-Identifier: ISC
//! Replay of dcrd's headers-first processing generated inside dcrd's
//! internal/blockchain package (`data/processheaders_vectors.txt`):
//! a 30-header simnet chain fed through `maybeAcceptBlockHeader` over
//! a real block index, covering acceptance, duplicates, orphan
//! headers, sanity and positional failures (with and without the
//! sanity checks), assumed-valid node discovery, automatic fork
//! rejection checkpoint discovery with `ErrForkTooOld` enforcement,
//! known-invalid branch short circuits after a mid-chain
//! invalidation, and the clamped assume-valid ancestry checks —
//! comparing the verdict, node creation, node status byte, best
//! header, assumed valid height, and checkpoint height at every step.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::blockindex::NodeId;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::BlockHeader;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn kind_of(result: &Result<NodeId, RuleError>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

fn check_state(chain: &Chain, f: &[&str], off: usize, line: &str) {
    let best = chain.index.best_header().expect("best header");
    assert_eq!(
        chain.store.node(best).hash,
        parse_hash(f[off]),
        "{line}: best header"
    );
    let avh = chain
        .assume_valid_node
        .map(|n| chain.store.node(n).height.to_string())
        .unwrap_or_else(|| "-".to_string());
    assert_eq!(avh, f[off + 1], "{line}: assume valid height");
    let rfh = chain
        .reject_forks_checkpoint
        .map(|n| chain.store.node(n).height.to_string())
        .unwrap_or_else(|| "-".to_string());
    assert_eq!(rfh, f[off + 2], "{line}: checkpoint height");
}

#[test]
fn processheaders_vectors() {
    let mut params = simnet_params();
    let data = include_str!("data/processheaders_vectors.txt");

    let mut now: i64 = 0;
    let mut chain: Option<Chain> = None;
    let mut counts = [0usize; 3];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "cfg" => {
                // cfg <hard-coded assumevalid> <config assumevalid>
                //   <allowoldforks> <expected2wks>
                params.assume_valid = parse_hash(f[1]);
                let mut c = Chain::new(&params, parse_hash(f[2]), false);
                assert_eq!(c.allow_old_forks.to_string(), f[3], "allow old forks");
                c.expected_blocks_in_two_weeks = f[4].parse().expect("e2w");
                chain = Some(c);
            }
            "hdr" => {
                // hdr <checksanity> <hex> <kind> <isnew> <status|->
                //   <besthdr> <avh|-> <rfcph|->
                let chain = chain.as_mut().expect("cfg first");
                let check_sanity: bool = f[1].parse().expect("checksanity");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                let hash = header.block_hash();
                let existed = chain.index.lookup_node(&hash).is_some();
                let result = chain.maybe_accept_block_header(&header, check_sanity, now, &params);
                assert_eq!(kind_of(&result), f[3], "{line}");
                let node = chain.index.lookup_node(&hash);
                let is_new = u8::from(!existed && node.is_some());
                assert_eq!(is_new.to_string(), f[4], "{line}: isnew");
                let status = node
                    .map(|n| chain.store.node(n).status.0.to_string())
                    .unwrap_or_else(|| "-".to_string());
                assert_eq!(status, f[5], "{line}: status");
                check_state(chain, &f, 6, line);
                counts[0] += 1;
            }
            "mark" => {
                // mark <hash> <besthdr> <avh|-> <rfcph|->
                let chain = chain.as_mut().expect("cfg first");
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("marked node");
                chain
                    .index
                    .mark_block_failed_validation(&mut chain.store, node);
                check_state(chain, &f, 2, line);
                counts[1] += 1;
            }
            "avcheck" => {
                // avcheck <hash> <bool>
                let chain = chain.as_ref().expect("cfg first");
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("checked node");
                assert_eq!(
                    chain.is_assume_valid_ancestor(node).to_string(),
                    f[2],
                    "{line}"
                );
                counts[2] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [43, 1, 4], "row counts");
}
