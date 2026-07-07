// SPDX-License-Identifier: ISC
//! Replay of dcrd's TicketPoolValue battery
//! (`data/tpv_vectors.txt`): a real regnet chain built past the stake
//! validation height from dcrd's own fullblocktests generator, with
//! dcrd's real TicketPoolValue recorded.  The block bytes are frozen
//! so the chain engine here rebuilds the same chain and sums the same
//! live-ticket utxo values, comparing the total pool value and the
//! live ticket count.

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

#[test]
fn ticket_pool_value_matches_dcrd() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/tpv_vectors.txt");

    let now: i64 = data
        .lines()
        .find_map(|l| l.strip_prefix("now|"))
        .expect("now row")
        .parse()
        .unwrap();

    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("blk|") {
            let hex_block = rest.split('|').nth(1).unwrap();
            let (block, _) = MsgBlock::from_bytes(&unhex(hex_block)).expect("block");
            let (_, errs) = chain.process_block(&block, now, &params);
            assert!(errs.is_empty(), "block rejected: {errs:?}");
        }
    }

    let tpv = data
        .lines()
        .find_map(|l| l.strip_prefix("tpv|"))
        .expect("tpv row");
    let f: Vec<&str> = tpv.split('|').collect();
    let want_value: i64 = f[0].parse().unwrap();
    let want_live: usize = f[1].parse().unwrap();

    assert_eq!(chain.live_tickets().len(), want_live, "live ticket count");
    assert_eq!(
        chain.ticket_pool_value(),
        Some(want_value),
        "ticket pool value"
    );
}
