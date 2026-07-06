// SPDX-License-Identifier: ISC
//! Replay of dcrd's mempool relay policy verdicts generated inside
//! dcrd's internal/mempool package (`data/policy_vectors.txt`):
//! minimum required relay fees over dcrd's own table plus boundary
//! and overflow cases, dust determinations around the canonical 6030
//! atom boundary with wrapped arithmetic, output script standardness
//! over multisig limits and script versions, full transaction
//! standardness over dcrd's own test table shapes, and input
//! standardness over a real utxo viewpoint including the vote and
//! treasury spend first-input skips.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use dcroxide_mempool::{
    calc_min_required_tx_relay_fee, check_inputs_standard, check_pk_script_standard,
    check_transaction_standard, is_dust,
};
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdscript::determine_script_type;
use dcroxide_wire::{MsgTx, TxOut};

fn tx_type(v: &str) -> TxType {
    match v {
        "0" => TxType::Regular,
        "1" => TxType::SStx,
        "2" => TxType::SSGen,
        "3" => TxType::SSRtx,
        "4" => TxType::TAdd,
        "5" => TxType::TSpend,
        "6" => TxType::TreasuryBase,
        other => panic!("unknown tx type {other}"),
    }
}

#[test]
fn policy_vectors() {
    let data = include_str!("data/policy_vectors.txt");
    let mut counts = [0usize; 5];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "fee" => {
                // fee <size> <relayfee> <want>
                let size: i64 = f[1].parse().expect("size");
                let relay: i64 = f[2].parse().expect("relay");
                let got = calc_min_required_tx_relay_fee(size, relay);
                assert_eq!(got.to_string(), f[3], "{line}");
                counts[0] += 1;
            }
            "dust" => {
                // dust <value> <version> <scripthex> <relayfee> <want>
                let out = TxOut {
                    value: f[1].parse().expect("value"),
                    version: f[2].parse().expect("version"),
                    pk_script: unhex(f[3]),
                };
                let relay: i64 = f[4].parse().expect("relay");
                assert_eq!(is_dust(&out, relay).to_string(), f[5], "{line}");
                counts[1] += 1;
            }
            "pks" => {
                // pks <version> <scripthex> <verdict>
                let version: u16 = f[1].parse().expect("version");
                let script = unhex(f[2]);
                let script_type = determine_script_type(version, &script);
                let kind = match check_pk_script_standard(version, &script, script_type) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind_name().to_string(),
                };
                assert_eq!(kind, f[3], "{line}");
                counts[2] += 1;
            }
            "txstd" => {
                // txstd <txhex> <type> <height> <mediantime> <relay> <verdict>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let kind = match check_transaction_standard(
                    &tx,
                    tx_type(f[2]),
                    f[3].parse().expect("height"),
                    f[4].parse().expect("median time"),
                    f[5].parse().expect("relay"),
                ) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind_name().to_string(),
                };
                assert_eq!(kind, f[6], "{line}");
                counts[3] += 1;
            }
            "inpstd" => {
                // inpstd <txhex> <type> <treasury> <entriescsv> <verdict>
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let treasury = f[3] == "true";
                let mut entries = HashMap::new();
                for (tx_in, entry) in tx.tx_in.iter().zip(f[4].split(',')) {
                    if entry == "-" {
                        continue;
                    }
                    let (ver, script) = entry.split_once('|').expect("entry");
                    let key = (
                        tx_in.previous_out_point.hash,
                        tx_in.previous_out_point.index,
                        tx_in.previous_out_point.tree,
                    );
                    entries.insert(key, (ver.parse::<u16>().expect("ver"), unhex(script)));
                }
                let kind = match check_inputs_standard(
                    &tx,
                    tx_type(f[2]),
                    |op| entries.get(&(op.hash, op.index, op.tree)).cloned(),
                    treasury,
                ) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind_name().to_string(),
                };
                assert_eq!(kind, f[5], "{line}");
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [16, 13, 14, 18, 8], "row counts");
}
