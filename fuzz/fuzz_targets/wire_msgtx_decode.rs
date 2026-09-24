// SPDX-License-Identifier: ISC
//! Transaction decoder fuzz target: must never panic, and any accepted input
//! must re-encode byte-identically to its consumed prefix (canonical-encoding
//! law). Hash computation is exercised on every accepted transaction.
//!
//! Every accepted transaction is then classified by the stake crate, as
//! relay and block validation classify every transaction they see (dcrd
//! `DetermineTxType` and the `Check*`/`Is*` family in `staketx.go` and
//! `treasury.go`). Those run on peer-supplied bytes, and under
//! `panic = "abort"` their safety rests on hand-ordered length checks ahead
//! of each index, which this reaches with adversarial shapes. Beyond not
//! panicking it checks that each `is_*` agrees with its `check_*`, that at
//! most one of the ticket, vote and revocation forms matches, and that
//! `determine_tx_type` names the first match in dcrd's order. It then runs
//! the extractors that are only safe once a form has matched
//! (`SSGenBlockVotedOn`, `SSGenVoteBits`, `SSGenVersion`,
//! `TxSStxStakeOutputInfo`), and the script parsers that take any bytes on
//! every output.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;

use dcroxide_chaincfg::Params;
use dcroxide_stake::{self as stake, TX_VERSION_TREASURY, TxType};
use dcroxide_wire::MsgTx;

static MAINNET: LazyLock<Params> = LazyLock::new(dcroxide_chaincfg::mainnet_params);

fn classify(tx: &MsgTx) {
    let sstx = stake::check_sstx(tx).is_ok();
    let ssgen = stake::check_ssgen(tx).is_ok();
    let ssrtx = stake::check_ssrtx(tx).is_ok();
    let tadd = stake::check_tadd(tx).is_ok();
    let tspend = stake::check_tspend(tx).is_ok();
    let tbase = stake::check_treasury_base(tx).is_ok();
    assert_eq!(stake::is_sstx(tx), sstx, "is_sstx vs check_sstx");
    assert_eq!(stake::is_ssgen(tx), ssgen, "is_ssgen vs check_ssgen");
    assert_eq!(
        stake::check_ssgen_votes(tx).is_ok(),
        ssgen,
        "check_ssgen_votes vs check_ssgen"
    );
    assert_eq!(stake::is_ssrtx(tx), ssrtx, "is_ssrtx vs check_ssrtx");
    assert_eq!(stake::is_tadd(tx), tadd, "is_tadd vs check_tadd");
    assert_eq!(stake::is_tspend(tx), tspend, "is_tspend vs check_tspend");
    assert_eq!(
        stake::is_treasury_base(tx),
        tbase,
        "is_treasury_base vs check_treasury_base"
    );
    assert!(
        u8::from(sstx) + u8::from(ssgen) + u8::from(ssrtx) <= 1,
        "ticket {sstx}, vote {ssgen}, revocation {ssrtx}"
    );

    let treasury = tx.version >= TX_VERSION_TREASURY;
    let want = if sstx {
        TxType::SStx
    } else if ssgen {
        TxType::SSGen
    } else if ssrtx {
        TxType::SSRtx
    } else if treasury && tadd {
        TxType::TAdd
    } else if treasury && tspend {
        TxType::TSpend
    } else if treasury && tbase {
        TxType::TreasuryBase
    } else {
        TxType::Regular
    };
    assert_eq!(stake::determine_tx_type(tx), want);

    if ssgen {
        let _ = stake::ssgen_block_voted_on(tx);
        let _ = stake::ssgen_vote_bits(tx);
        let _ = stake::ssgen_version(tx);
    }
    if sstx {
        let _ = stake::tx_sstx_stake_output_info(tx);
    }
    let _ = stake::is_stake_base(tx);
    for out in &tx.tx_out {
        let _ = stake::get_ssgen_treasury_votes(&out.pk_script);
        let _ = stake::amount_from_sstx_pk_scr_commitment(&out.pk_script);
        let _ = stake::addr_from_sstx_pk_scr_commitment(&out.pk_script, &*MAINNET);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok((tx, consumed)) = dcroxide_wire::MsgTx::from_bytes(data) {
        assert_eq!(tx.serialize().as_slice(), &data[..consumed]);
        assert_eq!(tx.serialize_size(), consumed);
        let _ = tx.tx_hash_full();
        classify(&tx);
    }
});
