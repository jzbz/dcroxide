// SPDX-License-Identifier: ISC
//! The surface a wallet links for compact filter matching: every
//! identifier dcrwallet imports from dcrd's `gcs` and `gcs/blockcf2`
//! packages, named here by its Rust counterpart.  This crate takes
//! dcroxide-stake without its `storage` feature, so a build of this
//! target with `--no-default-features`, as CI's storage-gate job makes
//! one, links neither dcroxide-database nor redb.
//!
//! The list is dcrwallet's at the commit dcr-purse pins
//! (`decred.org/dcrwallet/v5 v5.0.1-0.20261105142009-54b85b336077`):
//! every `gcs.<Name>` and `blockcf2.<Name>` its Go files name, tests
//! included (`gcs.NewFilter` appears only in its test data), and the
//! `FilterV2` and `Entries` methods it calls.  Each function is coerced
//! to a function pointer of its full type, so a change of signature
//! fails here, as it would in the wallet.
//!
//! dcrwallet calls `blockcf2.Regular` in two shapes, and both are
//! exercised here, against dcrd through the oracle when it is present.
//! Its non-test code (`wallet/udb/upgrades.go`) builds only the genesis
//! block's filter, with a `PrevScripter` that knows no output.  Its reorg
//! tests (`wallet/reorg_test.go`) build the filters of chaingen blocks
//! with one that returns a previous script for every input, so those
//! filters hold previous output scripts.  Blocks of every transaction
//! kind with arbitrary previous scripts, and the missing-script error,
//! are the business of `blockcf2_differential` in
//! `tests/oracle_differential.rs`.

use dcroxide_chaincfg::{Params, mainnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_gcs::blockcf2::{self, Entries, PrevScripter, RegularError};
use dcroxide_gcs::{Error, FilterV1, FilterV2, KEY_SIZE};
use dcroxide_testutil::{Oracle, hex, oracle_or_skip, unhex};
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// A `PrevScripter` that knows no output, as dcrwallet's
/// `genesisPrevScripter` (`wallet/udb/upgrades.go`) is: the genesis
/// block's one transaction is a coinbase and spends nothing.
struct NoPrevScripts;

impl PrevScripter for NoPrevScripts {
    fn prev_script(&self, _out: &OutPoint) -> Option<(u16, &[u8])> {
        None
    }
}

/// The p2sh script paying to `OP_TRUE` that chaingen's outputs pay to:
/// `OP_HASH160 <hash160(OP_TRUE)> OP_EQUAL`.
const CHAINGEN_OP_TRUE_P2SH: [u8; 23] = [
    0xa9, 0x14, 0xf5, 0xa8, 0x30, 0x2e, 0xe8, 0x69, 0x5b, 0xf8, 0x36, 0x25, 0x8b, 0x8f, 0x2b, 0x57,
    0xb3, 0x8a, 0x0b, 0xe1, 0x4e, 0x47, 0x87,
];

/// dcrwallet's `chaingenPrevScripter` (`wallet/reorg_test.go`): version
/// 0 and [`CHAINGEN_OP_TRUE_P2SH`] for every outpoint.
struct ChaingenPrevScripter;

impl PrevScripter for ChaingenPrevScripter {
    fn prev_script(&self, _out: &OutPoint) -> Option<(u16, &[u8])> {
        Some((0, &CHAINGEN_OP_TRUE_P2SH))
    }
}

/// `FilterV1::new`'s type, `gcs.NewFilter`'s counterpart.
type NewFilterV1 = fn(u8, [u8; KEY_SIZE], &[&[u8]]) -> Result<FilterV1, Error>;

#[test]
fn every_item_dcrwallet_names_is_reachable_without_storage() {
    // gcs.KeySize
    assert_eq!(KEY_SIZE, 16);
    // gcs.FromBytesV2
    let _: fn(u8, u64, &[u8]) -> Result<FilterV2, Error> = FilterV2::from_bytes;
    // gcs.NewFilter (version 1; dcrwallet's test data only)
    let _: NewFilterV1 = FilterV1::new;
    // FilterV2.Bytes, .MatchAny, .N, .Hash
    let _: fn(&FilterV2) -> &[u8] = FilterV2::bytes;
    let _: fn(&FilterV2, [u8; KEY_SIZE], &[&[u8]]) -> bool = FilterV2::matches_any;
    let _: fn(&FilterV2) -> u32 = FilterV2::n;
    let _: fn(&FilterV2) -> Hash = FilterV2::hash;

    // blockcf2.B and blockcf2.M (DCP0005).
    assert_eq!((blockcf2::B, blockcf2::M), (19, 784_931));
    // blockcf2.Key
    let _: fn(&Hash) -> [u8; KEY_SIZE] = blockcf2::key;
    // blockcf2.Regular, over blockcf2.PrevScripter, with both of the
    // scripters dcrwallet passes it.
    let _: fn(&MsgBlock, &NoPrevScripts) -> Result<FilterV2, RegularError> = blockcf2::regular;
    let _: fn(&MsgBlock, &ChaingenPrevScripter) -> Result<FilterV2, RegularError> =
        blockcf2::regular;
    // blockcf2.Entries and Entries.AddRegularPkScript
    let script = [0x76_u8, 0xa9];
    let mut entries = Entries::default();
    entries.add_regular_pk_script(&script);
    assert_eq!(entries.0, [&script[..]]);
}

/// A filter as the oracle's `gcs_blockcf2` dump prints it.
fn dumped(block: &MsgBlock, filter: &FilterV2) -> String {
    format!(
        "key={}\nbytes={}\nn={}\nhash={}\n",
        hex(&blockcf2::key(&block.header.merkle_root)),
        hex(filter.bytes()),
        filter.n(),
        filter.hash()
    )
}

/// dcrd's `blockcf2.Regular` of `block`, through the oracle, with
/// version 0 and `script` as the previous script of each outpoint in
/// `spent` and of no other.
fn dcrd_regular(
    oracle: &mut Oracle,
    block: &MsgBlock,
    spent: &[OutPoint],
    script: &[u8],
) -> String {
    let mut req = Vec::new();
    req.extend_from_slice(
        &u16::try_from(spent.len())
            .expect("few outpoints")
            .to_be_bytes(),
    );
    for op in spent {
        req.extend_from_slice(&op.hash.0);
        req.extend_from_slice(&op.index.to_be_bytes());
        req.extend_from_slice(&op.tree.to_be_bytes());
        req.extend_from_slice(&0_u16.to_be_bytes());
        req.extend_from_slice(
            &u16::try_from(script.len())
                .expect("short script")
                .to_be_bytes(),
        );
        req.extend_from_slice(script);
    }
    req.extend_from_slice(&block.serialize());
    let result = oracle.call_ok("gcs_blockcf2", &req);
    String::from_utf8(unhex(&result)).expect("dump is UTF-8")
}

/// A block shaped like those dcrwallet's reorg tests filter: a network's
/// genesis coinbase followed by regular transactions that spend chaingen
/// outputs.  They pay to a p2pkh script rather than to
/// [`CHAINGEN_OP_TRUE_P2SH`], so that script reaches the filter only as a
/// previous script.  Returns the block and every outpoint its
/// non-coinbase inputs spend.
fn chaingen_shaped_block(params: &Params) -> (MsgBlock, Vec<OutPoint>) {
    let mut block = params.genesis_block.clone();
    let mut spent = Vec::new();
    for (fill, inputs) in [(1_u8, 1_u32), (2, 3)] {
        let mut tx = MsgTx {
            ser_type: TxSerializeType::Full,
            version: 1,
            tx_in: Vec::new(),
            tx_out: Vec::new(),
            lock_time: 0,
            expiry: 0,
        };
        for index in 0..inputs {
            let previous_out_point = OutPoint {
                hash: Hash([fill; 32]),
                index,
                tree: 0,
            };
            spent.push(previous_out_point);
            tx.tx_in.push(TxIn {
                previous_out_point,
                sequence: 0xffff_ffff,
                value_in: 1_000_000,
                block_height: 0,
                block_index: 0xffff_ffff,
                signature_script: vec![0x51],
            });
        }
        let mut pk_script = vec![0x76, 0xa9, 0x14];
        pk_script.extend_from_slice(&[fill; 20]);
        pk_script.extend_from_slice(&[0x88, 0xac]);
        tx.tx_out.push(TxOut {
            value: 900_000,
            version: 0,
            pk_script,
        });
        block.transactions.push(tx);
    }
    (block, spent)
}

/// The genesis filter, dcrwallet's one non-test use: built with a
/// scripter that knows nothing, and equal to dcrd's on each network.
#[test]
fn genesis_filters_as_dcrwallet_builds_them() {
    let mut oracle = oracle_or_skip();
    for params in [mainnet_params(), testnet3_params(), simnet_params()] {
        let block = &params.genesis_block;
        let filter = blockcf2::regular(block, &NoPrevScripts).expect("genesis spends nothing");
        if let Some(oracle) = oracle.as_mut() {
            assert_eq!(
                dumped(block, &filter),
                dcrd_regular(oracle, block, &[], &[]),
                "{} genesis filter",
                params.name
            );
        }
    }
}

/// The filters dcrwallet's reorg tests build: every input's previous
/// script is chaingen's p2sh `OP_TRUE`, which no output of the block pays
/// to, the filter holds it, a scripter that knows no output cannot build
/// it, and dcrd builds the same bytes.
#[test]
fn chaingen_filters_as_dcrwallet_reorg_tests_build_them() {
    let mut oracle = oracle_or_skip();
    for params in [mainnet_params(), testnet3_params(), simnet_params()] {
        let (block, spent) = chaingen_shaped_block(&params);
        let filter = blockcf2::regular(&block, &ChaingenPrevScripter).expect("every script known");
        let key = blockcf2::key(&block.header.merkle_root);
        assert!(filter.matches_any(key, &[&CHAINGEN_OP_TRUE_P2SH[..]]));
        assert!(matches!(
            blockcf2::regular(&block, &NoPrevScripts),
            Err(RegularError::PrevScript(_))
        ));
        if let Some(oracle) = oracle.as_mut() {
            assert_eq!(
                dumped(&block, &filter),
                dcrd_regular(oracle, &block, &spent, &CHAINGEN_OP_TRUE_P2SH),
                "{} chaingen-shaped filter",
                params.name
            );
        }
    }
}
