// SPDX-License-Identifier: ISC
//! Transaction-to-JSON-result conversion (dcrd internal/rpcserver
//! `createVinList`, `createVoutList`, and `createTxRawResult`).
//!
//! The results are built as [`GoValue`] instances of the
//! dcroxide-rpctypes descriptors so they marshal byte for byte
//! through the Go-semantics encoder, with `Vin` entries carried as
//! raw pre-marshalled values through its custom marshaler.

// Index arithmetic over transaction structure mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashSet;

use dcroxide_chaincfg::Params;
use dcroxide_dcrjson::{GoValue, RPCError};
use dcroxide_rpctypes::chainsvrresults as results;
use dcroxide_wire::Message;
use dcroxide_wire::{BlockHeader, CurrencyNet, MsgTx};

use crate::rpcerrors::{rpc_internal_err, rpc_invalid_error};

/// The amount in coins (Go `dcrutil.Amount.ToCoin`).
pub fn to_coin(atoms: i64) -> f64 {
    atoms as f64 / 1e8
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn s(v: String) -> GoValue {
    GoValue::String(v)
}

/// Serialize a message to its wire protocol hex encoding (dcrd
/// `messageToHex`; the payload only, without framing).
pub fn message_to_hex(msg: &Message, pver: u32) -> Result<String, RPCError> {
    match msg.encode_payload(pver) {
        Ok(payload) => Ok(hex_str(&payload)),
        Err(e) => Err(rpc_internal_err(&format!(
            "Failed to encode msg of type {msg:?}: {e:?}"
        ))),
    }
}

/// One vin entry as the twelve-field value of the rpctypes `Vin`
/// descriptor.
#[allow(clippy::too_many_arguments)]
fn vin_value(
    coinbase: String,
    stakebase: String,
    treasurybase: bool,
    treasury_spend: String,
    txid: String,
    vout: u32,
    tree: i8,
    sequence: u32,
    amount_in: f64,
    block_height: u32,
    block_index: u32,
    script_sig: GoValue,
) -> GoValue {
    GoValue::Struct(vec![
        s(coinbase),
        s(stakebase),
        GoValue::Bool(treasurybase),
        s(treasury_spend),
        s(txid),
        GoValue::Uint(vout as u64),
        GoValue::Int(tree as i64),
        GoValue::Uint(sequence as u64),
        GoValue::Float64(amount_in),
        GoValue::Uint(block_height as u64),
        GoValue::Uint(block_index as u64),
        script_sig,
    ])
}

/// A slice of JSON objects for the inputs of the passed transaction
/// (dcrd `createVinList`), as values of the rpctypes `Vin`
/// descriptor.  Marshal each through `marshal_vin`.
pub fn create_vin_list(mtx: &MsgTx, is_treasury_enabled: bool) -> Vec<GoValue> {
    let simple = |ident: usize, script: &[u8], txin: &dcroxide_wire::TxIn| {
        let (coinbase, stakebase, treasurybase, tspend) = match ident {
            0 => (hex_str(script), String::new(), false, String::new()),
            1 => (String::new(), hex_str(script), false, String::new()),
            2 => (String::new(), String::new(), true, String::new()),
            _ => (String::new(), String::new(), false, hex_str(script)),
        };
        vin_value(
            coinbase,
            stakebase,
            treasurybase,
            tspend,
            String::new(),
            0,
            0,
            txin.sequence,
            to_coin(txin.value_in),
            txin.block_height,
            txin.block_index,
            GoValue::Null,
        )
    };

    // Treasurybase transactions only have a single txin by definition.
    // NOTE: this check MUST come before the coinbase check because a
    // treasurybase is identified as a coinbase as well.
    if is_treasury_enabled && dcroxide_standalone::is_treasury_base(mtx) {
        let txin = &mtx.tx_in[0];
        let mut list = vec![GoValue::Null; mtx.tx_in.len()];
        list[0] = simple(2, &[], txin);
        return fill_zero_vins(list, mtx);
    }

    // Coinbase transactions only have a single txin by definition.
    if dcroxide_standalone::is_coin_base_tx(mtx, is_treasury_enabled) {
        let txin = &mtx.tx_in[0];
        let mut list = vec![GoValue::Null; mtx.tx_in.len()];
        list[0] = simple(0, &txin.signature_script, txin);
        return fill_zero_vins(list, mtx);
    }

    // Treasury spend transactions only have a single txin by
    // definition.
    if is_treasury_enabled && dcroxide_stake::treasury::is_tspend(mtx) {
        let txin = &mtx.tx_in[0];
        let mut list = vec![GoValue::Null; mtx.tx_in.len()];
        list[0] = simple(3, &txin.signature_script, txin);
        return fill_zero_vins(list, mtx);
    }

    // Stakebase transactions (votes) have two inputs: a null stake
    // base followed by an input consuming a ticket's stakesubmission.
    let is_ssgen = dcroxide_stake::is_ssgen(mtx);

    let mut vin_list = Vec::with_capacity(mtx.tx_in.len());
    for (i, txin) in mtx.tx_in.iter().enumerate() {
        // Handle only the null input of a stakebase differently.
        if is_ssgen && i == 0 {
            vin_list.push(simple(1, &txin.signature_script, txin));
            continue;
        }

        // The disassembled string will contain [error] inline if the
        // script doesn't fully parse, so ignore the error here.
        let (disbuf, _) = dcroxide_txscript::disasm_string(&txin.signature_script);

        vin_list.push(vin_value(
            String::new(),
            String::new(),
            false,
            String::new(),
            txin.previous_out_point.hash.to_string(),
            txin.previous_out_point.index,
            txin.previous_out_point.tree,
            txin.sequence,
            to_coin(txin.value_in),
            txin.block_height,
            txin.block_index,
            GoValue::Struct(vec![s(disbuf), s(hex_str(&txin.signature_script))]),
        ));
    }

    vin_list
}

/// dcrd pre-sizes the vin list, so extra inputs on the single-input
/// shapes stay as zero-valued entries.
fn fill_zero_vins(mut list: Vec<GoValue>, mtx: &MsgTx) -> Vec<GoValue> {
    for (i, slot) in list.iter_mut().enumerate() {
        if matches!(slot, GoValue::Null) {
            let _ = &mtx.tx_in[i];
            *slot = vin_value(
                String::new(),
                String::new(),
                false,
                String::new(),
                String::new(),
                0,
                0,
                0,
                0.0,
                0,
                0,
                GoValue::Null,
            );
        }
    }
    list
}

/// A slice of JSON objects for the outputs of the passed transaction
/// (dcrd `createVoutList`), as values of the rpctypes `Vout`
/// descriptor.
pub fn create_vout_list(
    mtx: &MsgTx,
    chain_params: &Params,
    filter_addr_map: &HashSet<String>,
) -> Vec<GoValue> {
    let tx_type = dcroxide_stake::determine_tx_type(mtx);
    let is_sstx = tx_type == dcroxide_stake::TxType::SStx;

    let mut vout_list = Vec::with_capacity(mtx.tx_out.len());
    for (i, v) in mtx.tx_out.iter().enumerate() {
        // The disassembled string will contain [error] inline if the
        // script doesn't fully parse, so ignore the error here.
        let (disbuf, _) = dcroxide_txscript::disasm_string(&v.pk_script);

        // Attempt to extract addresses from the public key script.
        // In the case of stake submission transactions, the odd
        // outputs contain a commitment address.
        let mut addrs: Vec<String> = Vec::new();
        let script_type: String;
        let mut req_sigs: u16 = 0;
        let mut commit_amt: Option<i64> = None;
        if is_sstx && (i % 2 != 0) {
            script_type = "sstxcommitment".to_string();
            if let Ok(addr) =
                dcroxide_stake::addr_from_sstx_pk_scr_commitment(&v.pk_script, chain_params)
            {
                addrs = vec![addr.to_string()];
            }
            if let Ok(amt) = dcroxide_stake::amount_from_sstx_pk_scr_commitment(&v.pk_script) {
                commit_amt = Some(amt);
            }
        } else {
            let (st, extracted) =
                dcroxide_txscript::stdscript::extract_addrs(v.version, &v.pk_script, chain_params);
            script_type = st.to_string();
            addrs = extracted.iter().map(|a| a.to_string()).collect();
            req_sigs =
                dcroxide_txscript::stdscript::determine_required_sigs(v.version, &v.pk_script);
        }

        // Encode the addresses while checking the filter.
        let mut passes_filter = filter_addr_map.is_empty();
        for encoded in &addrs {
            if passes_filter {
                break;
            }
            if filter_addr_map.contains(encoded) {
                passes_filter = true;
            }
        }
        if !passes_filter {
            continue;
        }

        let spk = GoValue::Struct(vec![
            s(disbuf),
            s(hex_str(&v.pk_script)),
            GoValue::Int(req_sigs as i64),
            s(script_type),
            GoValue::Array(addrs.into_iter().map(s).collect()),
            match commit_amt {
                Some(amt) => GoValue::Float64(to_coin(amt)),
                None => GoValue::Null,
            },
            GoValue::Uint(v.version as u64),
        ]);
        vout_list.push(GoValue::Struct(vec![
            GoValue::Float64(to_coin(v.value)),
            GoValue::Uint(i as u64),
            GoValue::Uint(v.version as u64),
            spk,
        ]));
    }

    vout_list
}

/// Convert the passed transaction and associated parameters to a raw
/// transaction JSON result (dcrd `createTxRawResult`), as a value of
/// the rpctypes `TxRawResult` descriptor with the vins carried
/// through the custom Vin marshaler.
#[allow(clippy::too_many_arguments)]
pub fn create_tx_raw_result(
    chain_params: &Params,
    mtx: &MsgTx,
    tx_hash: &str,
    blk_idx: u32,
    blk_header: Option<&BlockHeader>,
    blk_hash: &str,
    blk_height: i64,
    confirmations: i64,
    is_treasury_enabled: bool,
    pver: u32,
    _net: CurrencyNet,
) -> Result<GoValue, RPCError> {
    let mtx_hex = message_to_hex(&Message::Tx(mtx.clone()), pver)?;

    if tx_hash != mtx.tx_hash().to_string() {
        return Err(rpc_invalid_error(&format!(
            "Tx hash does not match: got {tx_hash} expected {}",
            mtx.tx_hash()
        )));
    }

    let vins: Vec<GoValue> = create_vin_list(mtx, is_treasury_enabled)
        .iter()
        .map(|v| GoValue::Raw(results::marshal_vin(v)))
        .collect();
    let vouts = create_vout_list(mtx, chain_params, &HashSet::new());

    let (time, blocktime, block_hash, confs) = match blk_header {
        // This is not a typo; they are identical in dcrd as well.
        Some(header) => (
            header.timestamp as i64,
            header.timestamp as i64,
            blk_hash.to_string(),
            confirmations,
        ),
        None => (0, 0, String::new(), 0),
    };

    Ok(GoValue::Struct(vec![
        s(mtx_hex),
        s(tx_hash.to_string()),
        GoValue::Int(mtx.version as i64),
        GoValue::Uint(mtx.lock_time as u64),
        GoValue::Uint(mtx.expiry as u64),
        GoValue::Array(vins),
        GoValue::Array(vouts),
        s(block_hash),
        GoValue::Int(blk_height),
        GoValue::Uint(blk_idx as u64),
        GoValue::Int(confs),
        GoValue::Int(time),
        GoValue::Int(blocktime),
    ]))
}
