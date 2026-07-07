// SPDX-License-Identifier: ISC
//! The RPC command handlers (dcrd internal/rpcserver `rpcserver.go`
//! `handle*` functions), first slice: the handlers that operate
//! purely over the chain parameters, the configuration, and the small
//! [`crate::server::RpcChain`] seam.
//!
//! Commands arrive as [`GoValue`] instances of the dcroxide-rpctypes
//! command descriptors (the output of the ported `ParseParams`
//! pipeline) and results are returned as [`GoValue`] instances of the
//! corresponding result descriptors.

// Amount arithmetic, range checks, and index access mirror Go.
#![allow(clippy::arithmetic_side_effects, clippy::manual_range_contains)]

use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, RPCError, codes, err_rpc_parse, gojson};
use dcroxide_stake::MAX_AMOUNT;
use dcroxide_txscript::stdaddr;
use dcroxide_wire::{Message, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

use crate::rpcerrors::{
    rpc_address_key_error, rpc_decode_hex_error, rpc_deserialization_error, rpc_internal_err,
    rpc_invalid_error,
};
use crate::server::{RpcChain, Server};
use crate::txresults;

/// Go `wire.MaxTxInSequenceNum`.
const MAX_TX_IN_SEQUENCE_NUM: u32 = 0xffffffff;

/// Go `wire.NullValueIn`.
const NULL_VALUE_IN: i64 = -1;

fn s(v: &GoValue) -> &str {
    match v {
        GoValue::String(s) => s,
        other => panic!("expected string field, got {other:?}"),
    }
}

fn int(v: &GoValue) -> i64 {
    match v {
        GoValue::Int(n) => *n,
        other => panic!("expected int field, got {other:?}"),
    }
}

fn uint(v: &GoValue) -> u64 {
    match v {
        GoValue::Uint(n) => *n,
        other => panic!("expected uint field, got {other:?}"),
    }
}

fn float(v: &GoValue) -> f64 {
    match v {
        GoValue::Float64(f) => *f,
        other => panic!("expected float field, got {other:?}"),
    }
}

fn fields(v: &GoValue) -> &[GoValue] {
    match v {
        GoValue::Struct(fields) => fields,
        other => panic!("expected struct command, got {other:?}"),
    }
}

fn array(v: &GoValue) -> &[GoValue] {
    match v {
        GoValue::Array(items) => items,
        GoValue::Null => &[],
        other => panic!("expected array field, got {other:?}"),
    }
}

fn map(v: &GoValue) -> &[(String, GoValue)] {
    match v {
        GoValue::Map(entries) => entries,
        other => panic!("expected map field, got {other:?}"),
    }
}

fn opt_int(v: &GoValue) -> Option<i64> {
    match v {
        GoValue::Null => None,
        GoValue::Int(n) => Some(*n),
        other => panic!("expected optional int field, got {other:?}"),
    }
}

fn opt_uint(v: &GoValue) -> Option<u64> {
    match v {
        GoValue::Null => None,
        GoValue::Uint(n) => Some(*n),
        other => panic!("expected optional uint field, got {other:?}"),
    }
}

/// Go `%v` rendering of a float64 for error messages.
fn govf(f: f64) -> String {
    gojson::format_float_g(f)
}

/// Convert a floating point coin amount to atoms (Go
/// `dcrutil.NewAmount`).
fn new_amount(f: f64) -> Result<i64, String> {
    // The amount is only considered invalid if it cannot be represented
    // as an integer type.  This may happen if f is NaN or +-Infinity.
    if f.is_nan() || f.is_infinite() {
        return Err("invalid coin amount".to_string());
    }
    let scaled = f * 1e8;
    // Go dcrutil round: add or subtract 0.5 and truncate.
    if scaled < 0.0 {
        Ok((scaled - 0.5) as i64)
    } else {
        Ok((scaled + 0.5) as i64)
    }
}

/// The Go `%v` rendering of `dcrutil.MaxAmount`, an untyped float
/// constant in dcrd, as it appears in handler error messages.
fn max_amount_v() -> String {
    govf(MAX_AMOUNT as f64)
}

/// handlecreaterawtransaction (dcrd `handleCreateRawTransaction`);
/// the command is a `CreateRawTransactionCmd` value and the result is
/// the serialized transaction hex string.
pub fn handle_create_raw_transaction<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let (inputs, amounts, lock_time, expiry) = (&c[0], &c[1], opt_int(&c[2]), opt_int(&c[3]));

    // Validate expiry, if given.
    if let Some(expiry) = expiry
        && expiry < 0
    {
        return Err(rpc_invalid_error("Expiry out of range"));
    }

    // Validate the locktime, if given.
    if let Some(lock_time) = lock_time
        && (lock_time < 0 || lock_time > i64::from(MAX_TX_IN_SEQUENCE_NUM))
    {
        return Err(rpc_invalid_error("Locktime out of range"));
    }

    // Add all transaction inputs to a new transaction after performing
    // some validity checks.
    let mut mtx = MsgTx {
        ser_type: dcroxide_wire::TxSerializeType::Full,
        version: 1,
        tx_in: Vec::new(),
        tx_out: Vec::new(),
        lock_time: 0,
        expiry: 0,
    };
    for input in array(inputs) {
        let input = fields(input);
        let (amount, txid, vout, tree) = (
            float(&input[0]),
            s(&input[1]),
            uint(&input[2]) as u32,
            int(&input[3]) as i8,
        );
        let tx_hash: Hash = txid.parse().map_err(|_| rpc_decode_hex_error(txid))?;

        if !(tree == 0 || tree == 1) {
            return Err(rpc_invalid_error("Tx tree must be regular or stake"));
        }

        let mut prev_out_v = NULL_VALUE_IN;
        if amount > 0.0 {
            let amt = new_amount(amount).map_err(|e| rpc_invalid_error(&e))?;
            prev_out_v = amt;
        }

        let mut tx_in = TxIn {
            previous_out_point: OutPoint {
                hash: tx_hash,
                index: vout,
                tree,
            },
            sequence: MAX_TX_IN_SEQUENCE_NUM,
            value_in: prev_out_v,
            block_height: 0,
            // Go wire.NewTxIn sets the null block index sentinel.
            block_index: 0xffffffff,
            signature_script: Vec::new(),
        };
        if let Some(lock_time) = lock_time
            && lock_time != 0
        {
            tx_in.sequence = MAX_TX_IN_SEQUENCE_NUM - 1;
        }
        mtx.tx_in.push(tx_in);
    }

    // Add all transaction outputs to the transaction after performing
    // some validity checks.  Note that dcrd iterates the Go map in
    // random order here, so the output order with multiple amounts is
    // arbitrary there; entries are processed in JSON order here.
    for (encoded_addr, amount) in map(amounts) {
        let amount = float(amount);
        let atoms = new_amount(amount).map_err(|e| rpc_internal_err(&e))?;

        // Ensure amount is in the valid range for monetary amounts.
        if atoms <= 0 || atoms > MAX_AMOUNT {
            return Err(rpc_invalid_error(&format!(
                "Invalid amount: 0 >= {} > {}",
                govf(amount),
                max_amount_v()
            )));
        }

        // Decode the provided address.  This also ensures the network
        // encoded with the address matches the network the server is
        // currently on.
        let addr = stdaddr::decode_address(encoded_addr, &server.cfg.chain_params)
            .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;

        // Ensure the address is one of the supported types (dcrd
        // requires the StakeAddress interface here).
        let Some((pk_script_ver, pk_script)) =
            addr.voting_rights_script().map(|_| addr.payment_script())
        else {
            return Err(rpc_address_key_error(&format!(
                "Invalid type: {}",
                addr.go_type_name()
            )));
        };

        mtx.tx_out.push(TxOut {
            value: atoms,
            version: pk_script_ver,
            pk_script,
        });
    }

    // Set the Locktime, if given.
    if let Some(lock_time) = lock_time {
        mtx.lock_time = lock_time as u32;
    }

    // Set the Expiry, if given.
    if let Some(expiry) = expiry {
        mtx.expiry = expiry as u32;
    }

    let mtx_hex = txresults::message_to_hex(&Message::Tx(mtx), server.cfg.max_protocol_version)?;
    Ok(GoValue::String(mtx_hex))
}

/// handlecreaterawsstx (dcrd `handleCreateRawSStx`); the command is a
/// `CreateRawSStxCmd` value and the result is the serialized ticket
/// purchase hex string.
pub fn handle_create_raw_sstx<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let (inputs, amount, couts) = (array(&c[0]), map(&c[1]), array(&c[2]));

    // Basic sanity checks for the information coming from the cmd.
    if inputs.len() != couts.len() {
        return Err(rpc_invalid_error(&format!(
            "Number of inputs should be equal to the number of future \
             commitment/change outs for any sstx; {} inputs given, but {} COuts",
            inputs.len(),
            couts.len()
        )));
    }
    if amount.len() != 1 {
        return Err(rpc_invalid_error(&format!(
            "Only one SSGen tagged output is allowed per sstx; len ssgenout {}",
            amount.len()
        )));
    }

    // Add all transaction inputs to a new transaction after performing
    // some validity checks.
    let mut mtx = MsgTx {
        ser_type: dcroxide_wire::TxSerializeType::Full,
        version: 1,
        tx_in: Vec::new(),
        tx_out: Vec::new(),
        lock_time: 0,
        expiry: 0,
    };
    for input in inputs {
        let input = fields(input);
        let (txid, vout, tree, amt) = (
            s(&input[0]),
            uint(&input[1]) as u32,
            int(&input[2]) as i8,
            int(&input[3]),
        );
        let tx_hash: Hash = txid.parse().map_err(|_| rpc_decode_hex_error(txid))?;

        if !(tree == 0 || tree == 1) {
            return Err(rpc_invalid_error("Tx tree must be regular or stake"));
        }

        mtx.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash: tx_hash,
                index: vout,
                tree,
            },
            sequence: MAX_TX_IN_SEQUENCE_NUM,
            value_in: amt,
            block_height: 0,
            // Go wire.NewTxIn sets the null block index sentinel.
            block_index: 0xffffffff,
            signature_script: Vec::new(),
        });
    }

    // Add all transaction outputs to the transaction after performing
    // some validity checks.
    let mut amt_ticket: i64 = 0;
    for (encoded_addr, amount) in amount {
        let amount = int(amount);

        // Ensure amount is in the valid range for monetary amounts.
        if amount <= 0 || amount > MAX_AMOUNT {
            return Err(rpc_invalid_error(&format!(
                "Invalid SSTx commitment amount: 0 >= {amount} > {}",
                max_amount_v()
            )));
        }

        // Decode the provided address.
        let addr = stdaddr::decode_address(encoded_addr, &server.cfg.chain_params)
            .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;

        // Create the necessary voting rights script; None marks an
        // address kind outside dcrd's StakeAddress interface.
        let Some((pk_script_ver, pk_script)) = addr.voting_rights_script() else {
            return Err(rpc_address_key_error(&format!(
                "Invalid address type: {}",
                addr.go_type_name()
            )));
        };
        mtx.tx_out.push(TxOut {
            value: amount,
            version: pk_script_ver,
            pk_script,
        });

        amt_ticket += amount;
    }

    // Calculate the commitment amounts, then create the addresses and
    // payout proportions as null data outputs.
    let input_amts: Vec<i64> = inputs.iter().map(|input| int(&fields(input)[3])).collect();
    let change_amts: Vec<i64> = couts.iter().map(|cout| int(&fields(cout)[3])).collect();

    // Check and make sure none of the change overflows the input
    // amounts.
    for (i, amt) in input_amts.iter().enumerate() {
        if change_amts[i] >= *amt {
            return Err(rpc_invalid_error(&format!(
                "input {} >= amount {}",
                change_amts[i], amt
            )));
        }
    }

    // Obtain the commitment amounts.
    let (_, amounts_committed) =
        dcroxide_stake::sstx_null_output_amounts(&input_amts, &change_amts, amt_ticket)
            .map_err(|e| rpc_internal_err(&e.to_string()))?;

    for (i, cout) in couts.iter().enumerate() {
        let cout = fields(cout);
        let (addr_str, change_addr, change_amt) = (s(&cout[0]), s(&cout[2]), int(&cout[3]));

        // Append future commitment output.
        let addr = stdaddr::decode_address(addr_str, &server.cfg.chain_params)
            .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;

        // Create the reward commitment script.
        const VOTE_FEE_LIMIT: i64 = 0;
        const REVOKE_FEE_LIMIT: i64 = 0;
        let Some((cmt_script_ver, cmt_script)) =
            addr.reward_commitment_script(amounts_committed[i], VOTE_FEE_LIMIT, REVOKE_FEE_LIMIT)
        else {
            return Err(rpc_address_key_error(&format!(
                "Invalid type: {}",
                addr.go_type_name()
            )));
        };
        mtx.tx_out.push(TxOut {
            value: 0,
            version: cmt_script_ver,
            pk_script: cmt_script,
        });

        // Append change output.
        if change_amt < 0 || change_amt > MAX_AMOUNT {
            return Err(rpc_invalid_error(&format!(
                "Invalid change amount: 0 > {change_amt} > {}",
                max_amount_v()
            )));
        }

        let addr =
            stdaddr::decode_address(change_addr, &server.cfg.chain_params).map_err(|_| {
                // dcrd formats the nil address value into this message.
                rpc_address_key_error("Wrong network: <nil>")
            })?;

        // Create a new script which pays change to the provided
        // address.
        let Some((change_script_ver, change_script)) = addr.stake_change_script() else {
            return Err(rpc_address_key_error(&format!(
                "Invalid type: {}",
                addr.go_type_name()
            )));
        };
        mtx.tx_out.push(TxOut {
            value: change_amt,
            version: change_script_ver,
            pk_script: change_script,
        });
    }

    // Make sure we generated a valid SStx.
    dcroxide_stake::check_sstx(&mtx).map_err(|e| rpc_internal_err(&e.to_string()))?;

    let mtx_hex = txresults::message_to_hex(&Message::Tx(mtx), server.cfg.max_protocol_version)?;
    Ok(GoValue::String(mtx_hex))
}

/// Go's hex decoding acceptance for the handler inputs (Go
/// `hex.DecodeString` succeeds only on full byte pairs of hex
/// digits).
fn go_decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(())?;
        let lo = (pair[1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// handledecoderawtransaction (dcrd `handleDecodeRawTransaction`);
/// the result is a `TxRawDecodeResult` value with the vins carried
/// through the custom Vin marshaler.
pub fn handle_decode_raw_transaction<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hex_str = s(&c[0]);

    // Deserialize the transaction.
    let padded;
    let hex_str = if hex_str.len() % 2 != 0 {
        padded = format!("0{hex_str}");
        &padded
    } else {
        hex_str
    };
    let serialized_tx = go_decode_hex(hex_str).map_err(|_| rpc_decode_hex_error(hex_str))?;
    let (mtx, consumed) = MsgTx::from_bytes(&serialized_tx).map_err(|e| {
        // Go surfaces io.ErrUnexpectedEOF's text for truncation.
        let text = match e {
            dcroxide_wire::WireError::UnexpectedEof => "unexpected EOF".to_string(),
            other => other.to_string(),
        };
        rpc_deserialization_error(&format!("Could not decode Tx: {text}"))
    })?;
    if consumed != serialized_tx.len() {
        // Go's Deserialize reads from a stream and ignores trailing
        // bytes only when the reader is exhausted by the message;
        // extra bytes after a full transaction are ignored by dcrd as
        // well because it deserializes from a reader.
    }

    // Determine if the treasury rules are active as of the current
    // best tip.
    let prev_blk_hash = server.cfg.chain.best_snapshot().hash;
    let is_treasury_enabled = server.is_treasury_agenda_active(&prev_blk_hash)?;

    // Create and return the result.
    let vins: Vec<GoValue> = txresults::create_vin_list(&mtx, is_treasury_enabled)
        .iter()
        .map(|v| GoValue::Raw(dcroxide_rpctypes::chainsvrresults::marshal_vin(v)))
        .collect();
    let vouts = txresults::create_vout_list(
        &mtx,
        &server.cfg.chain_params,
        &std::collections::HashSet::new(),
    );
    Ok(GoValue::Struct(vec![
        GoValue::String(mtx.tx_hash().to_string()),
        GoValue::Int(i64::from(mtx.version as i32)),
        GoValue::Uint(u64::from(mtx.lock_time)),
        GoValue::Uint(u64::from(mtx.expiry)),
        GoValue::Array(vins),
        GoValue::Array(vouts),
    ]))
}

/// handledecodescript (dcrd `handleDecodeScript`); the result is a
/// `DecodeScriptResult` value.
pub fn handle_decode_script<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hex_str = s(&c[0]);
    let script_version = opt_uint(&c[1]).unwrap_or(0) as u16;

    // Convert the hex script to bytes.
    let padded;
    let hex_str = if hex_str.len() % 2 != 0 {
        padded = format!("0{hex_str}");
        &padded
    } else {
        hex_str
    };
    let script = go_decode_hex(hex_str).map_err(|_| rpc_decode_hex_error(hex_str))?;

    // The disassembled string will contain [error] inline if the
    // script doesn't fully parse, so ignore the error here.
    let (disbuf, _) = dcroxide_txscript::disasm_string(&script);

    // Attempt to extract known addresses associated with the script.
    // Pubkey addresses render as their pay-to-pubkey-hash form.
    let params = server.cfg.chain_params.clone();
    let (script_type, addrs) =
        dcroxide_txscript::stdscript::extract_addrs(script_version, &script, &params);
    let addresses: Vec<GoValue> = addrs
        .iter()
        .map(|addr| {
            let addr = addr.address_pub_key_hash().unwrap_or_else(|| addr.clone());
            GoValue::String(addr.to_string())
        })
        .collect();

    // Determine the number of required signatures for known standard
    // types.
    let req_sigs = dcroxide_txscript::stdscript::determine_required_sigs(script_version, &script);

    // Convert the script itself to a pay-to-script-hash address; only
    // version 0 scripts are supported (dcrd `NewAddressScriptHash`).
    let p2sh = if script_version == 0 {
        stdaddr::new_address_script_hash_v0(&script, &params)
            .map(|a| a.to_string())
            .map_err(|e| rpc_internal_err(&e.to_string()))?
    } else {
        // dcrd's version-generic NewAddressScriptHash error text.
        return Err(rpc_internal_err(&format!(
            "script hash addresses for version {script_version} are not supported"
        )));
    };

    // Generate and return the reply; the P2SH form is omitted for
    // scripts that are already pay-to-script-hash.
    let p2sh_field = if script_type == dcroxide_txscript::stdscript::ScriptType::ScriptHash {
        String::new()
    } else {
        p2sh
    };
    Ok(GoValue::Struct(vec![
        GoValue::String(disbuf),
        GoValue::Int(i64::from(req_sigs as i32)),
        GoValue::String(script_type.to_string()),
        GoValue::Array(addresses),
        GoValue::String(p2sh_field),
    ]))
}

/// handleestimatefee (dcrd `handleEstimateFee`): the minimum relay
/// fee in coins.
pub fn handle_estimate_fee<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Float64(txresults::to_coin(
        server.cfg.min_relay_tx_fee,
    )))
}

/// handlegetblocksubsidy (dcrd `handleGetBlockSubsidy`); the result
/// is a `GetBlockSubsidyResult` value.
pub fn handle_get_block_subsidy<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let height = int(&c[0]);
    let voters = uint(&c[1]) as u16;

    // Determine which agendas are active as of the provided height
    // when that height exists in the main chain or as of the current
    // best tip otherwise.
    let best = server.cfg.chain.best_snapshot();
    let mut prev_blk_hash = best.hash;
    if height <= best.height {
        let header = server
            .cfg
            .chain
            .header_by_height(height)
            .map_err(|e| rpc_internal_err(&e))?;
        prev_blk_hash = header.prev_block;
    }
    let is_treasury_enabled = server.is_treasury_agenda_active(&prev_blk_hash)?;
    let is_subsidy_enabled = server.is_subsidy_split_agenda_active(&prev_blk_hash)?;
    let is_subsidy_r2_enabled = server.is_subsidy_split_r2_agenda_active(&prev_blk_hash)?;

    // Determine which subsidy split variant to use depending on the
    // active agendas.
    let subsidy_split_variant = if is_subsidy_r2_enabled {
        dcroxide_standalone::SubsidySplitVariant::Dcp0012
    } else if is_subsidy_enabled {
        dcroxide_standalone::SubsidySplitVariant::Dcp0010
    } else {
        dcroxide_standalone::SubsidySplitVariant::Original
    };

    let subsidy_cache = &mut server.cfg.subsidy_cache;
    let dev = subsidy_cache.calc_treasury_subsidy(height, voters, is_treasury_enabled);
    let pos = subsidy_cache.calc_stake_vote_subsidy_v3(height - 1, subsidy_split_variant)
        * i64::from(voters);
    let pow = subsidy_cache.calc_work_subsidy_v3(height, voters, subsidy_split_variant);
    let total = dev + pos + pow;

    Ok(GoValue::Struct(vec![
        GoValue::Int(dev),
        GoValue::Int(pos),
        GoValue::Int(pow),
        GoValue::Int(total),
    ]))
}

/// handlegetcurrentnet (dcrd `handleGetCurrentNet`): the network
/// identifier as a number.
pub fn handle_get_current_net<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Uint(u64::from(server.cfg.chain_params.net.0)))
}

/// handlevalidateaddress (dcrd `handleValidateAddress`); the result
/// is a `ValidateAddressChainResult` value.  An undecodable address
/// yields the default (invalid) result with no error.
pub fn handle_validate_address<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let address = s(&c[0]);
    match stdaddr::decode_address(address, &server.cfg.chain_params) {
        Ok(addr) => Ok(GoValue::Struct(vec![
            GoValue::Bool(true),
            GoValue::String(addr.to_string()),
        ])),
        Err(_) => Ok(GoValue::Struct(vec![
            GoValue::Bool(false),
            GoValue::String(String::new()),
        ])),
    }
}

/// Decode standard base64 with Go `encoding/base64` `StdEncoding`
/// semantics: strict alphabet, mandatory padding, newlines ignored,
/// and Go's corrupt-input error message with its exact byte offsets
/// (the text surfaces in the verifymessage RPC error).  Truncated
/// (unpadded) tails report the corruption at the end of the input;
/// the dump pins the reachable shapes.
fn go_std_base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const PAD: u8 = 64;
    let mut rev = [255u8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        rev[b as usize] = i as u8;
    }
    rev[b'=' as usize] = PAD;

    let corrupt = |pos: usize| format!("illegal base64 data at input byte {pos}");

    // Collect the symbols with their original byte offsets, skipping
    // newlines like Go's decoder.
    let bytes = input.as_bytes();
    let mut syms: Vec<(u8, usize)> = Vec::with_capacity(bytes.len());
    for (pos, &b) in bytes.iter().enumerate() {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        let v = rev[b as usize];
        if v == 255 {
            return Err(corrupt(pos));
        }
        syms.push((v, pos));
    }

    let mut out = Vec::with_capacity(syms.len() / 4 * 3);
    let mut idx = 0usize;
    while idx < syms.len() {
        let quantum = &syms[idx..syms.len().min(idx + 4)];

        // A full quantum of data symbols decodes to three bytes.
        if quantum.len() == 4 && quantum.iter().all(|&(v, _)| v != PAD) {
            let q: Vec<u8> = quantum.iter().map(|&(v, _)| v).collect();
            out.push((q[0] << 2) | (q[1] >> 4));
            out.push((q[1] << 4) | (q[2] >> 2));
            out.push((q[2] << 6) | q[3]);
            idx += 4;
            continue;
        }

        // The final quantum: partial data plus mandatory padding.
        let n_data = quantum.iter().take_while(|&&(v, _)| v != PAD).count();

        // An unpadded incomplete tail reports the corruption at the
        // first symbol of the incomplete quantum (Go reports si - j).
        if n_data == quantum.len() && quantum.len() < 4 {
            return Err(corrupt(quantum[0].1));
        }
        match n_data {
            0 | 1 => {
                // Padding in the first two symbols (or a bare short
                // tail) is corrupt at the offending position.
                let pos = quantum.get(n_data).map_or(input.len(), |&(_, pos)| pos);
                return Err(corrupt(pos));
            }
            2 => {
                // Two data symbols need two padding symbols.
                if quantum.len() < 3 {
                    return Err(corrupt(input.len()));
                }
                if quantum.len() < 4 {
                    return Err(corrupt(input.len()));
                }
                if quantum[3].0 != PAD {
                    return Err(corrupt(quantum[3].1));
                }
                out.push((quantum[0].0 << 2) | (quantum[1].0 >> 4));
            }
            3 => {
                if quantum.len() < 4 {
                    return Err(corrupt(input.len()));
                }
                out.push((quantum[0].0 << 2) | (quantum[1].0 >> 4));
                out.push((quantum[1].0 << 4) | (quantum[2].0 >> 2));
            }
            _ => unreachable!(),
        }
        idx += 4;

        // Anything after the padded final quantum is corrupt at its
        // position.
        if idx < syms.len() {
            return Err(corrupt(syms[idx].1));
        }
    }

    Ok(out)
}

/// handleverifymessage (dcrd `handleVerifyMessage`): whether the
/// compact signature commits to the message for the address.
pub fn handle_verify_message<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let (address, signature, message) = (s(&c[0]), s(&c[1]), s(&c[2]));

    // Decode the provided address.  This also ensures the network
    // encoded with the address matches the network the server is
    // currently on.
    let params = server.cfg.chain_params.clone();
    let addr = stdaddr::decode_address(address, &params)
        .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;

    // Only version 0 P2PKH addresses are valid for signing.
    if !matches!(addr, stdaddr::Address::PubKeyHashEcdsaSecp256k1V0 { .. }) {
        return Err(RPCError::new(
            codes::TYPE,
            "Address is not a pay-to-pubkey-hash address",
        ));
    }

    // Decode base64 signature.
    let sig = go_std_base64_decode(signature).map_err(|e| {
        RPCError::new(
            err_rpc_parse().code,
            &format!("Malformed base64 encoding: {e}"),
        )
    })?;

    // Validate the signature - this just shows that it was valid at
    // all.  We will compare it with the key next.
    let mut buf = Vec::new();
    write_var_string(&mut buf, "Decred Signed Message:\n");
    write_var_string(&mut buf, message);
    let expected_message_hash = dcroxide_chainhash::hash_b(&buf);
    let Ok((pk, was_compressed)) =
        dcroxide_dcrec::secp256k1::ecdsa::recover_compact(&sig, &expected_message_hash)
    else {
        // Treat errors in RecoverCompact as an invalid signature.
        return Ok(GoValue::Bool(false));
    };

    // Reconstruct the pubkey hash.
    let pk_hash = if was_compressed {
        stdaddr::hash160(&pk.serialize_compressed()).to_vec()
    } else {
        stdaddr::hash160(&pk.serialize_uncompressed()).to_vec()
    };
    let Ok(reconstructed) = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&pk_hash, &params)
    else {
        // Treat error in reconstruction as an invalid signature.
        return Ok(GoValue::Bool(false));
    };

    // Return boolean if addresses match.
    Ok(GoValue::Bool(reconstructed.to_string() == address))
}

/// Go `wire.WriteVarString` at protocol version 0.
fn write_var_string(w: &mut Vec<u8>, s: &str) {
    dcroxide_wire::write_var_int(w, s.len() as u64);
    w.extend_from_slice(s.as_bytes());
}

/// handlegetbestblock (dcrd `handleGetBestBlock`); the result is a
/// `GetBestBlockResult` value.
pub fn handle_get_best_block<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    Ok(GoValue::Struct(vec![
        GoValue::String(best.hash.to_string()),
        GoValue::Int(best.height),
    ]))
}

/// handlegetbestblockhash (dcrd `handleGetBestBlockHash`).
pub fn handle_get_best_block_hash<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    Ok(GoValue::String(best.hash.to_string()))
}

/// handlegetblockcount (dcrd `handleGetBlockCount`).
pub fn handle_get_block_count<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Int(server.cfg.chain.best_snapshot().height))
}

/// handlegetcoinsupply (dcrd `handleGetCoinSupply`).
pub fn handle_get_coin_supply<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Int(server.cfg.chain.best_snapshot().total_subsidy))
}

/// handlegetdifficulty (dcrd `handleGetDifficulty`).
pub fn handle_get_difficulty<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    Ok(GoValue::Float64(crate::helpers::get_difficulty_ratio(
        best.bits,
        server.cfg.chain_params.pow_limit_bits,
    )))
}

/// handlegetblockhash (dcrd `handleGetBlockHash`).
pub fn handle_get_block_hash<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let index = int(&c[0]);
    let hash = server.cfg.chain.block_hash_by_height(index).map_err(|_| {
        RPCError::new(
            codes::OUT_OF_RANGE,
            &format!("Block number out of range: {index}"),
        )
    })?;
    Ok(GoValue::String(hash.to_string()))
}

/// handlegetchaintips (dcrd `handleGetChainTips`); the result is a
/// slice of `GetChainTipsResult` values.
pub fn handle_get_chain_tips<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let tips = server.cfg.chain.chain_tips();
    Ok(GoValue::Array(
        tips.into_iter()
            .map(|tip| {
                GoValue::Struct(vec![
                    GoValue::Int(tip.height),
                    GoValue::String(tip.hash.to_string()),
                    GoValue::Int(tip.branch_len),
                    GoValue::String(tip.status),
                ])
            })
            .collect(),
    ))
}

/// handlegetheaders (dcrd `handleGetHeaders`); the result is a
/// `GetHeadersResult` value.
pub fn handle_get_headers<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let locator_strs: Vec<String> = array(&c[0]).iter().map(|v| s(v).to_string()).collect();
    let hash_stop_str = s(&c[1]);

    let block_locators = crate::helpers::decode_hashes(&locator_strs)?;
    let mut hash_stop = Hash([0u8; 32]);
    if !hash_stop_str.is_empty() {
        hash_stop = hash_stop_str
            .parse()
            .map_err(|e| rpc_invalid_error(&format!("Failed to decode hashstop: {e}")))?;
    }

    let headers = server.cfg.chain.locate_headers(&block_locators, &hash_stop);

    // Return the serialized block headers as hex-encoded strings.
    let hex_block_headers: Vec<GoValue> = headers
        .iter()
        .map(|h| GoValue::String(hex_str(&h.serialize())))
        .collect();
    Ok(GoValue::Struct(vec![GoValue::Array(hex_block_headers)]))
}

/// The shared verbose header/block fields: pow hash selection by the
/// blake3 agenda, next hash, and confirmations.
struct VerboseBlockCommon {
    pow_hash: Hash,
    next_hash_string: String,
    confirmations: i64,
}

fn verbose_block_common<C: RpcChain>(
    server: &mut Server<C>,
    hash: &Hash,
    header: &dcroxide_wire::BlockHeader,
) -> Result<VerboseBlockCommon, RPCError> {
    let best = server.cfg.chain.best_snapshot();

    // Get next block hash unless there are none.
    let mut next_hash_string = String::new();
    let mut confirmations: i64 = -1;
    let height = i64::from(header.height);
    if server.cfg.chain.main_chain_has_block(hash) {
        if height < best.height {
            let next_hash = server
                .cfg
                .chain
                .block_hash_by_height(height + 1)
                .map_err(|e| rpc_internal_err(&e))?;
            next_hash_string = next_hash.to_string();
        }
        confirmations = 1 + best.height - height;
    }

    let is_blake3_pow_active = server.is_blake3_pow_agenda_active(&header.prev_block)?;
    let pow_hash = if is_blake3_pow_active {
        header.pow_hash_v2()
    } else {
        header.block_hash()
    };

    Ok(VerboseBlockCommon {
        pow_hash,
        next_hash_string,
        confirmations,
    })
}

/// handlegetblockheader (dcrd `handleGetBlockHeader`); the verbose
/// result is a `GetBlockHeaderVerboseResult` value and the
/// non-verbose result is the serialized header hex string.
pub fn handle_get_block_header<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_str = s(&c[0]);
    let verbose = opt_bool(&c[1]);

    // Fetch the header from chain.
    let hash: Hash = hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(hash_str))?;
    let header = server.cfg.chain.header_by_hash(&hash).map_err(|_| {
        RPCError::new(
            codes::BLOCK_NOT_FOUND,
            &format!("Block not found: {hash_str}"),
        )
    })?;

    // When the verbose flag isn't set, simply return the serialized
    // block header as a hex-encoded string.
    if let Some(false) = verbose {
        return Ok(GoValue::String(hex_str(&header.serialize())));
    }

    // The verbose flag is set, so generate the JSON object and return
    // it.
    let chain_work = server
        .cfg
        .chain
        .chain_work(&hash)
        .map_err(|e| rpc_internal_err(&e))?;

    let common = verbose_block_common(server, &hash, &header)?;

    let median_time = server
        .cfg
        .chain
        .median_time_by_hash(&hash)
        .map_err(|e| rpc_internal_err(&e))?;

    Ok(GoValue::Struct(vec![
        GoValue::String(hash_str.to_string()),
        GoValue::String(common.pow_hash.to_string()),
        GoValue::Int(common.confirmations),
        GoValue::Int(i64::from(header.version)),
        GoValue::String(header.merkle_root.to_string()),
        GoValue::String(header.stake_root.to_string()),
        GoValue::Uint(u64::from(header.vote_bits)),
        GoValue::String(hex_str(&header.final_state)),
        GoValue::Uint(u64::from(header.voters)),
        GoValue::Uint(u64::from(header.fresh_stake)),
        GoValue::Uint(u64::from(header.revocations)),
        GoValue::Uint(u64::from(header.pool_size)),
        GoValue::String(format!("{:x}", header.bits)),
        GoValue::Float64(txresults::to_coin(header.sbits)),
        GoValue::Uint(u64::from(header.height)),
        GoValue::Uint(u64::from(header.size)),
        GoValue::Int(i64::from(header.timestamp)),
        GoValue::Int(median_time),
        GoValue::Uint(u64::from(header.nonce)),
        GoValue::String(hex_str(&header.extra_data)),
        GoValue::Uint(u64::from(header.stake_version)),
        GoValue::Float64(crate::helpers::get_difficulty_ratio(
            header.bits,
            server.cfg.chain_params.pow_limit_bits,
        )),
        GoValue::String(format!("{chain_work:064x}")),
        GoValue::String(header.prev_block.to_string()),
        GoValue::String(common.next_hash_string),
    ]))
}

/// handlegetblock (dcrd `handleGetBlock`); the verbose result is a
/// `GetBlockVerboseResult` value and the non-verbose result is the
/// serialized block hex string.
pub fn handle_get_block<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_str = s(&c[0]);
    let verbose = opt_bool(&c[1]);
    let verbose_tx = opt_bool(&c[2]);

    // Load the raw block bytes from the database.  Note the parsed
    // hash renders into the not-found message, unlike getblockheader.
    let hash: Hash = hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(hash_str))?;
    let block =
        server.cfg.chain.block_by_hash(&hash).map_err(|_| {
            RPCError::new(codes::BLOCK_NOT_FOUND, &format!("Block not found: {hash}"))
        })?;

    // When the verbose flag isn't set, simply return the
    // network-serialized block as a hex-encoded string.
    if let Some(false) = verbose {
        return Ok(GoValue::String(hex_str(&block.serialize())));
    }

    let chain_work = server
        .cfg
        .chain
        .chain_work(&hash)
        .map_err(|e| rpc_internal_err(&e))?;

    let header = block.header;
    let common = verbose_block_common(server, &hash, &header)?;

    let sbits_float = header.sbits as f64 / 1e8;

    let median_time = server
        .cfg
        .chain
        .median_time_by_hash(&hash)
        .map_err(|e| rpc_internal_err(&e))?;

    // Determine if the treasury rules are active for the block.
    let is_treasury_enabled = server.is_treasury_agenda_active(&header.prev_block)?;

    let (tx, raw_tx, stx, raw_stx);
    if !matches!(verbose_tx, Some(true)) {
        tx = GoValue::Array(
            block
                .transactions
                .iter()
                .map(|t| GoValue::String(t.tx_hash().to_string()))
                .collect(),
        );
        stx = GoValue::Array(
            block
                .stransactions
                .iter()
                .map(|t| GoValue::String(t.tx_hash().to_string()))
                .collect(),
        );
        raw_tx = GoValue::Null;
        raw_stx = GoValue::Null;
    } else {
        let block_hash_str = block.header.block_hash().to_string();
        let build = |txns: &[MsgTx]| -> Result<GoValue, RPCError> {
            let mut raw = Vec::with_capacity(txns.len());
            for (i, t) in txns.iter().enumerate() {
                raw.push(txresults::create_tx_raw_result(
                    &server.cfg.chain_params,
                    t,
                    &t.tx_hash().to_string(),
                    i as u32,
                    Some(&header),
                    &block_hash_str,
                    i64::from(header.height),
                    common.confirmations,
                    is_treasury_enabled,
                    server.cfg.max_protocol_version,
                    server.cfg.chain_params.net,
                )?);
            }
            Ok(GoValue::Array(raw))
        };
        raw_tx = build(&block.transactions)?;
        raw_stx = build(&block.stransactions)?;
        tx = GoValue::Null;
        stx = GoValue::Null;
    }

    Ok(GoValue::Struct(vec![
        GoValue::String(hash_str.to_string()),
        GoValue::String(common.pow_hash.to_string()),
        GoValue::Int(common.confirmations),
        GoValue::Int(i64::from(header.size as i32)),
        GoValue::Int(i64::from(header.height)),
        GoValue::Int(i64::from(header.version)),
        GoValue::String(header.merkle_root.to_string()),
        GoValue::String(header.stake_root.to_string()),
        tx,
        raw_tx,
        stx,
        raw_stx,
        GoValue::Int(i64::from(header.timestamp)),
        GoValue::Int(median_time),
        GoValue::Uint(u64::from(header.nonce)),
        GoValue::Uint(u64::from(header.vote_bits)),
        GoValue::String(hex_str(&header.final_state)),
        GoValue::Uint(u64::from(header.voters)),
        GoValue::Uint(u64::from(header.fresh_stake)),
        GoValue::Uint(u64::from(header.revocations)),
        GoValue::Uint(u64::from(header.pool_size)),
        GoValue::String(format!("{:x}", header.bits)),
        GoValue::Float64(sbits_float),
        GoValue::String(hex_str(&header.extra_data)),
        GoValue::Uint(u64::from(header.stake_version)),
        GoValue::Float64(crate::helpers::get_difficulty_ratio(
            header.bits,
            server.cfg.chain_params.pow_limit_bits,
        )),
        GoValue::String(format!("{chain_work:064x}")),
        GoValue::String(header.prev_block.to_string()),
        GoValue::String(common.next_hash_string),
    ]))
}

/// handlegetblockchaininfo (dcrd `handleGetBlockchainInfo`); the
/// result is a `GetBlockChainInfoResult` value.
pub fn handle_get_blockchain_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    let (_, best_header_height) = server.cfg.chain.best_header();

    // Fetch the current chain work using the best block hash.
    let chain_work = server
        .cfg
        .chain
        .chain_work(&best.hash)
        .map_err(|e| rpc_internal_err(&e))?;

    // Estimate the verification progress of the node.
    let mut verify_progress = 0.0f64;
    if best_header_height > 0 {
        let progress = best.height as f64 / best_header_height as f64;
        verify_progress = progress.min(1.0);
    }

    // Fetch the maximum allowed block size for all blocks other than
    // the genesis block.
    let zero_hash = Hash([0u8; 32]);
    let params = server.cfg.chain_params.clone();
    let mut max_block_size = params.maximum_block_sizes[0] as i64;
    if best.prev_hash != zero_hash {
        max_block_size = server
            .cfg
            .chain
            .max_block_size(&best.prev_hash)
            .map_err(|e| rpc_internal_err(&e))?;
    }

    // Fetch the agendas of the consensus deployments as well as their
    // threshold states and state activation heights.  The map is
    // filled per agenda id; the encoder emits it bytewise sorted,
    // matching Go.
    let mut d_info: Vec<(String, GoValue)> = Vec::new();
    for (_, deployments) in &params.deployments {
        for agenda in deployments {
            let mut status = crate::helpers::threshold::State::Defined;
            let mut since = 0i64;

            // If the best block is the genesis block, continue without
            // attempting to query the threshold state or state changed
            // height.
            if best.prev_hash != zero_hash {
                status = server
                    .cfg
                    .chain
                    .next_threshold_state(&best.prev_hash, agenda.vote.id)
                    .map_err(|e| rpc_internal_err(&e))?;

                since = server
                    .cfg
                    .chain
                    .state_last_changed_height(&best.hash, agenda.vote.id)
                    .map_err(|e| rpc_internal_err(&e))?;
            }

            d_info.push((
                agenda.vote.id.to_string(),
                GoValue::Struct(vec![
                    GoValue::String(status.status_string().to_string()),
                    GoValue::Int(since),
                    GoValue::Uint(agenda.start_time),
                    GoValue::Uint(agenda.expire_time),
                ]),
            ));
        }
    }

    Ok(GoValue::Struct(vec![
        GoValue::String(params.name.to_string()),
        GoValue::Int(best.height),
        GoValue::Int(best_header_height),
        GoValue::Int(server.cfg.sync_mgr.sync_height()),
        GoValue::String(best.hash.to_string()),
        GoValue::Uint(u64::from(best.bits)),
        GoValue::Float64(crate::helpers::get_difficulty_ratio(
            best.bits,
            params.pow_limit_bits,
        )),
        GoValue::Float64(verify_progress),
        GoValue::String(format!("{chain_work:064x}")),
        GoValue::Bool(!server.cfg.chain.is_current()),
        GoValue::Int(max_block_size),
        GoValue::Map(d_info),
    ]))
}

fn opt_bool(v: &GoValue) -> Option<bool> {
    match v {
        GoValue::Null => None,
        GoValue::Bool(b) => Some(*b),
        other => panic!("expected optional bool field, got {other:?}"),
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A compacted set of bit flags from a slice of bools (Go
/// `bitset.NewBytes` + `Set`, LSB first within each byte).
fn bitset_bytes(flags: &[bool]) -> Vec<u8> {
    let mut set = vec![0u8; (flags.len() + 7) >> 3];
    for (i, flag) in flags.iter().enumerate() {
        if *flag {
            set[i >> 3] |= 1 << (i & 7);
        }
    }
    set
}

/// handleestimatestakediff (dcrd `handleEstimateStakeDiff`); the
/// result is an `EstimateStakeDiffResult` value.
pub fn handle_estimate_stake_diff<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let tickets = opt_uint(&c[0]);

    // Minimum and maximum possible stake difficulty.
    let best = server.cfg.chain.best_snapshot();
    let min = server
        .cfg
        .chain
        .estimate_next_stake_difficulty(&best.hash, 0, false)
        .map_err(|e| rpc_internal_err(&e))?;
    let max = server
        .cfg
        .chain
        .estimate_next_stake_difficulty(&best.hash, 0, true)
        .map_err(|e| rpc_internal_err(&e))?;

    // The expected stake difficulty.  Average the number of fresh
    // stake since the last retarget to get the number of tickets per
    // block, then use that to estimate the next stake difficulty.
    let params = server.cfg.chain_params.clone();
    let best_height = best.height;
    let last_adjustment =
        (best_height / params.stake_diff_window_size) * params.stake_diff_window_size;
    let next_adjustment =
        ((best_height / params.stake_diff_window_size) + 1) * params.stake_diff_window_size;
    let mut total_tickets: i64 = 0;
    for i in last_adjustment..=best_height {
        let bh = server
            .cfg
            .chain
            .header_by_height(i)
            .map_err(|e| rpc_internal_err(&e))?;
        total_tickets += i64::from(bh.fresh_stake);
    }
    let blocks_since = (best_height - last_adjustment + 1) as f64;
    let remaining = (next_adjustment - best_height - 1) as f64;
    let average_per_block = total_tickets as f64 / blocks_since;
    let expected_tickets = (average_per_block * remaining).floor() as i64;
    let expected = server
        .cfg
        .chain
        .estimate_next_stake_difficulty(&best.hash, expected_tickets, false)
        .map_err(|e| rpc_internal_err(&e))?;

    // User-specified stake difficulty, if they asked for one.
    let mut user = GoValue::Null;
    if let Some(tickets) = tickets {
        let user_est = server
            .cfg
            .chain
            .estimate_next_stake_difficulty(&best.hash, tickets as i64, false)
            .map_err(|e| rpc_internal_err(&e))?;
        user = GoValue::Float64(txresults::to_coin(user_est));
    }

    Ok(GoValue::Struct(vec![
        GoValue::Float64(txresults::to_coin(min)),
        GoValue::Float64(txresults::to_coin(max)),
        GoValue::Float64(txresults::to_coin(expected)),
        user,
    ]))
}

/// handleexistsliveticket (dcrd `handleExistsLiveTicket`).
pub fn handle_exists_live_ticket<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let tx_hash_str = s(&c[0]);
    let hash: Hash = tx_hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(tx_hash_str))?;
    Ok(GoValue::Bool(server.cfg.chain.check_live_ticket(&hash)))
}

/// handleexistslivetickets (dcrd `handleExistsLiveTickets`): the
/// existence bits as a compacted hex string.
pub fn handle_exists_live_tickets<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_strs: Vec<String> = array(&c[0]).iter().map(|v| s(v).to_string()).collect();
    let hashes = crate::helpers::decode_hashes(&hash_strs)?;

    let exists = server.cfg.chain.check_live_tickets(&hashes);
    if exists.len() != hashes.len() {
        return Err(rpc_invalid_error(&format!(
            "Invalid live ticket count got {}, want {}",
            exists.len(),
            hashes.len()
        )));
    }

    Ok(GoValue::String(hex_str(&bitset_bytes(&exists))))
}

/// handlegetstakedifficulty (dcrd `handleGetStakeDifficulty`); the
/// result is a `GetStakeDifficultyResult` value.
pub fn handle_get_stake_difficulty<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    let header = server
        .cfg
        .chain
        .header_by_height(best.height)
        .map_err(|e| {
            RPCError::new(
                codes::DIFFICULTY,
                &format!("Error getting stake difficulty: {e}"),
            )
        })?;
    Ok(GoValue::Struct(vec![
        GoValue::Float64(txresults::to_coin(header.sbits)),
        GoValue::Float64(txresults::to_coin(best.next_stake_diff)),
    ]))
}

/// The stake version version:count maps as sorted `VersionCount`
/// values (dcrd `convertVersionMap` over the handler's maps).
fn version_counts(m: &std::collections::HashMap<i64, i64>) -> GoValue {
    GoValue::Array(
        crate::helpers::convert_version_map(m)
            .into_iter()
            .map(|(v, c)| {
                GoValue::Struct(vec![
                    GoValue::Uint(u64::from(v)),
                    GoValue::Uint(u64::from(c)),
                ])
            })
            .collect(),
    )
}

/// handlegetstakeversioninfo (dcrd `handleGetStakeVersionInfo`); the
/// result is a `GetStakeVersionInfoResult` value.
pub fn handle_get_stake_version_info<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let count_arg = opt_int(&c[0]);

    let snapshot = server.cfg.chain.best_snapshot();
    let interval = server.cfg.chain_params.stake_version_interval;

    let mut count: i32 = 1;
    if let Some(requested) = count_arg {
        count = requested as i32;
        if count <= 0 {
            return Err(rpc_invalid_error("Count must be > 0"));
        }

        // Limit the count to the total possible available intervals.
        let total_intervals = (snapshot.height + interval - 1) / interval;
        if i64::from(count) > total_intervals {
            count = total_intervals as i32;
        }
    }

    // Assemble the result.
    let mut intervals = Vec::with_capacity(count as usize);
    let mut start_height = snapshot.height;
    let mut end_height = server.cfg.chain.calc_want_height(interval, snapshot.height) + 1;
    let mut hash = snapshot.hash;
    let mut adjust: i32 = 1; // Off by one on the initial iteration.
    for _ in 0..count {
        let num_blocks = (start_height - end_height) as i32;
        if num_blocks <= 0 {
            // Just return what we got.
            break;
        }
        let sv = server
            .cfg
            .chain
            .get_stake_versions(&hash, num_blocks + adjust)
            .map_err(|e| rpc_internal_err(&e))?;

        let mut pos_versions = std::collections::HashMap::new();
        let mut vote_versions = std::collections::HashMap::new();
        for v in &sv {
            *pos_versions.entry(i64::from(v.stake_version)).or_insert(0) += 1;
            for vote in &v.votes {
                *vote_versions.entry(i64::from(vote.0)).or_insert(0) += 1;
            }
        }
        intervals.push(GoValue::Struct(vec![
            GoValue::Int(end_height),
            GoValue::Int(start_height),
            version_counts(&pos_versions),
            version_counts(&vote_versions),
        ]));

        // Adjust interval.
        end_height -= interval;
        start_height = end_height + interval;
        adjust = 0;

        // Get prior block hash.
        hash = server
            .cfg
            .chain
            .block_hash_by_height(start_height - 1)
            .map_err(|e| rpc_internal_err(&e))?;
    }

    Ok(GoValue::Struct(vec![
        GoValue::Int(snapshot.height),
        GoValue::String(snapshot.hash.to_string()),
        GoValue::Array(intervals),
    ]))
}

/// handlegetstakeversions (dcrd `handleGetStakeVersions`); the result
/// is a `GetStakeVersionsResult` value.
pub fn handle_get_stake_versions<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_str = s(&c[0]);
    let count = int(&c[1]);

    let hash: Hash = hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(hash_str))?;
    if count <= 0 {
        return Err(rpc_invalid_error("Invalid parameter, count must be > 0"));
    }

    let sv = server
        .cfg
        .chain
        .get_stake_versions(&hash, count as i32)
        .map_err(|e| rpc_internal_err(&e))?;

    let stake_versions: Vec<GoValue> = sv
        .iter()
        .map(|v| {
            GoValue::Struct(vec![
                GoValue::String(v.hash.to_string()),
                GoValue::Int(v.height),
                GoValue::Int(i64::from(v.block_version)),
                GoValue::Uint(u64::from(v.stake_version)),
                GoValue::Array(
                    v.votes
                        .iter()
                        .map(|&(version, bits)| {
                            GoValue::Struct(vec![
                                GoValue::Uint(u64::from(version)),
                                GoValue::Uint(u64::from(bits)),
                            ])
                        })
                        .collect(),
                ),
            ])
        })
        .collect();

    Ok(GoValue::Struct(vec![GoValue::Array(stake_versions)]))
}

/// handlegetvoteinfo (dcrd `handleGetVoteInfo`); the result is a
/// `GetVoteInfoResult` value.
pub fn handle_get_vote_info<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let version = uint(&c[0]) as u32;

    // Shorter versions of some parameters for convenience.
    let params = server.cfg.chain_params.clone();
    let interval = i64::from(params.rule_change_activation_interval);
    let quorum = params.rule_change_activation_quorum;
    let snapshot = server.cfg.chain.best_snapshot();

    let agendas = server
        .cfg
        .chain
        .get_vote_info(&snapshot.hash, version)
        .map_err(|failure| {
            if failure.is_unknown_deployment_version {
                return rpc_invalid_error(&format!("{version}: unrecognized vote version"));
            }
            rpc_internal_err(&failure.message)
        })?;

    let start_height = server.cfg.chain.calc_want_height(interval, snapshot.height) + 1;
    let end_height = server.cfg.chain.calc_want_height(interval, snapshot.height) + interval;

    // We don't fail, we try to return the totals for this version.
    let total_votes = server
        .cfg
        .chain
        .count_vote_version(version)
        .map_err(|e| rpc_internal_err(&e))?;

    let mut result_agendas = Vec::with_capacity(agendas.len());
    for agenda in &agendas {
        // Obtain status of agenda.
        let state = server
            .cfg
            .chain
            .next_threshold_state(&snapshot.hash, agenda.vote.id)
            .map_err(|e| rpc_internal_err(&e))?;

        let mut quorum_progress = 0.0f64;
        let mut choice_counts: Vec<u32> = vec![0; agenda.vote.choices.len()];
        let mut choice_progress: Vec<f64> = vec![0.0; agenda.vote.choices.len()];
        if state == crate::helpers::threshold::State::Started {
            let counts = server
                .cfg
                .chain
                .get_vote_counts(version, agenda.vote.id)
                .map_err(|e| rpc_internal_err(&e))?;

            // Calculate quorum.
            let mut qmin = quorum;
            let total_non_abstain = counts.total - counts.total_abstain;
            if total_non_abstain < quorum {
                qmin = total_non_abstain;
            }
            quorum_progress = f64::from(qmin) / f64::from(quorum);

            // Calculate choice progress.
            for k in 0..choice_counts.len() {
                choice_counts[k] = counts.vote_choices[k];
                choice_progress[k] = f64::from(counts.vote_choices[k]) / f64::from(counts.total);
            }
        }

        let choices: Vec<GoValue> = agenda
            .vote
            .choices
            .iter()
            .enumerate()
            .map(|(k, choice)| {
                GoValue::Struct(vec![
                    GoValue::String(choice.id.to_string()),
                    GoValue::String(choice.description.to_string()),
                    GoValue::Uint(u64::from(choice.bits)),
                    GoValue::Bool(choice.is_abstain),
                    GoValue::Bool(choice.is_no),
                    GoValue::Uint(u64::from(choice_counts[k])),
                    GoValue::Float64(choice_progress[k]),
                ])
            })
            .collect();

        result_agendas.push(GoValue::Struct(vec![
            GoValue::String(agenda.vote.id.to_string()),
            GoValue::String(agenda.vote.description.to_string()),
            GoValue::Uint(u64::from(agenda.vote.mask)),
            GoValue::Uint(agenda.start_time),
            GoValue::Uint(agenda.expire_time),
            GoValue::String(state.status_string().to_string()),
            GoValue::Float64(quorum_progress),
            GoValue::Array(choices),
        ]));
    }

    Ok(GoValue::Struct(vec![
        GoValue::Int(snapshot.height),
        GoValue::Int(start_height),
        GoValue::Int(end_height),
        GoValue::String(snapshot.hash.to_string()),
        GoValue::Uint(u64::from(version)),
        GoValue::Uint(u64::from(quorum)),
        GoValue::Uint(u64::from(total_votes)),
        GoValue::Array(result_agendas),
    ]))
}

/// handlegetticketpoolvalue (dcrd `handleGetTicketPoolValue`).
pub fn handle_get_ticket_pool_value<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let amt = server
        .cfg
        .chain
        .ticket_pool_value()
        .map_err(|e| rpc_internal_err(&e))?;
    Ok(GoValue::Float64(txresults::to_coin(amt)))
}

/// handlegettreasurybalance (dcrd `handleGetTreasuryBalance`); the
/// result is a `GetTreasuryBalanceResult` value.
pub fn handle_get_treasury_balance<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_arg = match &c[0] {
        GoValue::Null => None,
        GoValue::String(s) => Some(s.as_str()),
        other => panic!("expected optional string field, got {other:?}"),
    };
    let verbose = opt_bool(&c[1]);

    // Either parse the provided hash or use the current best tip hash
    // when none is provided.
    let hash = match hash_arg {
        None | Some("") => server.cfg.chain.best_snapshot().hash,
        Some(hash_str) => hash_str
            .parse()
            .map_err(|_| rpc_decode_hex_error(hash_str))?,
    };

    let balance_info = server
        .cfg
        .chain
        .treasury_balance(&hash)
        .map_err(|failure| {
            if failure.is_unknown_block {
                return RPCError::new(codes::BLOCK_NOT_FOUND, &format!("Block not found: {hash}"));
            }
            if failure.is_no_treasury_balance {
                return RPCError::new(
                    codes::NO_TREASURY,
                    &format!("Treasury inactive for block {hash}"),
                );
            }
            rpc_internal_err(&failure.message)
        })?;

    let updates = if matches!(verbose, Some(true)) {
        GoValue::Array(
            balance_info
                .updates
                .iter()
                .map(|&u| GoValue::Int(u))
                .collect(),
        )
    } else {
        GoValue::Null
    };
    Ok(GoValue::Struct(vec![
        GoValue::String(hash.to_string()),
        GoValue::Int(balance_info.block_height),
        GoValue::Uint(balance_info.balance),
        updates,
    ]))
}

/// handlelivetickets (dcrd `handleLiveTickets`); the result is a
/// `LiveTicketsResult` value.
pub fn handle_live_tickets<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let lt = server
        .cfg
        .chain
        .live_tickets()
        .map_err(|e| rpc_internal_err(&e))?;
    Ok(GoValue::Struct(vec![GoValue::Array(
        lt.iter().map(|h| GoValue::String(h.to_string())).collect(),
    )]))
}

/// Go `strconv.ParseUint(s, 10, 32)` acceptance: non-empty ASCII
/// digits without a sign, within 32 bits.
fn go_parse_uint32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().and_then(|v| u32::try_from(v).ok())
}

/// Go `net.ParseIP` acceptance for the target forms the node handler
/// distinguishes (plain IPv4/IPv6 literals).
fn go_parse_ip_ok(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// handleaddnode (dcrd `handleAddNode`): no data unless an error.
pub fn handle_add_node<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let (addr_arg, sub_cmd) = (s(&c[0]), s(&c[1]));

    let default_port = server.cfg.chain_params.default_port;
    let addr =
        crate::helpers::normalize_address(&mut *server.cfg.interfaces, addr_arg, default_port);
    let result = match sub_cmd {
        "add" => server.cfg.conn_mgr.connect(&addr, true),
        "remove" => server.cfg.conn_mgr.remove_by_addr(&addr),
        "onetry" => server.cfg.conn_mgr.connect(&addr, false),
        _ => return Err(rpc_invalid_error("Invalid subcommand for addnode")),
    };

    result.map_err(|e| rpc_invalid_error(&format!("{sub_cmd}: {e}")))?;

    // No data returned unless an error.
    Ok(GoValue::Null)
}

/// Whether a peer with the given address or id is currently connected
/// (dcrd `peerExists`).
fn peer_exists<C: RpcChain>(server: &mut Server<C>, addr: &str, node_id: i32) -> bool {
    server
        .cfg
        .conn_mgr
        .connected_peers()
        .iter()
        .any(|p| p.id == node_id || p.addr == addr)
}

/// handlenode (dcrd `handleNode`): no data unless an error.
pub fn handle_node<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let (sub_cmd, target) = (s(&c[0]).to_string(), s(&c[1]).to_string());
    let connect_sub_cmd = match &c[2] {
        GoValue::Null => None,
        GoValue::String(s) => Some(s.clone()),
        other => panic!("expected optional string field, got {other:?}"),
    };

    let default_port = server.cfg.chain_params.default_port;
    let mut addr = String::new();
    let mut node_id: u32 = 0;
    let result = match sub_cmd.as_str() {
        "disconnect" => {
            // If we have a valid uint disconnect by node id.  Otherwise,
            // attempt to disconnect by address, returning an error if a
            // valid IP address is not supplied.
            if let Some(id) = go_parse_uint32(&target) {
                node_id = id;
                server.cfg.conn_mgr.disconnect_by_id(id as i32)
            } else if crate::helpers::split_host_port(&target).is_ok() || go_parse_ip_ok(&target) {
                addr = crate::helpers::normalize_address(
                    &mut *server.cfg.interfaces,
                    &target,
                    default_port,
                );
                server.cfg.conn_mgr.disconnect_by_addr(&addr)
            } else {
                return Err(rpc_invalid_error(&format!(
                    "{sub_cmd}: Invalid address or node ID"
                )));
            }
        }
        "remove" => {
            if let Some(id) = go_parse_uint32(&target) {
                node_id = id;
                server.cfg.conn_mgr.remove_by_id(id as i32)
            } else if crate::helpers::split_host_port(&target).is_ok() || go_parse_ip_ok(&target) {
                addr = crate::helpers::normalize_address(
                    &mut *server.cfg.interfaces,
                    &target,
                    default_port,
                );
                server.cfg.conn_mgr.remove_by_addr(&addr)
            } else {
                return Err(rpc_invalid_error(&format!(
                    "{sub_cmd}: invalid address or node ID"
                )));
            }
        }
        "connect" => {
            addr = crate::helpers::normalize_address(
                &mut *server.cfg.interfaces,
                &target,
                default_port,
            );

            // Default to temporary connections.
            let sub = connect_sub_cmd.as_deref().unwrap_or("temp");
            match sub {
                "perm" | "temp" => server.cfg.conn_mgr.connect(&addr, sub == "perm"),
                _ => {
                    return Err(rpc_invalid_error(&format!(
                        "{sub}: invalid subcommand for node connect"
                    )));
                }
            }
        }
        _ => {
            return Err(rpc_invalid_error(&format!(
                "{sub_cmd}: invalid subcommand for node"
            )));
        }
    };

    if let Err(err) = result {
        // The permanence hints only apply when the peer is known.
        if peer_exists(server, &addr, node_id as i32) {
            match sub_cmd.as_str() {
                "disconnect" => {
                    return Err(crate::rpcerrors::rpc_misc_error(
                        "can't disconnect a permanent peer, use remove",
                    ));
                }
                "remove" => {
                    return Err(crate::rpcerrors::rpc_misc_error(
                        "can't remove a temporary peer, use disconnect",
                    ));
                }
                _ => {}
            }
        }
        return Err(rpc_invalid_error(&format!("{sub_cmd}: {err}")));
    }

    // No data returned unless an error.
    Ok(GoValue::Null)
}

/// handlegetconnectioncount (dcrd `handleGetConnectionCount`).
pub fn handle_get_connection_count<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Int(i64::from(
        server.cfg.conn_mgr.connected_count(),
    )))
}

/// handlegetnettotals (dcrd `handleGetNetTotals`); the result is a
/// `GetNetTotalsResult` value.
pub fn handle_get_net_totals<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let (total_bytes_recv, total_bytes_sent) = server.cfg.conn_mgr.net_totals();
    Ok(GoValue::Struct(vec![
        GoValue::Uint(total_bytes_recv),
        GoValue::Uint(total_bytes_sent),
        GoValue::Int(server.cfg.clock.now_unix_millis()),
    ]))
}

/// handleping (dcrd `handlePing`): asks the server to ping all peers.
pub fn handle_ping<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let nonce = (server.cfg.rand_u64)();
    server
        .cfg
        .conn_mgr
        .broadcast_message(&Message::Ping(dcroxide_wire::MsgPing { nonce }));
    Ok(GoValue::Null)
}

/// handlegetmempoolinfo (dcrd `handleGetMempoolInfo`); the result is
/// a `GetMempoolInfoResult` value.
pub fn handle_get_mempool_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let mempool_txns = server.cfg.tx_mempooler.tx_descs();

    let mut num_bytes: i64 = 0;
    for tx_d in &mempool_txns {
        num_bytes += tx_d.tx.serialize_size() as i64;
    }

    Ok(GoValue::Struct(vec![
        GoValue::Int(mempool_txns.len() as i64),
        GoValue::Int(num_bytes),
    ]))
}

/// handlegetrawmempool (dcrd `handleGetRawMempool`); the verbose
/// result is a map of `GetRawMempoolVerboseResult` values keyed by
/// transaction hash and the plain result is the hash list.
pub fn handle_get_raw_mempool<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let verbose = opt_bool(&c[0]);
    let tx_type_arg = match &c[1] {
        GoValue::Null => None,
        GoValue::String(s) => Some(s.as_str()),
        other => panic!("expected optional string field, got {other:?}"),
    };

    // Choose the type to filter the results by based on the provided
    // param.  A filter type of None means no filtering.
    use dcroxide_stake::TxType;
    let mut filter_type: Option<TxType> = None;
    if let Some(tx_type) = tx_type_arg {
        match tx_type {
            "regular" => filter_type = Some(TxType::Regular),
            "tickets" => filter_type = Some(TxType::SStx),
            "votes" => filter_type = Some(TxType::SSGen),
            "revocations" => filter_type = Some(TxType::SSRtx),
            "tspend" => filter_type = Some(TxType::TSpend),
            "tadd" => filter_type = Some(TxType::TAdd),
            "all" => {}
            other => {
                return Err(rpc_invalid_error(&format!(
                    "Invalid transaction type: {other} -- supported types: \
                     [regular tickets votes revocations tspend tadd all]"
                )));
            }
        }
    }

    // Return verbose results if requested.
    if matches!(verbose, Some(true)) {
        let descs = server.cfg.tx_mempooler.verbose_tx_descs();
        let mut result: Vec<(String, GoValue)> = Vec::with_capacity(descs.len());
        for desc in &descs {
            if let Some(filter) = filter_type
                && desc.tx_type != filter
            {
                continue;
            }

            let depends: Vec<GoValue> = desc
                .depends
                .iter()
                .map(|h| GoValue::String(h.to_string()))
                .collect();
            result.push((
                desc.tx.tx_hash().to_string(),
                GoValue::Struct(vec![
                    GoValue::Int(desc.tx.serialize_size() as i64),
                    GoValue::Float64(txresults::to_coin(desc.fee)),
                    GoValue::Int(desc.added_unix),
                    GoValue::Int(desc.height),
                    GoValue::Float64(0.0),
                    GoValue::Float64(0.0),
                    GoValue::Array(depends),
                ]),
            ));
        }

        return Ok(GoValue::Map(result));
    }

    // The response is simply an array of the transaction hashes if the
    // verbose flag is not set.
    let descs = server.cfg.tx_mempooler.tx_descs();
    let mut hash_strings = Vec::with_capacity(descs.len());
    for desc in &descs {
        if let Some(filter) = filter_type
            && desc.tx_type != filter
        {
            continue;
        }
        hash_strings.push(GoValue::String(desc.tx.tx_hash().to_string()));
    }
    Ok(GoValue::Array(hash_strings))
}

/// handleexistsmempooltxs (dcrd `handleExistsMempoolTxs`): the
/// existence bits as a compacted hex string.
pub fn handle_exists_mempool_txs<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_strs: Vec<String> = array(&c[0]).iter().map(|v| s(v).to_string()).collect();
    let hashes = crate::helpers::decode_hash_pointers(&hash_strs)?;

    let exists = server.cfg.tx_mempooler.have_transactions(&hashes);
    if exists.len() != hashes.len() {
        return Err(rpc_internal_err(&format!(
            "got {}, want {}",
            exists.len(),
            hashes.len()
        )));
    }

    Ok(GoValue::String(hex_str(&bitset_bytes(&exists))))
}

/// handlegetrawtransaction (dcrd `handleGetRawTransaction`); the
/// verbose result is a `TxRawResult` value and the non-verbose
/// result is the serialized transaction hex string.
pub fn handle_get_raw_transaction<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let txid = s(&c[0]);
    let verbose = opt_int(&c[1]).is_some_and(|v| v != 0);

    // Convert the provided transaction hash hex to a Hash.
    let tx_hash: Hash = txid.parse().map_err(|_| rpc_decode_hex_error(txid))?;

    // Try to fetch the transaction from the memory pool and if that
    // fails, try the block database.
    let mtx: MsgTx;
    let mut blk_hash: Option<Hash> = None;
    let mut blk_height: i64 = 0;
    let mut blk_index: u32 = 0;
    match server.cfg.tx_mempooler.fetch_transaction(&tx_hash) {
        Err(_) => {
            let Some(tx_index) = server.cfg.tx_indexer.as_mut() else {
                return Err(rpc_internal_err(
                    "the transaction index must be enabled to query the \
                     blockchain (specify --txindex)",
                ));
            };

            // Ensure the tx index is synced.
            let (t_height, t_hash) = tx_index.tip().map_err(|e| rpc_internal_err(&e))?;

            // Return an out-of-sync error if the index is lagging a
            // maximum reorg depth (6) blocks or more from the chain
            // tip.
            let index_name = tx_index.name();
            if server.cfg.chain.best_snapshot().height > t_height + 5 {
                return Err(rpc_internal_err(&format!("{index_name}: index not synced")));
            }

            // Wait for the index to catch up to the current best tip,
            // failing after dcrd's three second timeout.
            if server.cfg.chain.best_snapshot().hash != t_hash {
                let tx_index = server.cfg.tx_indexer.as_mut().expect("checked above");
                if !tx_index.wait_for_sync() {
                    return Err(rpc_internal_err(&format!("{index_name}: index not synced")));
                }
            }

            // Look up the location of the transaction.
            let tx_index = server.cfg.tx_indexer.as_mut().expect("checked above");
            let idx_entry = tx_index.entry(&tx_hash).map_err(|e| rpc_internal_err(&e))?;
            let Some(idx_entry) = idx_entry else {
                return Err(crate::rpcerrors::rpc_no_tx_info_error(&tx_hash));
            };

            // Load the raw transaction bytes from the database.
            let tx_bytes = server
                .cfg
                .db
                .fetch_block_region(&idx_entry.block_hash, idx_entry.offset, idx_entry.len)
                .map_err(|_| crate::rpcerrors::rpc_no_tx_info_error(&tx_hash))?;

            // When the verbose flag isn't set, simply return the
            // serialized transaction as a hex-encoded string.  This is
            // done here to avoid deserializing it only to reserialize
            // it again later.
            if !verbose {
                return Ok(GoValue::String(hex_str(&tx_bytes)));
            }

            // Grab the block details.
            blk_hash = Some(idx_entry.block_hash);
            blk_height = server
                .cfg
                .chain
                .block_height_by_hash(&idx_entry.block_hash)
                .map_err(|e| rpc_internal_err(&e))?;
            blk_index = idx_entry.block_index;

            // Deserialize the transaction.
            let (msg_tx, _) =
                MsgTx::from_bytes(&tx_bytes).map_err(|e| rpc_internal_err(&format!("{e:?}")))?;
            mtx = msg_tx;
        }
        Ok((tx, _tree)) => {
            // When the verbose flag isn't set, simply return the
            // network-serialized transaction as a hex-encoded string.
            if !verbose {
                let mtx_hex =
                    txresults::message_to_hex(&Message::Tx(tx), server.cfg.max_protocol_version)?;
                return Ok(GoValue::String(mtx_hex));
            }

            mtx = tx;
        }
    }

    // The verbose flag is set, so generate the JSON object and return
    // it.
    let mut blk_header = None;
    let prev_blk_hash;
    let mut blk_hash_str = String::new();
    let mut confirmations: i64 = 0;
    if let Some(blk_hash) = blk_hash {
        // Fetch the header from chain.
        let header = server
            .cfg
            .chain
            .header_by_hash(&blk_hash)
            .map_err(|e| rpc_internal_err(&e))?;

        prev_blk_hash = header.prev_block;
        blk_header = Some(header);
        blk_hash_str = blk_hash.to_string();
        confirmations = 1 + server.cfg.chain.best_snapshot().height - blk_height;
    } else {
        // The transaction was obtained from the mempool when there is
        // no block hash set, so the previous block hash is the current
        // best chain tip in that case.
        prev_blk_hash = server.cfg.chain.best_snapshot().hash;
    }

    // Determine if the treasury rules are active as of either the
    // block that contains the transaction or the current best tip when
    // it is in the mempool.
    let is_treasury_enabled = server.is_treasury_agenda_active(&prev_blk_hash)?;

    txresults::create_tx_raw_result(
        &server.cfg.chain_params,
        &mtx,
        &tx_hash.to_string(),
        blk_index,
        blk_header.as_ref(),
        &blk_hash_str,
        blk_height,
        confirmations,
        is_treasury_enabled,
        server.cfg.max_protocol_version,
        server.cfg.chain_params.net,
    )
}

/// handlegettxout (dcrd `handleGetTxOut`); the result is a
/// `GetTxOutResult` value, or null when the output does not exist or
/// is spent.
pub fn handle_get_tx_out<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let txid = s(&c[0]);
    let vout = uint(&c[1]) as u32;
    let tree = int(&c[2]) as i8;
    let include_mempool = opt_bool(&c[3]).unwrap_or(true);

    // Convert the provided transaction hash hex to a Hash.
    let tx_hash: Hash = txid.parse().map_err(|_| rpc_decode_hex_error(txid))?;

    if !(tree == 0 || tree == 1) {
        return Err(rpc_invalid_error("Tx tree must be regular or stake"));
    }

    let best = server.cfg.chain.best_snapshot();

    // If requested and the tx is available in the mempool try to fetch
    // it from there, otherwise attempt to fetch from the block
    // database.
    let mut tx_from_mempool: Option<MsgTx> = None;
    if include_mempool
        && let Ok((tx, tx_tree)) = server.cfg.tx_mempooler.fetch_transaction(&tx_hash)
    {
        // Skip the mempool hit if the tx tree does not match the tree
        // param that was passed; it is technically possible (though
        // extremely unlikely) that the tx exists elsewhere.
        if tx_tree == tree {
            tx_from_mempool = Some(tx);
        }
    }

    let (best_block_hash, confirmations, value, script_version, pk_script, is_coinbase);
    if let Some(mtx) = &tx_from_mempool {
        if vout > (mtx.tx_out.len() as u32).wrapping_sub(1) {
            return Err(RPCError::new(
                codes::INVALID_TX_VOUT,
                "Output index number (vout) does not exist for transaction.",
            ));
        }

        // dcrd also guards against a nil *wire.TxOut in the slice
        // here; outputs cannot be nil in this representation.
        let tx_out = &mtx.tx_out[vout as usize];

        // The transaction output in question is from the mempool, so
        // determine if the treasury rules are active from the point of
        // view of the current best tip.
        let is_treasury_enabled = server.is_treasury_agenda_active(&best.prev_hash)?;

        best_block_hash = best.hash.to_string();
        confirmations = 0i64;
        value = tx_out.value;
        script_version = tx_out.version;
        pk_script = tx_out.pk_script.clone();
        is_coinbase = dcroxide_standalone::is_coin_base_tx(mtx, is_treasury_enabled);
    } else {
        let entry = server
            .cfg
            .chain
            .fetch_utxo_entry(&tx_hash, vout, tree)
            .map_err(|e| rpc_internal_err(&e))?;

        // To match the behavior of the reference client, return nil
        // (JSON null) if the transaction output could not be found
        // (never existed or was pruned) or is spent by another
        // transaction already in the main chain.  Mined transactions
        // that are spent by a mempool transaction are not affected by
        // this.
        let Some(entry) = entry else {
            return Ok(GoValue::Null);
        };
        if entry.is_spent {
            return Ok(GoValue::Null);
        }

        best_block_hash = best.hash.to_string();
        confirmations = 1 + best.height - entry.block_height;
        value = entry.amount;
        script_version = entry.script_version;
        pk_script = entry.pk_script;
        is_coinbase = entry.is_coinbase;
    }

    // Disassemble script into single line printable format.  The
    // disassembled string will contain [error] inline if the script
    // doesn't fully parse, so ignore the error here.
    let (disbuf, _) = dcroxide_txscript::disasm_string(&pk_script);

    // Attempt to extract known addresses associated with the script.
    let params = server.cfg.chain_params.clone();
    let (script_type, addrs) =
        dcroxide_txscript::stdscript::extract_addrs(script_version, &pk_script, &params);
    let addresses: Vec<GoValue> = addrs
        .iter()
        .map(|addr| GoValue::String(addr.to_string()))
        .collect();

    // Determine the number of required signatures for known standard
    // types.
    let req_sigs =
        dcroxide_txscript::stdscript::determine_required_sigs(script_version, &pk_script);

    Ok(GoValue::Struct(vec![
        GoValue::String(best_block_hash),
        GoValue::Int(confirmations),
        GoValue::Float64(txresults::to_coin(value)),
        GoValue::Struct(vec![
            GoValue::String(disbuf),
            GoValue::String(hex_str(&pk_script)),
            GoValue::Int(i64::from(req_sigs as i32)),
            GoValue::String(script_type.to_string()),
            GoValue::Array(addresses),
            GoValue::Null,
            GoValue::Uint(u64::from(script_version)),
        ]),
        GoValue::Bool(is_coinbase),
    ]))
}

/// handlegettxoutsetinfo (dcrd `handleGetTxOutSetInfo`); the result
/// is a `GetTxOutSetInfoResult` value.  Note dcrd returns the bare
/// stats error which its dispatch layer wraps; the wrapped internal
/// error stands in until the dispatch layer is ported.
pub fn handle_get_tx_out_set_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();
    let stats = server
        .cfg
        .chain
        .fetch_utxo_stats()
        .map_err(|e| rpc_internal_err(&e))?;

    Ok(GoValue::Struct(vec![
        GoValue::Int(best.height),
        GoValue::String(best.hash.to_string()),
        GoValue::Int(stats.transactions),
        GoValue::Int(stats.utxos),
        GoValue::String(stats.serialized_hash.to_string()),
        GoValue::Int(stats.size),
        GoValue::Int(stats.total),
    ]))
}

/// handlegetcfilterv2 (dcrd `handleGetCFilterV2`); the result is a
/// `GetCFilterV2Result` value.
pub fn handle_get_cfilter_v2<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let block_hash_str = s(&c[0]);
    let hash: Hash = block_hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(block_hash_str))?;

    let proof = server
        .cfg
        .filterer_v2
        .filter_by_block_hash(&hash)
        .map_err(|failure| {
            if failure.is_no_filter {
                return RPCError::new(codes::BLOCK_NOT_FOUND, &format!("Block not found: {hash}"));
            }
            rpc_internal_err(&failure.message)
        })?;

    // dcrd allocates a zero-length proof hash slice and assigns into
    // it by index, which panics for any non-empty proof; the header
    // commitment has a single leaf so proofs are always empty in
    // practice, and the panic is mirrored deliberately.
    if !proof.proof_hashes.is_empty() {
        panic!("getcfilterv2: non-empty proof hashes are unreachable in dcrd");
    }

    Ok(GoValue::Struct(vec![
        GoValue::String(block_hash_str.to_string()),
        GoValue::String(hex_str(&proof.filter_bytes)),
        GoValue::Uint(u64::from(proof.proof_index)),
        GoValue::Null,
    ]))
}

/// handlegetpeerinfo (dcrd `handleGetPeerInfo`); the result is a
/// slice of `GetPeerInfoResult` values sorted by peer id.
pub fn handle_get_peer_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let peers = server.cfg.conn_mgr.connected_peers();
    let sync_peer_id = server.cfg.sync_mgr.sync_peer_id();
    let mut infos: Vec<(i32, GoValue)> = Vec::with_capacity(peers.len());
    for p in &peers {
        let addr_local = p.local_addr.clone().unwrap_or_default();
        let mut ping_wait = GoValue::Float64(0.0);
        if p.last_ping_nonce != 0 {
            let wait = server.cfg.clock.since_nanos(p.last_ping_time_unix_nanos) as f64;
            // We actually want microseconds.
            ping_wait = GoValue::Float64(wait / 1000.0);
        }
        infos.push((
            p.id,
            GoValue::Struct(vec![
                GoValue::Int(i64::from(p.id)),
                GoValue::String(p.addr.clone()),
                GoValue::String(addr_local),
                GoValue::String(format!("{:08}", p.services)),
                GoValue::Bool(!p.tx_relay_disabled),
                GoValue::Int(p.last_send_unix),
                GoValue::Int(p.last_recv_unix),
                GoValue::Uint(p.bytes_sent),
                GoValue::Uint(p.bytes_recv),
                GoValue::Int(p.conn_time_unix),
                GoValue::Int(p.time_offset),
                GoValue::Float64(p.last_ping_micros as f64),
                ping_wait,
                GoValue::Uint(u64::from(p.version)),
                GoValue::String(p.user_agent.clone()),
                GoValue::Bool(p.inbound),
                GoValue::Int(p.starting_height),
                GoValue::Int(p.last_block),
                GoValue::Int(i64::from(p.ban_score as i32)),
                GoValue::Bool(p.id == sync_peer_id),
            ]),
        ));
    }
    infos.sort_by_key(|(id, _)| *id);
    Ok(GoValue::Array(infos.into_iter().map(|(_, v)| v).collect()))
}

/// handlegetaddednodeinfo (dcrd `handleGetAddedNodeInfo`); the
/// result is either the address list or a slice of
/// `GetAddedNodeInfoResult` values when the dns flag is set.
pub fn handle_get_added_node_info<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let dns = match &c[0] {
        GoValue::Bool(b) => *b,
        other => panic!("expected bool field, got {other:?}"),
    };
    let node = match &c[1] {
        GoValue::Null => None,
        GoValue::String(s) => Some(s.clone()),
        other => panic!("expected optional string field, got {other:?}"),
    };

    // Retrieve a list of persistent (added) peers and filter the list
    // per the specified address (if any).  dcrd reslices under a range
    // over the original list, so the last match wins.
    let mut peers = server.cfg.conn_mgr.persistent_peers();
    if let Some(node) = &node {
        let mut found = None;
        for (i, peer) in peers.iter().enumerate() {
            if peer.addr == *node {
                found = Some(i);
            }
        }
        let Some(i) = found else {
            return Err(rpc_internal_err("node not found"));
        };
        peers = vec![peers[i].clone()];
    }

    // Without the dns flag, the result is just a slice of the
    // addresses as strings.
    if !dns {
        return Ok(GoValue::Array(
            peers
                .iter()
                .map(|peer| GoValue::String(peer.addr.clone()))
                .collect(),
        ));
    }

    // With the dns flag, the result is an array of JSON objects which
    // include the result of DNS lookups for each peer.
    let mut results = Vec::with_capacity(peers.len());
    for peer in &peers {
        // Split the address into host and port portions so we can do
        // a DNS lookup against the host.  When no port is specified in
        // the address, just use the address as the host.
        let host = match crate::helpers::split_host_port(&peer.addr) {
            Ok((host, _)) => host,
            Err(()) => peer.addr.clone(),
        };

        // Do a DNS lookup for the address.  If the lookup fails, just
        // use the host.
        let ip_list = match server.cfg.conn_mgr.lookup(&host) {
            Ok(ips) => ips,
            Err(_) => vec![host.clone()],
        };

        // Add the addresses and connection info to the result.
        let addrs: Vec<GoValue> = ip_list
            .iter()
            .map(|ip| {
                let mut connected = "false";
                if *ip == host && peer.connected {
                    connected = crate::helpers::direction_string(peer.inbound);
                }
                GoValue::Struct(vec![
                    GoValue::String(ip.clone()),
                    GoValue::String(connected.to_string()),
                ])
            })
            .collect();
        results.push(GoValue::Struct(vec![
            GoValue::String(peer.addr.clone()),
            GoValue::Bool(peer.connected),
            GoValue::Array(addrs),
        ]));
    }
    Ok(GoValue::Array(results))
}

/// The exists-address index sync gauntlet shared by the two exists
/// handlers (mirrors the tx index handling).
fn exists_addr_index_synced<C: RpcChain>(server: &mut Server<C>) -> Result<(), RPCError> {
    let addresser = server.cfg.exists_addresser.as_mut().expect("checked");
    let (t_height, t_hash) = addresser.tip().map_err(|e| rpc_internal_err(&e))?;
    let index_name = addresser.name();

    // Return an out-of-sync error if the index is lagging a maximum
    // reorg depth (6) blocks or more from the chain tip.
    if server.cfg.chain.best_snapshot().height > t_height + 5 {
        return Err(rpc_internal_err(&format!("{index_name}: index not synced")));
    }

    if server.cfg.chain.best_snapshot().hash != t_hash {
        let addresser = server.cfg.exists_addresser.as_mut().expect("checked");
        if !addresser.wait_for_sync() {
            return Err(rpc_internal_err(&format!("{index_name}: index not synced")));
        }
    }
    Ok(())
}

/// handleexistsaddress (dcrd `handleExistsAddress`).
pub fn handle_exists_address<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    if server.cfg.exists_addresser.is_none() {
        return Err(rpc_internal_err("exists address index disabled"));
    }

    let c = fields(cmd);
    let address = s(&c[0]);

    // Decode the provided address.  This also ensures the network
    // encoded with the address matches the network the server is
    // currently on.
    let addr = stdaddr::decode_address(address, &server.cfg.chain_params)
        .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;

    // Ensure the exists address index is synced.
    exists_addr_index_synced(server)?;

    let addresser = server.cfg.exists_addresser.as_mut().expect("checked");
    let exists = addresser
        .exists_address(&addr)
        .map_err(|e| rpc_invalid_error(&format!("Could not query address: {e}")))?;

    Ok(GoValue::Bool(exists))
}

/// handleexistsaddresses (dcrd `handleExistsAddresses`): the
/// existence bits as a compacted hex string.
pub fn handle_exists_addresses<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    if server.cfg.exists_addresser.is_none() {
        return Err(rpc_internal_err("exists address index disabled"));
    }

    let c = fields(cmd);
    let address_strs: Vec<String> = array(&c[0]).iter().map(|v| s(v).to_string()).collect();
    let mut addresses = Vec::with_capacity(address_strs.len());
    for address in &address_strs {
        let addr = stdaddr::decode_address(address, &server.cfg.chain_params)
            .map_err(|e| rpc_address_key_error(&format!("Could not decode address: {e}")))?;
        addresses.push(addr);
    }

    // Ensure the exists address index is synced.
    exists_addr_index_synced(server)?;

    let addresser = server.cfg.exists_addresser.as_mut().expect("checked");
    let exists = addresser
        .exists_addresses(&addresses)
        .map_err(|e| rpc_invalid_error(&format!("Could not query address: {e}")))?;

    Ok(GoValue::String(hex_str(&bitset_bytes(&exists))))
}

/// handleticketsforaddress (dcrd `handleTicketsForAddress`); the
/// result is a `TicketsForAddressResult` value.
pub fn handle_tickets_for_address<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let address = s(&c[0]);

    // Decode the provided address.  This also ensures the network
    // encoded with the address matches the network the server is
    // currently on.
    let addr = stdaddr::decode_address(address, &server.cfg.chain_params)
        .map_err(|e| rpc_invalid_error(&format!("Invalid address: {e}")))?;

    // Only stake addresses participate in the staking system.
    if addr.voting_rights_script().is_none() {
        return Err(rpc_invalid_error(
            "Address is not valid for use in the staking system",
        ));
    }

    let tickets = server
        .cfg
        .chain
        .tickets_with_address(&addr)
        .map_err(|e| rpc_internal_err(&e))?;

    Ok(GoValue::Struct(vec![GoValue::Array(
        tickets
            .iter()
            .map(|t| GoValue::String(t.to_string()))
            .collect(),
    )]))
}

/// Go `hex.DecodeString` with its exact error text for the handlers
/// that surface it (`encoding/hex: invalid byte: %#U`).
fn go_decode_hex_msg(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("encoding/hex: odd length hex string".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        for &b in pair {
            if !(b as char).is_ascii_hexdigit() {
                return Err(format!(
                    "encoding/hex: invalid byte: U+{:04X} {:?}",
                    b, b as char
                ));
            }
        }
        let hi = (pair[0] as char).to_digit(16).expect("checked");
        let lo = (pair[1] as char).to_digit(16).expect("checked");
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// handlesendrawtransaction (dcrd `handleSendRawTransaction`): the
/// accepted transaction hash string.
pub fn handle_send_raw_transaction<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hex_tx = s(&c[0]);
    let allow_high_fees = opt_bool(&c[1]).unwrap_or(false);

    // Deserialize and send off to tx relay.
    let padded;
    let hex_str = if hex_tx.len() % 2 != 0 {
        padded = format!("0{hex_tx}");
        &padded
    } else {
        hex_tx
    };
    let serialized_tx = go_decode_hex(hex_str).map_err(|_| rpc_decode_hex_error(hex_str))?;
    let (msgtx, _) = MsgTx::from_bytes(&serialized_tx).map_err(|e| {
        let text = match e {
            dcroxide_wire::WireError::UnexpectedEof => "unexpected EOF".to_string(),
            other => other.to_string(),
        };
        rpc_deserialization_error(&format!("Could not decode Tx: {text}"))
    })?;

    // Use 0 for the tag to represent the local node.
    let tx_hash = msgtx.tx_hash();
    let accepted_txs =
        match server
            .cfg
            .sync_mgr
            .process_transaction(&msgtx, false, allow_high_fees, 0)
        {
            Ok(accepted) => accepted,
            Err(failure) => {
                if failure.is_rule_error {
                    let msg = format!("rejected transaction {tx_hash}: {}", failure.message);

                    // Use the duplicate tx error code when the transaction
                    // is known to already be submitted to the mempool, as
                    // well as whenever there is a high certainty that the
                    // transaction has been confirmed in a recent block.
                    if failure.is_duplicate || server.cfg.sync_mgr.recently_confirmed_txn(&tx_hash)
                    {
                        return Err(crate::rpcerrors::rpc_duplicate_tx_error(&msg));
                    }

                    // Return a generic rule error.
                    return Err(crate::rpcerrors::rpc_rule_error(&msg));
                }

                return Err(rpc_deserialization_error(&format!(
                    "rejected: failed to process transaction {tx_hash}: {}",
                    failure.message
                )));
            }
        };

    // Generate and relay inventory vectors for all newly accepted
    // transactions.  dcrd also notifies its websocket clients here;
    // that hook arrives with the websocket layer.
    server.cfg.conn_mgr.relay_transactions(&accepted_txs);

    // Keep track of the request transaction so it can be rebroadcast
    // if it doesn't make its way into a block.  Votes are only valid
    // for a specific block and are time sensitive, so they are not
    // added to the rebroadcast logic.
    let tx_type = dcroxide_stake::determine_tx_type(&msgtx);
    if tx_type != dcroxide_stake::TxType::SSGen {
        server
            .cfg
            .conn_mgr
            .add_rebroadcast_inventory(&tx_hash, &msgtx);
    }

    Ok(GoValue::String(tx_hash.to_string()))
}

/// handlesubmitblock (dcrd `handleSubmitBlock`): null on acceptance
/// or a rejection string.
pub fn handle_submit_block<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hex_block = s(&c[0]);

    // Deserialize the submitted block.  Note dcrd surfaces the raw
    // hex/deserialization error text through an internal error here.
    let padded;
    let hex_str = if hex_block.len() % 2 != 0 {
        padded = format!("0{hex_block}");
        &padded
    } else {
        hex_block
    };
    let serialized_block = go_decode_hex_msg(hex_str).map_err(|e| rpc_internal_err(&e))?;
    let block = match MsgBlock::from_bytes(&serialized_block) {
        Ok((block, _)) => block,
        Err(e) => {
            let text = match e {
                dcroxide_wire::WireError::UnexpectedEof => "unexpected EOF".to_string(),
                other => other.to_string(),
            };
            return Err(rpc_internal_err(&text));
        }
    };

    if let Err(err) = server.cfg.sync_mgr.submit_block(&block) {
        return Ok(GoValue::String(format!("rejected: {err}")));
    }

    Ok(GoValue::Null)
}

/// handleinvalidateblock (dcrd `handleInvalidateBlock`): no data
/// unless an error.
pub fn handle_invalidate_block<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let block_hash_str = s(&c[0]);
    let hash: Hash = block_hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(block_hash_str))?;

    server
        .cfg
        .chain
        .invalidate_block(&hash)
        .map_err(|failure| {
            if failure.is_unknown_block {
                return RPCError::new(codes::BLOCK_NOT_FOUND, &format!("Block not found: {hash}"));
            }
            if failure.is_invalidate_genesis {
                return rpc_invalid_error(&failure.message);
            }
            rpc_internal_err(&failure.message)
        })?;

    Ok(GoValue::Null)
}

/// handlereconsiderblock (dcrd `handleReconsiderBlock`): no data
/// unless an error.
pub fn handle_reconsider_block<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let block_hash_str = s(&c[0]);
    let hash: Hash = block_hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(block_hash_str))?;

    server
        .cfg
        .chain
        .reconsider_block(&hash)
        .map_err(|failure| {
            if failure.is_unknown_block {
                return RPCError::new(codes::BLOCK_NOT_FOUND, &format!("Block not found: {hash}"));
            }

            // Use a separate error code for failed validation.
            if failure.all_rule_errs {
                return RPCError::new(
                    codes::RECONSIDER_FAILURE,
                    &format!(
                        "Reconsidering block {hash} led to one or more validation \
                     failures: {}",
                        failure.message
                    ),
                );
            }

            // Fall back to an internal error.
            rpc_internal_err(&failure.message)
        })?;

    Ok(GoValue::Null)
}

/// handleregentemplate (dcrd `handleRegenTemplate`): no data unless
/// an error.
pub fn handle_regen_template<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let Some(bt) = server.cfg.block_templater.as_mut() else {
        return Err(rpc_internal_err("node is not configured for mining"));
    };
    bt.force_regen();
    Ok(GoValue::Null)
}

/// handledebuglevel (dcrd `handleDebugLevel`).
pub fn handle_debug_level<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let level_spec = s(&c[0]);

    // Special show command to list supported subsystems.
    if level_spec == "show" {
        let subsystems = server.cfg.log_manager.supported_subsystems();
        return Ok(GoValue::String(format!(
            "Supported subsystems [{}]",
            subsystems.join(" ")
        )));
    }

    server
        .cfg
        .log_manager
        .parse_and_set_debug_levels(level_spec)
        .map_err(|e| rpc_invalid_error(&format!("Invalid debug level {level_spec}: {e}")))?;

    Ok(GoValue::String("Done.".to_string()))
}

/// handleestimatesmartfee (dcrd `handleEstimateSmartFee`); the
/// result is an `EstimateSmartFeeResult` value.
pub fn handle_estimate_smart_fee<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let confirmations = int(&c[0]);
    let mode = match &c[1] {
        GoValue::Null => "conservative",
        GoValue::String(s) => s.as_str(),
        other => panic!("expected optional string field, got {other:?}"),
    };

    if mode != "conservative" {
        return Err(rpc_invalid_error(
            "Only the default and conservative modes are supported for smart \
             fee estimation at the moment",
        ));
    }

    let fee = server
        .cfg
        .fee_estimator
        .estimate_fee(confirmations as i32)
        .map_err(|e| rpc_internal_err(&e))?;

    Ok(GoValue::Struct(vec![
        GoValue::Float64(txresults::to_coin(fee)),
        GoValue::Null,
        GoValue::Int(confirmations),
    ]))
}

fn opt_float(v: &GoValue) -> Option<f64> {
    match v {
        GoValue::Null => None,
        GoValue::Float64(f) => Some(*f),
        other => panic!("expected optional float field, got {other:?}"),
    }
}

/// Go `dcrutil.Amount.String()`: the coin value rendered with
/// `strconv.FormatFloat(f, 'f', -1, 64)` plus the " DCR" unit.
fn amount_string(atoms: i64) -> String {
    format!("{} DCR", gojson::format_float_f(txresults::to_coin(atoms)))
}

/// The minimum amount, zero when empty (dcrd rpcserver `min`).
fn amounts_min(s: &[i64]) -> i64 {
    s.iter().copied().min().unwrap_or(0)
}

/// The maximum amount, seeded with zero (dcrd rpcserver `max`).
fn amounts_max(s: &[i64]) -> i64 {
    s.iter().copied().fold(0, i64::max)
}

/// The mean amount via integer division, zero when empty (dcrd
/// rpcserver `mean`).
fn amounts_mean(s: &[i64]) -> i64 {
    if s.is_empty() {
        return 0;
    }
    let sum: i64 = s.iter().sum();
    sum / s.len() as i64
}

/// The median amount: the middle element after sorting, or the
/// integer mean of the two middle elements (dcrd rpcserver `median`).
fn amounts_median(s: &[i64]) -> i64 {
    if s.is_empty() {
        return 0;
    }
    let mut sorted = s.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 != 0 {
        sorted[middle]
    } else {
        (sorted[middle] + sorted[middle - 1]) / 2
    }
}

/// The standard deviation over coin-denominated floats with Go's
/// amount rounding, zero for fewer than two samples (dcrd rpcserver
/// `stdDev`).
fn amounts_std_dev(s: &[i64]) -> i64 {
    let mean_coin = txresults::to_coin(amounts_mean(s));
    let mut total = 0f64;
    for amt in s {
        let d = txresults::to_coin(*amt) - mean_coin;
        total += d * d;
    }
    if s.len() as i64 - 1 == 0 {
        return 0;
    }
    let v = total / (s.len() as i64 - 1) as f64;
    // NewAmount cannot fail here; it would return zero anyway.
    new_amount(v.sqrt()).unwrap_or(0)
}

/// The fee per kilobyte of a transaction with its fraud proofs set
/// (dcrd `calcFeePerKb`).
fn calc_fee_per_kb(tx: &MsgTx) -> i64 {
    let mut value_in: i64 = 0;
    for tx_in in &tx.tx_in {
        value_in += tx_in.value_in;
    }
    let mut out: i64 = 0;
    for tx_out in &tx.tx_out {
        out += tx_out.value;
    }
    ((value_in - out) * 1000) / tx.serialize_size() as i64
}

/// The distilled fee statistics every fee info result carries.
struct FeeStats {
    number: u32,
    min: f64,
    max: f64,
    mean: f64,
    median: f64,
    std_dev: f64,
}

impl FeeStats {
    /// The statistics over the given per-kilobyte fees.
    fn over(fees: &[i64], number: u32) -> FeeStats {
        FeeStats {
            number,
            min: txresults::to_coin(amounts_min(fees)),
            max: txresults::to_coin(amounts_max(fees)),
            mean: txresults::to_coin(amounts_mean(fees)),
            median: txresults::to_coin(amounts_median(fees)),
            std_dev: txresults::to_coin(amounts_std_dev(fees)),
        }
    }

    /// The `Number, Min, Max, Mean, Median, StdDev` field values every
    /// fee info struct ends with.
    fn tail_fields(&self) -> Vec<GoValue> {
        vec![
            GoValue::Uint(u64::from(self.number)),
            GoValue::Float64(self.min),
            GoValue::Float64(self.max),
            GoValue::Float64(self.mean),
            GoValue::Float64(self.median),
            GoValue::Float64(self.std_dev),
        ]
    }
}

/// The fee information for the given tx type in the mempool (dcrd
/// `feeInfoForMempool`).
fn fee_info_for_mempool<C: RpcChain>(
    server: &mut Server<C>,
    tx_type: dcroxide_stake::TxType,
) -> FeeStats {
    let tx_descs = server.cfg.tx_mempooler.tx_descs();
    let mut ticket_fees = Vec::with_capacity(tx_descs.len());
    for tx_desc in &tx_descs {
        if tx_desc.tx_type == tx_type {
            let fee_per_kb = tx_desc.fee * 1000 / tx_desc.tx.serialize_size() as i64;
            ticket_fees.push(fee_per_kb);
        }
    }
    FeeStats::over(&ticket_fees, ticket_fees.len() as u32)
}

/// The fees of the transactions of the given type in the block, sized
/// by the corresponding header count (dcrd `ticketFeeInfoForBlock`'s
/// per-block fee collection).
fn block_type_fees(bl: &MsgBlock, tx_type: dcroxide_stake::TxType) -> Vec<i64> {
    let tx_num = match tx_type {
        dcroxide_stake::TxType::Regular => bl.transactions.len() - 1,
        dcroxide_stake::TxType::SStx => usize::from(bl.header.fresh_stake),
        dcroxide_stake::TxType::SSGen => usize::from(bl.header.voters),
        dcroxide_stake::TxType::SSRtx => usize::from(bl.header.revocations),
        _ => 0,
    };

    let mut tx_fees = vec![0i64; tx_num];
    let mut itr = 0;
    if tx_type == dcroxide_stake::TxType::Regular {
        for (i, tx) in bl.transactions.iter().enumerate() {
            // Skip the coin base.
            if i == 0 {
                continue;
            }
            tx_fees[itr] = calc_fee_per_kb(tx);
            itr += 1;
        }
    } else {
        for stx in &bl.stransactions {
            if dcroxide_stake::determine_tx_type(stx) == tx_type {
                tx_fees[itr] = calc_fee_per_kb(stx);
                itr += 1;
            }
        }
    }
    tx_fees
}

/// The fee information for the given tx type in the block at the
/// given height (dcrd `ticketFeeInfoForBlock`); the raw chain error
/// feeds the caller's internal error.
fn ticket_fee_info_for_block<C: RpcChain>(
    server: &mut Server<C>,
    height: i64,
    tx_type: dcroxide_stake::TxType,
) -> Result<FeeStats, String> {
    let bl = server.cfg.chain.block_by_height(height)?;
    let tx_fees = block_type_fees(&bl, tx_type);
    Ok(FeeStats::over(&tx_fees, tx_fees.len() as u32))
}

/// The fee information for the given tx type over the height range
/// `[start, end)` (dcrd `ticketFeeInfoForRange`).
fn ticket_fee_info_for_range<C: RpcChain>(
    server: &mut Server<C>,
    start: i64,
    end: i64,
    tx_type: dcroxide_stake::TxType,
) -> Result<FeeStats, String> {
    let hashes = server.cfg.chain.height_range(start, end)?;

    let mut tx_fees = Vec::new();
    for hash in &hashes {
        let bl = server.cfg.chain.block_by_hash(hash)?;
        if tx_type == dcroxide_stake::TxType::Regular {
            for (i, tx) in bl.transactions.iter().enumerate() {
                // Skip the coin base.
                if i == 0 {
                    continue;
                }
                tx_fees.push(calc_fee_per_kb(tx));
            }
        } else {
            for stx in &bl.stransactions {
                if dcroxide_stake::determine_tx_type(stx) == tx_type {
                    tx_fees.push(calc_fee_per_kb(stx));
                }
            }
        }
    }
    Ok(FeeStats::over(&tx_fees, tx_fees.len() as u32))
}

/// handleticketfeeinfo (dcrd `handleTicketFeeInfo`); the result is a
/// `TicketFeeInfoResult` value.
pub fn handle_ticket_fee_info<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let blocks = opt_uint(&c[0]).unwrap_or(0) as u32;
    let windows = opt_uint(&c[1]).unwrap_or(0) as u32;

    let best_height = server.cfg.chain.best_snapshot().height;

    // Memory pool first.
    let fee_info_mempool = fee_info_for_mempool(server, dcroxide_stake::TxType::SStx);

    // Blocks requested, descending from the chain tip.
    let mut fee_info_blocks = GoValue::Null;
    if blocks > 0 {
        let start = best_height;
        let end = best_height - i64::from(blocks);
        let mut items = Vec::new();
        let mut i = start;
        while i > end {
            let stats = ticket_fee_info_for_block(server, i, dcroxide_stake::TxType::SStx)
                .map_err(|e| rpc_internal_err(&e))?;
            let mut item = vec![GoValue::Uint(i as u32 as u64)];
            item.extend(stats.tail_fields());
            items.push(GoValue::Struct(item));
            i -= 1;
        }
        fee_info_blocks = GoValue::Array(items);
    }

    let mut fee_info_windows = GoValue::Null;
    if windows > 0 {
        // The first window is special because it may not be finished.
        let win_len = server.cfg.chain_params.stake_diff_window_size;
        let last_change = (best_height / win_len) * win_len;

        let mut items = Vec::new();
        let push_window = |server: &mut Server<C>,
                           items: &mut Vec<GoValue>,
                           start: i64,
                           end: i64|
         -> Result<(), RPCError> {
            let stats = ticket_fee_info_for_range(server, start, end, dcroxide_stake::TxType::SStx)
                .map_err(|e| rpc_internal_err(&e))?;
            let mut item = vec![
                GoValue::Uint(start as u32 as u64),
                GoValue::Uint(end as u32 as u64),
            ];
            item.extend(stats.tail_fields());
            items.push(GoValue::Struct(item));
            Ok(())
        };
        push_window(server, &mut items, last_change, best_height + 1)?;

        // Move backwards through window lengths from the last
        // adjustment.
        if windows > 1 {
            let mut end = -1i64;
            if last_change - i64::from(windows) * win_len > end {
                end = last_change - i64::from(windows) * win_len;
            }
            let mut i = last_change;
            while i > end + win_len {
                push_window(server, &mut items, i - win_len, i)?;
                i -= win_len;
            }
        }
        fee_info_windows = GoValue::Array(items);
    }

    let mut mempool_item = Vec::new();
    mempool_item.extend(fee_info_mempool.tail_fields());
    Ok(GoValue::Struct(vec![
        GoValue::Struct(mempool_item),
        fee_info_blocks,
        fee_info_windows,
    ]))
}

/// handleticketvwap (dcrd `handleTicketVWAP`); the result is the
/// volume weighted average ticket price as a float.
pub fn handle_ticket_vwap<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);

    // The default VWAP is for the past WorkDiffWindows *
    // WorkDiffWindowSize many blocks.
    let best_height = server.cfg.chain.best_snapshot().height;
    let start = match opt_uint(&c[0]) {
        None => {
            let params = &server.cfg.chain_params;
            let to_eval = params.work_diff_windows * params.work_diff_window_size;
            let start_i64 = best_height - to_eval;
            // Use 1 as the first block if there aren't enough blocks.
            if start_i64 <= 0 { 1 } else { start_i64 as u32 }
        }
        Some(start) => start as u32,
    };

    let end = match opt_uint(&c[1]) {
        None => best_height as u32,
        Some(end) => end as u32,
    };
    if start > end {
        return Err(rpc_invalid_error(&format!(
            "Start height {start} is beyond end height {end}"
        )));
    }
    if i64::from(end) > best_height {
        return Err(rpc_invalid_error(&format!(
            "End height {end} is beyond blockchain tip height {best_height}"
        )));
    }

    // Calculate the volume weighted average price of a ticket for the
    // given range.
    let mut ticket_num: i64 = 0;
    let mut total_value: i64 = 0;
    for i in start..=end {
        let block_header = server
            .cfg
            .chain
            .header_by_height(i64::from(i))
            .map_err(|e| rpc_internal_err(&e))?;

        ticket_num += i64::from(block_header.fresh_stake);
        total_value += block_header.sbits * i64::from(block_header.fresh_stake);
    }
    let mut vwap = 0i64;
    if ticket_num > 0 {
        vwap = total_value / ticket_num;
    }

    Ok(GoValue::Float64(txresults::to_coin(vwap)))
}

/// handletxfeeinfo (dcrd `handleTxFeeInfo`); the result is a
/// `TxFeeInfoResult` value.
pub fn handle_tx_fee_info<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let blocks = opt_uint(&c[0]).unwrap_or(0) as u32;

    let best_height = server.cfg.chain.best_snapshot().height;

    // Memory pool first.
    let fee_info_mempool = fee_info_for_mempool(server, dcroxide_stake::TxType::Regular);

    // Blocks requested, descending from the chain tip.
    let mut fee_info_blocks = GoValue::Null;
    if blocks > 0 {
        let start = best_height;
        let end = best_height - i64::from(blocks);
        let mut items = Vec::new();
        let mut i = start;
        while i > end {
            let stats = ticket_fee_info_for_block(server, i, dcroxide_stake::TxType::Regular)
                .map_err(|e| rpc_internal_err(&e))?;
            let mut item = vec![GoValue::Uint(i as u32 as u64)];
            item.extend(stats.tail_fields());
            items.push(GoValue::Struct(item));
            i -= 1;
        }
        fee_info_blocks = GoValue::Array(items);
    }

    // Get the fee info for the range requested, unless none is given.
    // The default range is for the past WorkDiffWindowSize many
    // blocks.
    let start = match opt_uint(&c[1]) {
        None => {
            let to_eval = server.cfg.chain_params.work_diff_window_size;
            let start_i64 = best_height - to_eval;
            // Use 1 as the first block if there aren't enough blocks.
            if start_i64 <= 0 { 1 } else { start_i64 as u32 }
        }
        Some(start) => start as u32,
    };

    let end = match opt_uint(&c[2]) {
        None => best_height as u32,
        Some(end) => end as u32,
    };
    if start > end {
        return Err(rpc_invalid_error(&format!(
            "Start height {start} is beyond end height {end}"
        )));
    }
    if i64::from(end) > best_height {
        return Err(rpc_invalid_error(&format!(
            "End height {end} is beyond blockchain tip height {best_height}"
        )));
    }

    let stats = ticket_fee_info_for_range(
        server,
        i64::from(start),
        i64::from(end.wrapping_add(1)),
        dcroxide_stake::TxType::Regular,
    )
    .map_err(|e| rpc_internal_err(&e))?;

    let mut mempool_item = Vec::new();
    mempool_item.extend(fee_info_mempool.tail_fields());
    Ok(GoValue::Struct(vec![
        GoValue::Struct(mempool_item),
        fee_info_blocks,
        GoValue::Struct(stats.tail_fields()),
    ]))
}

/// The chain verification loop (dcrd `verifyChain`); the error only
/// feeds the boolean result.
fn verify_chain<C: RpcChain>(server: &mut Server<C>, level: i64, depth: i64) -> Result<(), ()> {
    let best = server.cfg.chain.best_snapshot();
    let mut finish_height = best.height - depth;
    if finish_height < 0 {
        finish_height = 0;
    }

    let mut height = best.height;
    while height > finish_height {
        // Level 0 just looks up the block.
        let block = server.cfg.chain.block_by_height(height).map_err(|_| ())?;

        // Level 1 does basic chain sanity checks.
        if level > 0 {
            server
                .cfg
                .sanity_checker
                .check_block_sanity(&block)
                .map_err(|_| ())?;
        }
        height -= 1;
    }
    Ok(())
}

/// handleverifychain (dcrd `handleVerifyChain`); the result is a
/// boolean.
pub fn handle_verify_chain<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let check_level = opt_int(&c[0]).unwrap_or(0);
    let check_depth = opt_int(&c[1]).unwrap_or(0);

    let ok = verify_chain(server, check_level, check_depth).is_ok();
    Ok(GoValue::Bool(ok))
}

/// handlegetinfo (dcrd `handleGetInfo`); the result is an
/// `InfoChainResult` value.
pub fn handle_get_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let best = server.cfg.chain.best_snapshot();

    // Go `time.Duration.Seconds()` truncated to an int64.
    let offset_nanos = server.cfg.time_source.offset_nanos();
    let offset_secs =
        (offset_nanos / 1_000_000_000) as f64 + (offset_nanos % 1_000_000_000) as f64 / 1e9;

    Ok(GoValue::Struct(vec![
        GoValue::Int(i64::from(
            (1_000_000 * crate::version::MAJOR
                + 10_000 * crate::version::MINOR
                + 100 * crate::version::PATCH) as i32,
        )),
        GoValue::Int(i64::from(server.cfg.max_protocol_version as i32)),
        GoValue::Int(best.height),
        GoValue::Int(offset_secs as i64),
        GoValue::Int(i64::from(server.cfg.conn_mgr.connected_count())),
        GoValue::String(server.cfg.proxy.clone()),
        GoValue::Float64(crate::helpers::get_difficulty_ratio(
            best.bits,
            server.cfg.chain_params.pow_limit_bits,
        )),
        GoValue::Bool(server.cfg.test_net),
        GoValue::Float64(txresults::to_coin(server.cfg.min_relay_tx_fee)),
        GoValue::String(String::new()),
        GoValue::Bool(server.cfg.tx_indexer.is_some()),
    ]))
}

/// The JSON-RPC API semantic version (dcrd `jsonrpcSemver*`).
const JSONRPC_SEMVER_MAJOR: u32 = 8;
const JSONRPC_SEMVER_MINOR: u32 = 3;
const JSONRPC_SEMVER_PATCH: u32 = 0;
const JSONRPC_SEMVER_STRING: &str = "8.3.0";

/// handleversion (dcrd `handleVersion`); the result is a map of
/// `VersionResult` values keyed by component.
pub fn handle_version<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let runtime_ver = server.cfg.runtime_version.replace('.', "-");
    let mut build_meta = crate::version::normalize_string(&runtime_ver);
    let build = crate::version::normalize_string(crate::version::BUILD_METADATA);
    if !build.is_empty() {
        build_meta = format!("{build}.{build_meta}");
    }
    Ok(GoValue::Map(vec![
        (
            "dcrdjsonrpcapi".to_string(),
            GoValue::Struct(vec![
                GoValue::String(JSONRPC_SEMVER_STRING.to_string()),
                GoValue::Uint(u64::from(JSONRPC_SEMVER_MAJOR)),
                GoValue::Uint(u64::from(JSONRPC_SEMVER_MINOR)),
                GoValue::Uint(u64::from(JSONRPC_SEMVER_PATCH)),
                GoValue::String(String::new()),
                GoValue::String(String::new()),
            ]),
        ),
        (
            "dcrd".to_string(),
            GoValue::Struct(vec![
                GoValue::String(crate::version::VERSION.to_string()),
                GoValue::Uint(u64::from(crate::version::MAJOR)),
                GoValue::Uint(u64::from(crate::version::MINOR)),
                GoValue::Uint(u64::from(crate::version::PATCH)),
                GoValue::String(crate::version::normalize_string(
                    crate::version::PRE_RELEASE,
                )),
                GoValue::String(build_meta),
            ]),
        ),
    ]))
}

/// handlecreaterawssrtx (dcrd `handleCreateRawSSRtx`); the result is
/// the serialized revocation transaction hex string.
pub fn handle_create_raw_ssrtx<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let inputs = array(&c[0]);

    // Only a single SStx should be given.
    if inputs.len() != 1 {
        return Err(rpc_invalid_error("SSRtx invalid number of inputs"));
    }

    // The input must be in the stake tree.
    let input = fields(&inputs[0]);
    let (amount, txid, vout, tree) = (
        float(&input[0]),
        s(&input[1]),
        uint(&input[2]) as u32,
        int(&input[3]) as i8,
    );
    if tree != 1 {
        return Err(rpc_invalid_error("Input tree is not TxTreeStake type"));
    }

    // The input must be a ticket submission output.
    const TICKET_SUBMISSION_OUTPUT: u32 = 0;
    if vout != TICKET_SUBMISSION_OUTPUT {
        return Err(rpc_invalid_error(
            "Input is not a ticket submission output (output index 0)",
        ));
    }

    // Convert the provided transaction hash hex to a hash.
    let tx_hash: Hash = txid.parse().map_err(|_| rpc_decode_hex_error(txid))?;

    // Try to fetch the ticket from the block database.
    let ticket_utxo = match server.cfg.chain.fetch_utxo_entry(&tx_hash, vout, tree) {
        Ok(Some(entry)) => entry,
        Ok(None) | Err(_) => {
            return Err(crate::rpcerrors::rpc_no_tx_info_error(&tx_hash));
        }
    };
    if ticket_utxo.tx_type != dcroxide_stake::TxType::SStx {
        return Err(rpc_deserialization_error(&format!(
            "Invalid Tx type: {}",
            ticket_utxo.tx_type as i32
        )));
    }

    // The sstx pubkeyhashes and amounts as found in the transaction
    // outputs.
    let Some(minimal_outputs) = ticket_utxo.ticket_minimal_outputs else {
        return Err(rpc_internal_err("missing ticket minimal outputs"));
    };

    // The input amount must be the ticket submission amount.
    let ticket_submission_amount = minimal_outputs[TICKET_SUBMISSION_OUTPUT as usize].value;
    let input_amount = new_amount(amount).map_err(|e| rpc_invalid_error(&e))?;
    if input_amount != ticket_submission_amount {
        return Err(rpc_invalid_error(&format!(
            "Input amount {} is not equal to ticket submission amount {}",
            amount_string(input_amount),
            amount_string(ticket_submission_amount)
        )));
    }

    // Decode the fee as coins.
    let mut fee_amt = 0i64;
    if let Some(fee) = opt_float(&c[1]) {
        fee_amt =
            new_amount(fee).map_err(|e| rpc_invalid_error(&format!("Invalid fee amount: {e}")))?;
    }

    // Determine if the automatic ticket revocations agenda is active.
    let prev_blk_hash = server.cfg.chain.best_snapshot().hash;
    let is_auto_revocations_enabled = server.is_auto_revocations_agenda_active(&prev_blk_hash)?;

    // If the automatic ticket revocations agenda is active, validate
    // that the fee amount is zero and set the transaction version to 2.
    let mut revocation_tx_version = 1u16;
    if is_auto_revocations_enabled {
        if fee_amt != 0 {
            return Err(rpc_invalid_error(
                "Fee amount must be 0 when the automatic ticket revocations agenda is active",
            ));
        }
        revocation_tx_version = dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS;
    }

    // Get the previous header bytes.
    let prev_header = server
        .cfg
        .chain
        .header_by_hash(&prev_blk_hash)
        .map_err(|_| crate::rpcerrors::rpc_block_not_found_error(&prev_blk_hash))?;
    let prev_header_bytes = prev_header.serialize();

    let mtx = dcroxide_stake::create_revocation_from_ticket(
        &tx_hash,
        &minimal_outputs,
        fee_amt,
        revocation_tx_version,
        &server.cfg.chain_params,
        &prev_header_bytes,
        is_auto_revocations_enabled,
    )
    .map_err(|e| rpc_invalid_error(&format!("Invalid SSRtx: {e}")))?;

    // Check to make sure our SSRtx was created correctly.
    dcroxide_stake::check_ssrtx(&mtx).map_err(|e| rpc_internal_err(&e.to_string()))?;

    // Return the serialized and hex-encoded transaction.
    let mtx_hex = txresults::message_to_hex(&Message::Tx(mtx), server.cfg.max_protocol_version)?;
    Ok(GoValue::String(mtx_hex))
}

/// handlegenerate (dcrd `handleGenerate`); the result is the list of
/// generated block hash strings.
pub fn handle_generate<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    // Respond with an error if there are no addresses to pay the
    // created blocks to.
    if server.cfg.mining_addrs.is_empty() {
        return Err(rpc_internal_err(
            "no payment addresses specified via --miningaddr",
        ));
    }

    // Respond with an error if there's virtually 0 chance of
    // CPU-mining a block.
    let params = &server.cfg.chain_params;
    if !params.generate_supported {
        return Err(RPCError::new(
            codes::DIFFICULTY,
            &format!(
                "No support for `generate` on the current network, {}, as it's \
                 unlikely to be possible to mine a block with the CPU.",
                params.net
            ),
        ));
    }

    let c = fields(cmd);
    let num_blocks = uint(&c[0]) as u32;

    // Extend the main chain by the requested number of blocks.
    let block_hashes = match server.cfg.cpu_miner.generate_n_blocks(num_blocks) {
        Ok(hashes) => hashes,
        Err(failure) if failure.is_ctx_err => {
            return Err(crate::rpcerrors::rpc_connection_closed_error());
        }
        Err(failure) if failure.is_cancel_discrete => {
            return Err(crate::rpcerrors::rpc_cancel_error(&format!(
                "Failed to generate the requested number of blocks: {}",
                failure.message
            )));
        }
        Err(failure) => return Err(rpc_internal_err(&failure.message)),
    };
    if block_hashes.is_empty() {
        return Ok(GoValue::Null);
    }
    Ok(GoValue::Array(
        block_hashes
            .iter()
            .map(|hash| GoValue::String(hash.to_string()))
            .collect(),
    ))
}

/// handlegetgenerate (dcrd `handleGetGenerate`); the result is a
/// boolean.
pub fn handle_get_generate<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Bool(server.cfg.cpu_miner.is_mining()))
}

/// handlegethashespersec (dcrd `handleGetHashesPerSec`); the result
/// is the truncated integer rate.
pub fn handle_get_hashes_per_sec<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    Ok(GoValue::Int(server.cfg.cpu_miner.hashes_per_second() as i64))
}

/// handlesetgenerate (dcrd `handleSetGenerate`); the result is null.
pub fn handle_set_generate<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let mut generate = match &c[0] {
        GoValue::Bool(b) => *b,
        other => panic!("expected bool field, got {other:?}"),
    };
    let gen_proc_limit = opt_int(&c[1]).unwrap_or(-1);

    // Disable generation regardless of the provided generate flag if
    // the maximum number of threads is 0.
    if gen_proc_limit == 0 {
        generate = false;
    }

    if !generate {
        // Stop CPU mining by setting the number of workers to zero.
        server.cfg.cpu_miner.set_num_workers(0);
    } else {
        // Respond with an error if there are no addresses to pay the
        // created blocks to.
        if server.cfg.mining_addrs.is_empty() {
            return Err(rpc_internal_err(
                "no payment addresses specified via --miningaddr",
            ));
        }

        server.cfg.cpu_miner.set_num_workers(gen_proc_limit as i32);
    }
    Ok(GoValue::Null)
}

/// handlegetnetworkhashps (dcrd `handleGetNetworkHashPS`); the result
/// is an `int64` rate.
pub fn handle_get_network_hash_ps<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);

    // When the passed height is too high or zero, just return 0 now
    // since we can't reasonably calculate the number of network hashes
    // per second from invalid values.  When it's negative, use the
    // current best block height.
    let best = server.cfg.chain.best_snapshot();
    let mut end_height = opt_int(&c[1]).unwrap_or(-1);
    if end_height > best.height || end_height == 0 {
        return Ok(GoValue::Int(0));
    }
    if end_height < 0 {
        end_height = best.height;
    }

    // Calculate the starting block height based on the passed number
    // of blocks.  When the passed value is negative, use the default.
    // Also, make sure the starting height is not before the beginning
    // of the chain.
    let mut num_blocks = 120i64;
    if let Some(blocks) = opt_int(&c[0])
        && blocks >= 0
    {
        num_blocks = blocks;
    }
    let mut start_height = end_height - num_blocks;
    if start_height < 0 {
        start_height = 0;
    }

    // Find the min and max block timestamps as well as calculate the
    // total amount of work that happened between the start and end
    // blocks.
    let mut min_timestamp = 0u32;
    let mut max_timestamp = 0u32;
    let mut total_work = num_bigint::BigInt::from(0);
    let mut cur_height = start_height;
    while cur_height <= end_height {
        let hash = server
            .cfg
            .chain
            .block_hash_by_height(cur_height)
            .map_err(|e| rpc_internal_err(&e))?;
        let header = server
            .cfg
            .chain
            .header_by_hash(&hash)
            .map_err(|e| rpc_internal_err(&e))?;

        if cur_height == start_height {
            min_timestamp = header.timestamp;
            max_timestamp = min_timestamp;
        } else {
            total_work += dcroxide_standalone::calc_work(header.bits);

            if min_timestamp > header.timestamp {
                min_timestamp = header.timestamp;
            }
            if max_timestamp < header.timestamp {
                max_timestamp = header.timestamp;
            }
        }
        cur_height += 1;
    }

    // Calculate the difference in seconds between the min and max
    // block timestamps and avoid division by zero in the case where
    // there is no time difference.
    let time_diff = i64::from(max_timestamp) - i64::from(min_timestamp);
    if time_diff == 0 {
        return Ok(GoValue::Int(0));
    }

    // Go `big.Int.Int64` keeps the low 64 bits of the magnitude (the
    // quotient is never negative here).
    let hashes_per_sec = total_work / num_bigint::BigInt::from(time_diff);
    let low = hashes_per_sec.iter_u64_digits().next().unwrap_or(0);
    Ok(GoValue::Int(low as i64))
}

/// handlegetmininginfo (dcrd `handleGetMiningInfo`); the result is a
/// `GetMiningInfoResult` value.
pub fn handle_get_mining_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    // Create a default getnetworkhashps command to use defaults and
    // make use of the existing getnetworkhashps handler.
    let gnhps_cmd = GoValue::Struct(vec![GoValue::Null, GoValue::Null]);
    let network_hashes_per_sec = match handle_get_network_hash_ps(server, &gnhps_cmd)? {
        GoValue::Int(n) => n,
        other => panic!("expected int result, got {other:?}"),
    };

    let best = server.cfg.chain.best_snapshot();
    Ok(GoValue::Struct(vec![
        GoValue::Int(best.height),
        GoValue::Uint(best.block_size),
        GoValue::Uint(best.num_txns),
        GoValue::Float64(crate::helpers::get_difficulty_ratio(
            best.bits,
            server.cfg.chain_params.pow_limit_bits,
        )),
        GoValue::Int(best.next_stake_diff),
        GoValue::String(String::new()),
        GoValue::Bool(server.cfg.cpu_miner.is_mining()),
        GoValue::Int(i64::from(server.cfg.cpu_miner.num_workers())),
        GoValue::Int(server.cfg.cpu_miner.hashes_per_second() as i64),
        GoValue::Int(network_hashes_per_sec),
        GoValue::Uint(server.cfg.tx_mempooler.count() as u64),
        GoValue::Bool(server.cfg.test_net),
    ]))
}

/// handlegetnetworkinfo (dcrd `handleGetNetworkInfo`); the result is
/// a `GetNetworkInfoResult` value.
pub fn handle_get_network_info<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let local_addrs: Vec<GoValue> = server
        .cfg
        .addr_manager
        .local_addresses()
        .into_iter()
        .map(|(address, port)| {
            GoValue::Struct(vec![
                GoValue::String(address),
                GoValue::Uint(u64::from(port)),
                GoValue::Int(0),
            ])
        })
        .collect();

    // Go `time.Duration.Seconds()` truncated to an int64.
    let offset_nanos = server.cfg.time_source.offset_nanos();
    let offset_secs =
        (offset_nanos / 1_000_000_000) as f64 + (offset_nanos % 1_000_000_000) as f64 / 1e9;

    let networks = server
        .cfg
        .net_info
        .iter()
        .map(|net| {
            GoValue::Struct(vec![
                GoValue::String(net.name.clone()),
                GoValue::Bool(net.limited),
                GoValue::Bool(net.reachable),
                GoValue::String(net.proxy.clone()),
                GoValue::Bool(net.proxy_randomize_credentials),
            ])
        })
        .collect();

    Ok(GoValue::Struct(vec![
        GoValue::Int(i64::from(
            (1_000_000 * crate::version::MAJOR
                + 10_000 * crate::version::MINOR
                + 100 * crate::version::PATCH) as i32,
        )),
        GoValue::String(server.cfg.user_agent_version.clone()),
        GoValue::Int(i64::from(server.cfg.max_protocol_version as i32)),
        GoValue::Int(offset_secs as i64),
        GoValue::Int(i64::from(server.cfg.conn_mgr.connected_count())),
        GoValue::Array(networks),
        GoValue::Float64(txresults::to_coin(server.cfg.min_relay_tx_fee)),
        GoValue::Array(local_addrs),
        GoValue::String(format!("{:016x}", server.cfg.services)),
    ]))
}

/// handlegetmixmessage (dcrd `handleGetMixMessage`); the result is a
/// `GetMixMessageResult` value.
pub fn handle_get_mix_message<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let hash_str = s(&c[0]);
    let msg_hash: Hash = hash_str
        .parse()
        .map_err(|_| rpc_decode_hex_error(hash_str))?;

    let msg = server
        .cfg
        .mix_pooler
        .message(&msg_hash)
        .map_err(|_| crate::rpcerrors::rpc_mix_message_not_found_error(&msg_hash))?;

    // dcrd returns the bare encode error and lets the dispatch layer
    // wrap it; encoding a pool-held message cannot fail, so the
    // messageToHex internal error stands in.
    let message_hex = txresults::message_to_hex(&msg, dcroxide_wire::MIX_VERSION)?;

    Ok(GoValue::Struct(vec![
        GoValue::String(msg.command().to_string()),
        GoValue::String(message_hex),
    ]))
}

/// handlegetmixpairrequests (dcrd `handleGetMixPairRequests`); the
/// result is the list of serialized pair request hex strings.
pub fn handle_get_mix_pair_requests<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let prs = server.cfg.mix_pooler.mix_prs();

    let mut res = Vec::with_capacity(prs.len());
    for pr in prs {
        let msg = Message::MixPairReq(pr);
        let message_hex = txresults::message_to_hex(&msg, dcroxide_wire::MIX_VERSION)?;
        res.push(GoValue::String(message_hex));
    }

    Ok(GoValue::Array(res))
}

/// Decode a hex string like Go's streaming `hex.Decoder`: the valid
/// prefix decodes, and the first problem is remembered with Go's
/// error text, surfacing only if a reader ever needs bytes past the
/// prefix.
fn lazy_hex_decode(s: &str) -> (Vec<u8>, Option<String>) {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let pair = [bytes[i], bytes[i + 1]];
        for &b in &pair {
            if !(b as char).is_ascii_hexdigit() {
                return (
                    out,
                    Some(format!(
                        "encoding/hex: invalid byte: U+{:04X} {:?}",
                        b, b as char
                    )),
                );
            }
        }
        let hi = (pair[0] as char).to_digit(16).expect("checked");
        let lo = (pair[1] as char).to_digit(16).expect("checked");
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    if i < bytes.len() {
        // A lone trailing character: an invalid one surfaces as the
        // invalid-byte error, a valid one as an unexpected EOF.
        let b = bytes[i];
        if !(b as char).is_ascii_hexdigit() {
            return (
                out,
                Some(format!(
                    "encoding/hex: invalid byte: U+{:04X} {:?}",
                    b, b as char
                )),
            );
        }
        return (out, Some("unexpected EOF".to_string()));
    }
    (out, None)
}

/// handlesendrawmixmessage (dcrd `handleSendRawMixMessage`); the
/// result is null.
pub fn handle_send_raw_mix_message<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let command = s(&c[0]);
    let message_hex = s(&c[1]);

    // Only the mixing message wire commands are recognized.
    match command {
        "mixpairreq" | "mixkeyxchg" | "mixcphrtxt" | "mixslotres" | "mixdcnet" | "mixconfirm"
        | "mixfactpoly" | "mixsecrets" => {}
        other => {
            return Err(rpc_invalid_error(&format!(
                "Unrecognized mixing message wire command string {}",
                gojson::go_quote(other)
            )));
        }
    }

    // Deserialize the message.  dcrd streams through a lazy hex
    // decoder, so hex problems past the end of the message are never
    // observed and a short message surfaces the reader's error.
    let (payload, hex_err) = lazy_hex_decode(message_hex);
    let msg =
        dcroxide_wire::decode_message_payload_prefix(command, &payload, dcroxide_wire::MIX_VERSION)
            .map_err(|e| {
                let text = match e {
                    dcroxide_wire::WireError::UnexpectedEof => match &hex_err {
                        Some(err) => err.clone(),
                        None => "unexpected EOF".to_string(),
                    },
                    other => other.to_string(),
                };
                rpc_deserialization_error(&format!("Could not decode mix message: {text}"))
            })?;

    // dcrd pre-calculates the message hash here; the ported mixing
    // types compute it on demand.

    // Use the local node as the source.
    if let Err(err) = server.cfg.sync_mgr.accept_mix_message(&msg) {
        return Err(crate::rpcerrors::rpc_misc_error(&format!(
            "Rejected mix message: {err}"
        )));
    }

    server.cfg.conn_mgr.relay_mix_messages(&[msg]);

    // The websocket notification hook (`NotifyMixMessage`) arrives
    // with the websocket layer.

    Ok(GoValue::Null)
}

/// handlestartprofiler (dcrd `handleStartProfiler`); the result is a
/// `StartProfilerResult` value.
pub fn handle_start_profiler<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let addr = s(&c[0]);
    let allow_non_loopback = opt_bool(&c[1]).unwrap_or(false);

    if !server.cfg.profiler_mgr.listeners().is_empty() {
        return Err(RPCError::new(
            codes::PROFILER_STATE,
            "profile server is already running",
        ));
    }

    if let Err(err) = server.cfg.profiler_mgr.start(addr, allow_non_loopback) {
        return Err(rpc_invalid_error(&format!(
            "unable to start profile server: {err}"
        )));
    }

    // Ensure there are active listeners for generating the result.
    let listeners = server.cfg.profiler_mgr.listeners();
    if listeners.is_empty() {
        return Err(rpc_internal_err(
            "profile server started without active listeners",
        ));
    }

    Ok(GoValue::Struct(vec![GoValue::Array(
        listeners.into_iter().map(GoValue::String).collect(),
    )]))
}

/// handlestopprofiler (dcrd `handleStopProfiler`); the result is a
/// status string.
pub fn handle_stop_profiler<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    if server.cfg.profiler_mgr.listeners().is_empty() {
        return Err(RPCError::new(
            codes::PROFILER_STATE,
            "profile server is not started",
        ));
    }

    server
        .cfg
        .profiler_mgr
        .stop()
        .map_err(|e| rpc_internal_err(&e))?;

    Ok(GoValue::String("profile server stopped".to_string()))
}

/// handlestop (dcrd `handleStop`); the result is a status string.
pub fn handle_stop<C: RpcChain>(
    server: &mut Server<C>,
    _cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    (server.cfg.request_shutdown)();
    Ok(GoValue::String("dcrd stopping.".to_string()))
}

/// handlegettreasuryspendvotes (dcrd `handleGetTreasurySpendVotes`);
/// the result is a `GetTreasurySpendVotesResult` value.
pub fn handle_get_treasury_spend_votes<C: RpcChain>(
    server: &mut Server<C>,
    cmd: &GoValue,
) -> Result<GoValue, RPCError> {
    let c = fields(cmd);
    let tvi = server.cfg.chain_params.treasury_vote_interval;
    let mul = server.cfg.chain_params.treasury_vote_interval_multiplier;

    // Either parse the provided hash or use the current best tip hash
    // when none is provided.
    let block_param = match &c[0] {
        GoValue::Null => None,
        GoValue::String(s) => Some(s.as_str()),
        other => panic!("expected optional string field, got {other:?}"),
    };
    let (block, block_height, checking_main_chain) = match block_param {
        None | Some("") => {
            let best = server.cfg.chain.best_snapshot();
            (best.hash, best.height, true)
        }
        Some(hash_str) => {
            let block: Hash = hash_str
                .parse()
                .map_err(|_| rpc_decode_hex_error(hash_str))?;

            // Using HeaderByHash allows querying both the mainchain
            // and any sidechains.
            let hdr = server
                .cfg
                .chain
                .header_by_hash(&block)
                .map_err(|_| crate::rpcerrors::rpc_block_not_found_error(&block))?;

            let checking = server.cfg.chain.main_chain_has_block(&block);
            (block, i64::from(hdr.height), checking)
        }
    };

    // When tallying votes on mainchain and for mined tspends, only
    // count votes up to when the tspend was mined.
    let mut end_blocks: Vec<(Hash, Hash)> = Vec::new();

    // Determine whether to use the specified tspends or all the ones
    // in the mempool.
    let client_tspends: Option<Vec<&str>> = match &c[1] {
        GoValue::Null => None,
        v => Some(array(v).iter().map(s).collect()),
    };
    let mut tspends: Vec<MsgTx> = Vec::new();
    match client_tspends {
        Some(list) if !list.is_empty() => {
            // Client-specified tspends may be in the mempool, mined,
            // or completely unknown.
            for tspend_str in list {
                let hash: Hash = tspend_str
                    .parse()
                    .map_err(|_| rpc_decode_hex_error(tspend_str))?;

                // Check if this tspend is in the mempool.
                if let Ok((tx, _tree)) = server.cfg.tx_mempooler.fetch_transaction(&hash) {
                    // Sanity check this is actually a tspend.
                    if !dcroxide_stake::is_tspend(&tx) {
                        return Err(rpc_invalid_error(&format!(
                            "mempool tx {hash} is not a tspend"
                        )));
                    }
                    tspends.push(tx);
                    continue;
                }

                // Not in the mempool.  Check if it is mined.
                let blocks = match server.cfg.chain.fetch_tspend(&hash) {
                    Ok(blocks) if !blocks.is_empty() => blocks,
                    _ => {
                        // TSpend does not exist mined or in mempool.
                        return Err(crate::rpcerrors::rpc_no_tx_info_error(&hash));
                    }
                };

                // TSpend exists mined in at least one block.  Fetch
                // the first one and extract the tspend.
                let full_block = server
                    .cfg
                    .chain
                    .block_by_hash(&blocks[0])
                    .map_err(|e| rpc_internal_err(&e))?;

                // TSpends live in the stake tree.  dcrd dereferences a
                // nil error when the block does not contain the
                // tspend, so the missing case is unreachable.
                let tx = full_block
                    .stransactions
                    .iter()
                    .find(|tx| tx.tx_hash() == hash)
                    .unwrap_or_else(|| {
                        panic!("block did not contain treasury spend tx in stake tree")
                    });
                tspends.push(tx.clone());

                // Figure out which (if any) of the blocks the tspend
                // is found in are in the main chain so votes count
                // only up to that block.
                if !checking_main_chain {
                    continue;
                }
                for block_hash in &blocks {
                    if !server.cfg.chain.main_chain_has_block(block_hash) {
                        continue;
                    }

                    // Fetch the header to discover this block's
                    // height.
                    let hdr = server
                        .cfg
                        .chain
                        .header_by_hash(block_hash)
                        .map_err(|e| rpc_internal_err(&e))?;

                    // Count votes only up to the block before the
                    // tspend was mined.
                    if block_height >= i64::from(hdr.height) {
                        end_blocks.push((hash, hdr.prev_block));
                    }

                    break;
                }
            }
        }
        _ => {
            // Fetch vote counts for all mempool tspends.
            for hash in server.cfg.tx_mempooler.tspend_hashes() {
                let (tx, _tree) = server
                    .cfg
                    .tx_mempooler
                    .fetch_transaction(&hash)
                    .map_err(|e| rpc_internal_err(&e))?;
                tspends.push(tx);
            }
        }
    }

    // Fetch the vote counts from the blockchain.
    let mut votes = Vec::with_capacity(tspends.len());
    for tx in &tspends {
        let tx_hash = tx.tx_hash();

        // Early check to ensure this tx has a valid expiry.
        let expiry = tx.expiry;
        if !dcroxide_standalone::is_treasury_vote_interval(u64::from(expiry.wrapping_sub(2)), tvi) {
            return Err(rpc_internal_err(&format!(
                "treasury spend {tx_hash} has incorrect expiry {expiry}"
            )));
        }

        // Only count votes for tspends that are inside their voting
        // window; otherwise just return the vote start and end
        // heights.
        let mut yes = 0i64;
        let mut no = 0i64;
        let inside_window =
            dcroxide_standalone::inside_tspend_window(block_height, expiry, tvi, mul);
        let mined_block = end_blocks
            .iter()
            .find(|(hash, _)| *hash == tx_hash)
            .map(|(_, end)| *end);
        if inside_window || mined_block.is_some() {
            // Use the originally requested stop block or the custom
            // one for mainchain mined tspends.
            let check_block = mined_block.unwrap_or(block);

            match server.cfg.chain.tspend_count_votes(&check_block, tx) {
                Ok((y, n)) => {
                    yes = y;
                    no = n;
                }
                Err(failure) if failure.is_unknown_block => {
                    return Err(crate::rpcerrors::rpc_block_not_found_error(&block));
                }
                Err(failure) => return Err(rpc_internal_err(&failure.message)),
            }
        }

        // The error can be ignored because the expiry was verified to
        // be in a TVI earlier.
        let (start, end) =
            dcroxide_standalone::calc_tspend_window(expiry, tvi, mul).unwrap_or((0, 0));

        votes.push(GoValue::Struct(vec![
            GoValue::String(tx_hash.to_string()),
            GoValue::Int(i64::from(expiry)),
            GoValue::Int(i64::from(start)),
            GoValue::Int(i64::from(end)),
            GoValue::Int(yes),
            GoValue::Int(no),
        ]));
    }

    Ok(GoValue::Struct(vec![
        GoValue::String(block.to_string()),
        GoValue::Int(block_height),
        GoValue::Array(votes),
    ]))
}
