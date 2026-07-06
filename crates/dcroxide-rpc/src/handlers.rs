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
use dcroxide_wire::{Message, MsgTx, OutPoint, TxIn, TxOut};

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
        .any(|(id, peer_addr)| *id == node_id || peer_addr == addr)
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
