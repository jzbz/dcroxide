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
