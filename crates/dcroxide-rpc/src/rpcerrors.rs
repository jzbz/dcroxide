// SPDX-License-Identifier: ISC
//! The RPC error constructors handlers use (dcrd internal/rpcserver
//! `rpcserver.go`).

use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{RPCError, codes, err_rpc_internal};

/// An internal error carrying the underlying error text (dcrd
/// `rpcInternalErr`; the context only feeds the log).
pub fn rpc_internal_err(err_text: &str) -> RPCError {
    RPCError::new(err_rpc_internal().code, err_text)
}

/// An invalid-parameter error (dcrd `rpcInvalidError`).
pub fn rpc_invalid_error(message: &str) -> RPCError {
    RPCError::new(codes::INVALID_PARAMETER, message)
}

/// A deserialization error (dcrd `rpcDeserializationError`).
pub fn rpc_deserialization_error(message: &str) -> RPCError {
    RPCError::new(codes::DESERIALIZATION, message)
}

/// A rule error (dcrd `rpcRuleError`).
pub fn rpc_rule_error(message: &str) -> RPCError {
    RPCError::new(codes::MISC, message)
}

/// A rejected duplicate transaction error (dcrd
/// `rpcDuplicateTxError`).
pub fn rpc_duplicate_tx_error(message: &str) -> RPCError {
    RPCError::new(codes::DUPLICATE_TX, message)
}

/// An address/key error (dcrd `rpcAddressKeyError`).
pub fn rpc_address_key_error(message: &str) -> RPCError {
    RPCError::new(codes::INVALID_ADDRESS_OR_KEY, message)
}

/// The hex-decode failure error with dcrd's exact quoting (dcrd
/// `rpcDecodeHexError`).
pub fn rpc_decode_hex_error(got_hex: &str) -> RPCError {
    RPCError::new(
        codes::DECODE_HEX_STRING,
        &format!(
            "Argument must be hexadecimal string (not {})",
            dcroxide_dcrjson::gojson::go_quote(got_hex)
        ),
    )
}

/// The no-transaction-information error (dcrd `rpcNoTxInfoError`).
pub fn rpc_no_tx_info_error(tx_hash: &Hash) -> RPCError {
    RPCError::new(
        codes::NO_TX_INFO,
        &format!("No information available about transaction {tx_hash}"),
    )
}

/// The block-not-found error (dcrd `rpcBlockNotFoundError`).
pub fn rpc_block_not_found_error(block_hash: &Hash) -> RPCError {
    RPCError::new(
        codes::BLOCK_NOT_FOUND,
        &format!("No information available about block {block_hash}"),
    )
}

/// The mix-message-not-found error (dcrd
/// `rpcMixMessageNotFoundError`).
pub fn rpc_mix_message_not_found_error(hash: &Hash) -> RPCError {
    RPCError::new(
        codes::NO_MIX_MSG_INFO,
        &format!("No information available about mix message {hash}"),
    )
}

/// The connection-closed error (dcrd `rpcConnectionClosedError`).
pub fn rpc_connection_closed_error() -> RPCError {
    RPCError::new(codes::MISC, "Connection closed")
}

/// A cancellation error (dcrd `rpcCancelError`).
pub fn rpc_cancel_error(message: &str) -> RPCError {
    RPCError::new(codes::CANCEL, message)
}

/// The miscellaneous error (dcrd `rpcMiscError`).
pub fn rpc_misc_error(message: &str) -> RPCError {
    RPCError::new(codes::MISC, message)
}
