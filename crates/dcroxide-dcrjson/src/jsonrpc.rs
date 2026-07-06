// SPDX-License-Identifier: ISC
//! JSON-RPC request and response primitives (dcrd dcrjson
//! `jsonrpc.go` and `jsonrpcerr.go`).

use crate::gojson::{append_json_string, format_float_json};
use crate::{DcrjsonError, ErrorKind, make_error};

/// An error code to be used as a part of an [`RPCError`] (dcrd
/// `RPCErrorCode`).
pub type RPCErrorCode = i32;

/// An error that is used as a part of a JSON-RPC Response object (dcrd
/// `RPCError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RPCError {
    /// The error code.
    pub code: RPCErrorCode,
    /// The error message.
    pub message: String,
}

impl RPCError {
    /// Construct a new JSON-RPC error suitable for use in a JSON-RPC
    /// Response object (dcrd `NewRPCError`).
    pub fn new(code: RPCErrorCode, message: &str) -> RPCError {
        RPCError {
            code,
            message: message.to_string(),
        }
    }

    /// Marshal to JSON exactly as Go does for the `*RPCError` field
    /// (both fields carry `omitempty`).
    pub fn marshal(&self) -> String {
        let mut out = String::from("{");
        if self.code != 0 {
            out.push_str("\"code\":");
            out.push_str(&self.code.to_string());
        }
        if !self.message.is_empty() {
            if self.code != 0 {
                out.push(',');
            }
            out.push_str("\"message\":");
            append_json_string(&mut out, &self.message);
        }
        out.push('}');
        out
    }
}

impl core::fmt::Display for RPCError {
    /// A string describing the RPC error (dcrd `RPCError.Error`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// The standard JSON-RPC 2.0 invalid request error (dcrd
/// `ErrRPCInvalidRequest`).
pub fn err_rpc_invalid_request() -> RPCError {
    RPCError::new(-32600, "Invalid request")
}

/// The standard JSON-RPC 2.0 method not found error (dcrd
/// `ErrRPCMethodNotFound`).
pub fn err_rpc_method_not_found() -> RPCError {
    RPCError::new(-32601, "Method not found")
}

/// The standard JSON-RPC 2.0 invalid parameters error (dcrd
/// `ErrRPCInvalidParams`).
pub fn err_rpc_invalid_params() -> RPCError {
    RPCError::new(-32602, "Invalid parameters")
}

/// The standard JSON-RPC 2.0 internal error (dcrd `ErrRPCInternal`).
pub fn err_rpc_internal() -> RPCError {
    RPCError::new(-32603, "Internal error")
}

/// The standard JSON-RPC 2.0 parse error (dcrd `ErrRPCParse`).
pub fn err_rpc_parse() -> RPCError {
    RPCError::new(-32700, "Parse error")
}

/// General application defined JSON errors (dcrd `ErrRPCMisc` and
/// friends).
pub mod codes {
    use super::RPCErrorCode;

    /// dcrd `ErrRPCMisc`.
    pub const MISC: RPCErrorCode = -1;
    /// dcrd `ErrRPCForbiddenBySafeMode`.
    pub const FORBIDDEN_BY_SAFE_MODE: RPCErrorCode = -2;
    /// dcrd `ErrRPCType`.
    pub const TYPE: RPCErrorCode = -3;
    /// dcrd `ErrRPCInvalidAddressOrKey`.
    pub const INVALID_ADDRESS_OR_KEY: RPCErrorCode = -5;
    /// dcrd `ErrRPCOutOfMemory`.
    pub const OUT_OF_MEMORY: RPCErrorCode = -7;
    /// dcrd `ErrRPCInvalidParameter`.
    pub const INVALID_PARAMETER: RPCErrorCode = -8;
    /// dcrd `ErrRPCDatabase`.
    pub const DATABASE: RPCErrorCode = -20;
    /// dcrd `ErrRPCDeserialization`.
    pub const DESERIALIZATION: RPCErrorCode = -22;
    /// dcrd `ErrRPCVerify`.
    pub const VERIFY: RPCErrorCode = -25;
    /// dcrd `ErrRPCInvalidState`.
    pub const INVALID_STATE: RPCErrorCode = -26;
    /// dcrd `ErrRPCCancel`.
    pub const CANCEL: RPCErrorCode = -27;
    /// dcrd `ErrRPCClientNotConnected`.
    pub const CLIENT_NOT_CONNECTED: RPCErrorCode = -9;
    /// dcrd `ErrRPCClientInInitialDownload`.
    pub const CLIENT_IN_INITIAL_DOWNLOAD: RPCErrorCode = -10;
    /// dcrd `ErrRPCWallet`.
    pub const WALLET: RPCErrorCode = -4;
    /// dcrd `ErrRPCWalletInsufficientFunds`.
    pub const WALLET_INSUFFICIENT_FUNDS: RPCErrorCode = -6;
    /// dcrd `ErrRPCWalletInvalidAccountName`.
    pub const WALLET_INVALID_ACCOUNT_NAME: RPCErrorCode = -11;
    /// dcrd `ErrRPCWalletKeypoolRanOut`.
    pub const WALLET_KEYPOOL_RAN_OUT: RPCErrorCode = -12;
    /// dcrd `ErrRPCWalletUnlockNeeded`.
    pub const WALLET_UNLOCK_NEEDED: RPCErrorCode = -13;
    /// dcrd `ErrRPCWalletPassphraseIncorrect`.
    pub const WALLET_PASSPHRASE_INCORRECT: RPCErrorCode = -14;
    /// dcrd `ErrRPCWalletWrongEncState`.
    pub const WALLET_WRONG_ENC_STATE: RPCErrorCode = -15;
    /// dcrd `ErrRPCWalletEncryptionFailed`.
    pub const WALLET_ENCRYPTION_FAILED: RPCErrorCode = -16;
    /// dcrd `ErrRPCWalletAlreadyUnlocked`.
    pub const WALLET_ALREADY_UNLOCKED: RPCErrorCode = -17;
    /// dcrd `ErrRPCBlockNotFound`.
    pub const BLOCK_NOT_FOUND: RPCErrorCode = -5;
    /// dcrd `ErrRPCBlockCount`.
    pub const BLOCK_COUNT: RPCErrorCode = -5;
    /// dcrd `ErrRPCBestBlockHash`.
    pub const BEST_BLOCK_HASH: RPCErrorCode = -5;
    /// dcrd `ErrRPCDifficulty`.
    pub const DIFFICULTY: RPCErrorCode = -5;
    /// dcrd `ErrRPCOutOfRange`.
    pub const OUT_OF_RANGE: RPCErrorCode = -1;
    /// dcrd `ErrRPCNoTxInfo`.
    pub const NO_TX_INFO: RPCErrorCode = -5;
    /// dcrd `ErrRPCNoNewestBlockInfo`.
    pub const NO_NEWEST_BLOCK_INFO: RPCErrorCode = -5;
    /// dcrd `ErrRPCInvalidTxVout`.
    pub const INVALID_TX_VOUT: RPCErrorCode = -5;
    /// dcrd `ErrRPCNoTreasury`.
    pub const NO_TREASURY: RPCErrorCode = -5;
    /// dcrd `ErrRPCNoMixMsgInfo`.
    pub const NO_MIX_MSG_INFO: RPCErrorCode = -5;
    /// dcrd `ErrRPCRawTxString`.
    pub const RAW_TX_STRING: RPCErrorCode = -32602;
    /// dcrd `ErrRPCDecodeHexString`.
    pub const DECODE_HEX_STRING: RPCErrorCode = -22;
    /// dcrd `ErrRPCProfilerState`.
    pub const PROFILER_STATE: RPCErrorCode = -26;
    /// dcrd `ErrRPCDuplicateTx`.
    pub const DUPLICATE_TX: RPCErrorCode = -40;
    /// dcrd `ErrRPCReconsiderFailure`.
    pub const RECONSIDER_FAILURE: RPCErrorCode = -50;
    /// dcrd `ErrRPCNoWallet`.
    pub const NO_WALLET: RPCErrorCode = -1;
    /// dcrd `ErrRPCUnimplemented`.
    pub const UNIMPLEMENTED: RPCErrorCode = -1;
}

/// A JSON-RPC id value.  Go allows any integer, float, or string type
/// (or nil); the [`RpcId::Invalid`] variant models Go values that fail
/// `IsValidIDType`, carrying the Go type display used in the error.
#[derive(Clone, Debug, PartialEq)]
pub enum RpcId {
    /// A signed integer id of any width.
    Int(i64),
    /// An unsigned integer id of any width.
    Uint(u64),
    /// A `float64` id.
    Float(f64),
    /// A string id.
    Str(String),
    /// A nil id (used for notifications).
    Null,
    /// A value whose Go dynamic type is not a valid id type; the
    /// string is the Go type display (e.g. `[]int`).
    Invalid(String),
}

impl RpcId {
    fn marshal(&self, out: &mut String) {
        match self {
            RpcId::Int(i) => out.push_str(&i.to_string()),
            RpcId::Uint(u) => out.push_str(&u.to_string()),
            RpcId::Float(f) => out.push_str(&format_float_json(*f)),
            RpcId::Str(s) => append_json_string(out, s),
            RpcId::Null | RpcId::Invalid(_) => out.push_str("null"),
        }
    }
}

/// Check that the id field is of a type allowed by JSON-RPC 2.0 (dcrd
/// `IsValidIDType`).
pub fn is_valid_id_type(id: &RpcId) -> bool {
    !matches!(id, RpcId::Invalid(_))
}

/// A raw JSON-RPC request (dcrd `Request`).  The parameters are kept
/// as raw JSON documents.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// The JSON-RPC protocol version ("1.0" or "2.0").
    pub jsonrpc: String,
    /// The raw marshalled parameters.
    pub params: Vec<String>,
    /// The request id.
    pub id: RpcId,
}

/// Return a new JSON-RPC request object given the provided rpc
/// version, id, and pre-marshalled parameters (dcrd `NewRequest`; the
/// method is supplied when marshalling).
pub fn new_request(
    rpc_version: &str,
    id: &RpcId,
    params: Vec<String>,
) -> Result<Request, DcrjsonError> {
    // Default to JSON-RPC 1.0 if the RPC type is not specified.
    let version = if rpc_version != "2.0" && rpc_version != "1.0" {
        "1.0"
    } else {
        rpc_version
    };

    if !is_valid_id_type(id) {
        let type_name = match id {
            RpcId::Invalid(t) => t.clone(),
            _ => unreachable!(),
        };
        let str = format!("the id of type '{type_name}' is invalid");
        return Err(make_error(ErrorKind::InvalidType, str));
    }

    Ok(Request {
        jsonrpc: version.to_string(),
        params,
        id: id.clone(),
    })
}

/// Marshal a request with its method name to the exact bytes Go's
/// `json.Marshal` produces for dcrd's `Request` struct.
pub fn marshal_request(req: &Request, method: &str) -> String {
    let mut out = String::from("{\"jsonrpc\":");
    append_json_string(&mut out, &req.jsonrpc);
    out.push_str(",\"method\":");
    append_json_string(&mut out, method);
    out.push_str(",\"params\":[");
    for (i, p) in req.params.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(p);
    }
    out.push_str("],\"id\":");
    req.id.marshal(&mut out);
    out.push('}');
    out
}

/// Marshal the passed rpc version, id, pre-marshalled result, and
/// error to a JSON-RPC response byte slice suitable for transmission
/// to a JSON-RPC client (dcrd `MarshalResponse`).  A `None` result
/// marshals as JSON null, exactly as Go marshals a nil interface.
pub fn marshal_response(
    rpc_version: &str,
    id: &RpcId,
    marshalled_result: Option<&str>,
    rpc_err: Option<&RPCError>,
) -> Result<String, DcrjsonError> {
    let version = if rpc_version != "2.0" && rpc_version != "1.0" {
        "1.0"
    } else {
        rpc_version
    };

    if !is_valid_id_type(id) {
        let type_name = match id {
            RpcId::Invalid(t) => t.clone(),
            _ => unreachable!(),
        };
        let str = format!("the id of type '{type_name}' is invalid");
        return Err(make_error(ErrorKind::InvalidType, str));
    }

    let mut out = String::from("{\"jsonrpc\":");
    append_json_string(&mut out, version);
    out.push_str(",\"result\":");
    out.push_str(marshalled_result.unwrap_or("null"));
    out.push_str(",\"error\":");
    match rpc_err {
        Some(e) => out.push_str(&e.marshal()),
        None => out.push_str("null"),
    }
    out.push_str(",\"id\":");
    id.marshal(&mut out);
    out.push('}');
    Ok(out)
}
