// SPDX-License-Identifier: ISC
//! An implementation of the JSON-RPC 1.0 command infrastructure of
//! dcrd's `dcrjson/v4` module.
//!
//! dcrjson drives everything through Go reflection over registered
//! command struct types.  The port makes the reflection data explicit:
//! [`GoType`] trees describe the command parameter and result types
//! (including struct tags), and the registry, marshalling, parameter
//! parsing, usage, and help generation operate on those descriptions
//! producing byte-for-byte the JSON, error strings, and help text dcrd
//! produces.  Go's package-global registry with its mutex is
//! daemon-phase concurrency; the port keeps an explicit [`Registry`]
//! value.
//!
//! The pointer helper functions (`dcrjson.Bool`, `dcrjson.Int`, ...)
//! have no equivalent because optional values are represented with
//! [`GoValue::Null`] directly.

mod cmdparse;
pub mod gojson;
mod gotype;
mod hashes;
mod help;
mod jsonrpc;
mod registry;
mod tabwriter;
mod usage;

pub use cmdparse::{Arg, CmdInstance, marshal_cmd, new_cmd, parse_params};
pub use gotype::{GoType, GoValue, Kind, StructField};
pub use hashes::{decode_concatenated_hashes, encode_concatenated_hashes};
pub use jsonrpc::{
    RPCError, RPCErrorCode, Request, RpcId, codes, err_rpc_internal, err_rpc_invalid_params,
    err_rpc_invalid_request, err_rpc_method_not_found, err_rpc_parse, is_valid_id_type,
    marshal_request, marshal_response, new_request,
};
pub use registry::{Method, Registry, UF_NOTIFICATION, UF_WEBSOCKET_ONLY, UsageFlag};
pub use tabwriter::TabWriter;

/// A kind of error (dcrd `ErrorKind`).  These error kinds are NOT used
/// for JSON-RPC response errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A command with the specified method already exists.
    DuplicateMethod,
    /// One or more unrecognized flag bits were specified.
    InvalidUsageFlags,
    /// A type was passed that is not the required type.
    InvalidType,
    /// The provided command struct contains an embedded type which is
    /// not supported.
    EmbeddedType,
    /// The provided command struct contains an unexported field which
    /// is not supported.
    UnexportedField,
    /// The type of a field in the provided command struct is not one
    /// of the supported types.
    UnsupportedFieldType,
    /// A non-optional field was specified after an optional field.
    NonOptionalField,
    /// A `jsonrpcdefault` struct tag was specified for a non-optional
    /// field.
    NonOptionalDefault,
    /// A `jsonrpcdefault` struct tag contains a value that doesn't
    /// match the type of the field.
    MismatchedDefault,
    /// A method was specified that has not been registered.
    UnregisteredMethod,
    /// A description required to generate help is missing.
    MissingDescription,
    /// The number of params supplied does not match the requirements
    /// of the associated command.
    NumParams,
}

impl ErrorKind {
    /// The dcrd constant name for the kind, as printed by the Go
    /// `ErrorKind.Error` method.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::DuplicateMethod => "ErrDuplicateMethod",
            ErrorKind::InvalidUsageFlags => "ErrInvalidUsageFlags",
            ErrorKind::InvalidType => "ErrInvalidType",
            ErrorKind::EmbeddedType => "ErrEmbeddedType",
            ErrorKind::UnexportedField => "ErrUnexportedField",
            ErrorKind::UnsupportedFieldType => "ErrUnsupportedFieldType",
            ErrorKind::NonOptionalField => "ErrNonOptionalField",
            ErrorKind::NonOptionalDefault => "ErrNonOptionalDefault",
            ErrorKind::MismatchedDefault => "ErrMismatchedDefault",
            ErrorKind::UnregisteredMethod => "ErrUnregisteredMethod",
            ErrorKind::MissingDescription => "ErrMissingDescription",
            ErrorKind::NumParams => "ErrNumParams",
        }
    }
}

/// An error related to Decred's JSON-RPC APIs (dcrd `Error`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrjsonError {
    /// The kind of error.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl core::fmt::Display for DcrjsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for DcrjsonError {}

/// Create a [`DcrjsonError`] given a set of arguments (dcrd
/// `makeError`).
pub(crate) fn make_error(kind: ErrorKind, description: String) -> DcrjsonError {
    DcrjsonError { kind, description }
}
