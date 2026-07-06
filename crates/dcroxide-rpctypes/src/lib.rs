// SPDX-License-Identifier: ISC
//! Chain server JSON-RPC command, result, and notification definitions
//! from dcrd's `rpc/jsonrpc/types/v4` module.
//!
//! dcrd defines these as Go structs consumed reflectively by dcrjson;
//! the port expresses each type as a [`GoType`] descriptor over the
//! dcroxide-dcrjson infrastructure, preserving the field order, struct
//! tags, defaults, and usage strings that determine every observable
//! byte.  The `register_*` functions perform the same registrations as
//! dcrd's `init` functions, keyed by the `types.Method` dynamic type.
//!
//! The Go `New*Cmd` constructor helpers have no equivalent because
//! command instances are built directly as
//! [`dcroxide_dcrjson::CmdInstance`] values over these descriptors.

use dcroxide_dcrjson::{GoType, Method, Registry, StructField};

pub mod chainsvrcmds;
pub mod chainsvrresults;
pub mod chainsvrwscmds;
pub mod chainsvrwsntfns;
pub mod chainsvrwsresults;

pub use chainsvrcmds::register_chain_svr_cmds;
pub use chainsvrwscmds::register_chain_svr_ws_cmds;
pub use chainsvrwsntfns::register_chain_svr_ws_ntfns;

/// The Go display name of the method type used to register method and
/// parameter pairs with dcrjson (dcrd `types.Method`).
pub const METHOD_TYPE_NAME: &str = "types.Method";

/// A method key of the `types.Method` dynamic type (dcrd `Method`).
pub fn method(name: &str) -> Method {
    Method::typed(METHOD_TYPE_NAME, name)
}

/// Register every chain server command, websocket command, and
/// websocket notification, in the same order dcrd's `init` functions
/// run (lexical file order within the package).
pub fn register_all(registry: &mut Registry) {
    register_chain_svr_cmds(registry);
    register_chain_svr_ws_cmds(registry);
    register_chain_svr_ws_ntfns(registry);
}

/// A plain exported field with no struct tags.
pub(crate) fn f(name: &str, typ: GoType) -> StructField {
    StructField::new(name, typ)
}

/// A named struct type in the `types` package.
pub(crate) fn strukt(name: &str, fields: Vec<StructField>) -> GoType {
    GoType::strukt("types", name, fields)
}

/// A defined string type in the `types` package.
pub(crate) fn named_str(name: &str) -> GoType {
    GoType::Named(
        "types".to_string(),
        name.to_string(),
        Box::new(GoType::String),
    )
}
