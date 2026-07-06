// SPDX-License-Identifier: ISC
//! RPC server components from dcrd's `internal/rpcserver`, starting
//! with the help subsystem: the English help description map, the
//! per-method result types, and the caching help/usage provider.
//!
//! Combined with the dcrjson machinery and the chain server type
//! descriptors, this produces the complete output of dcrd's `help`
//! RPC byte for byte, including QK-0005: the usage cache holds a
//! single string regardless of whether websocket commands were
//! requested, so whichever variant is generated first is returned
//! for both.

pub mod handlers;
pub mod help;
pub mod helpdescs;
pub mod helpers;
pub mod rpcerrors;
pub mod server;
pub mod txresults;
pub mod version;

pub use help::{HelpCacher, RPC_HANDLER_METHODS, WS_HANDLER_METHODS, rpc_result_types};
pub use helpdescs::HELP_DESCS_EN_US;
