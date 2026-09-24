// SPDX-License-Identifier: ISC
//! RPC server components from dcrd's `internal/rpcserver`: the server
//! configuration and its interfaces, the command handlers and request
//! dispatch, the HTTP request surface (auth decisions, request
//! unmarshalling, response assembly), the websocket client handling
//! and notifications, the getwork semaphore, the transaction result
//! builders, and the help subsystem.  The listener and connection
//! plumbing that serve them are the daemon's (dcroxide-node).
//!
//! The help subsystem -- the English help description map, the
//! per-method result types, and the caching help/usage provider --
//! combined with the dcrjson machinery and the chain server type
//! descriptors, produces the complete output of dcrd's `help` RPC byte
//! for byte, including QK-0005: the usage cache holds a single string
//! regardless of whether websocket commands were requested, so
//! whichever variant is requested first is returned for both.

pub mod dispatch;
pub mod handlers;
pub mod help;
pub mod helpdescs;
pub mod helpers;
pub mod http;
pub mod rpcerrors;
pub mod server;
pub mod txresults;
pub mod version;
pub mod websocket;
pub mod worksem;

pub use help::{HelpCacher, RPC_HANDLER_METHODS, WS_HANDLER_METHODS, rpc_result_types};
pub use helpdescs::HELP_DESCS_EN_US;
