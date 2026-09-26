// SPDX-License-Identifier: ISC
//! Daemon assembly, ported from dcrd's package main and the internal
//! packages it wires together, at the parity pin, master `b9634e01`:
//!
//! - configuration: the network parameter groupings with their RPC
//!   ports (`params`), the go-flags v1.6.1 command line and INI
//!   front-end (`flags`), and the `config.go` pipeline behind it
//!   (`config`) — defaults, config file and command line precedence,
//!   and the full validation and derivation gauntlet with dcrd's exact
//!   error strings — plus the logging subsystems and log line format;
//! - the peer-to-peer server: `server.go`'s decision core (`server`),
//!   the threaded runtime over its `Run` and `peerHandler` goroutines
//!   (`runtime`), the per-peer message loops and served-peer dispatch,
//!   the outbound connection driver, seeding, SOCKS dialing, and the
//!   netsync, mempool, mixing pool and chain notification seams;
//! - the RPC server's HTTP and websocket serving (`rpcrun`,
//!   `websocket`, `wsframe`), the CPU miner and block template glue,
//!   and the optional indexes;
//! - process plumbing: the pipe IPC protocol and runtime (`ipc`,
//!   `pipeserve`), process limits (`limits`), the median-adjusted
//!   network time (`mediantime`), and the `addblock` tool's core.
//!
//! The `dcroxide` binary (`src/bin/dcroxide.rs`) is dcrd's `dcrdMain`
//! and `newServer` over these pieces; `addblock`, `gencerts` and
//! `promptsecret` port dcrd's `cmd/` tools.

#![forbid(unsafe_code)]

pub mod addblock;
pub mod bgtemplate;
pub mod blockdb;
pub mod chainntfns;
pub mod config;
pub mod cpuminer;
pub mod dispatch;
pub mod fees;
pub mod flags;
mod gostd;
pub mod indexes;
pub mod ipc;
pub mod limits;
pub mod listenaddrs;
pub mod logging;
pub mod logo;
pub mod logsubsys;
pub mod mediantime;
pub mod mining;
pub mod mixnode;
pub mod outbound;
pub mod params;
pub mod peerconn;
pub mod peerloop;
pub mod pipeserve;
pub mod progresslog;
pub mod rebroadcast;
pub mod rpcrun;
pub mod runtime;
pub mod secretfile;
pub mod seeding;
pub mod server;
pub mod socks;
pub mod socktimeout;
pub mod sync;
pub mod transport;
pub mod txmempool;
pub mod version;
pub mod websocket;
pub mod wsframe;

pub use config::{
    AUTH_TYPE_BASIC, AUTH_TYPE_CLIENT_CERT, Assignment, Config, ConfigEnv, DialSelection,
    ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS, ERR_VERSION_REQUESTED, IfaceAddrs, IpPrefix,
    LookupSelection, NORMALIZE_INTERFACE_ADDRS, NORMALIZE_INTERFACE_FIRST_ADDR, OnionSelection,
    TlsCurve, app_data_dir, clean_and_expand_path, create_default_config_file, load_config,
    load_config_from_argv, normalize_addresses, parse_listeners, parse_network_interfaces,
    port_to_local_host_addr, remove_duplicate_addresses, sample_dcroxide_conf, tls_curve,
    validate_profile_addr,
};
pub use flags::{OPTIONS, OptKind, OptSpec};
pub use gostd::{go_duration_string, go_parse_int, parse_go_duration};
pub use ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
pub use logsubsys::{LogLevel, LogLevels, parse_and_set_debug_levels, supported_subsystems};
pub use params::{ActiveNet, NodeParams};
pub use server::{
    DEFAULT_TARGET_OUTBOUND, MAX_PEERS_MAKECHAN_LIMIT, addrmgr_to_wire_net_address, has_services,
    host_to_net_address, is_supported_net_addr_type_v1, max_peers_is_startable, natf_supported,
    netsync_max_outbound_peers, server_target_outbound, wire_to_addrmgr_net_address,
    wire_to_addrmgr_net_addresses,
};
