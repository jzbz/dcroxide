// SPDX-License-Identifier: ISC
//! Daemon assembly, ported from dcrd's package main at
//! release-v2.1.5: the network parameter groupings with their RPC
//! ports and the configuration pipeline (`config.go`) — defaults,
//! config file and command line precedence, and the full validation
//! and derivation gauntlet with dcrd's exact error strings.  The
//! command line and INI syntax layer replicating go-flags arrives
//! with a later piece; the pipeline consumes already-split option
//! assignments.

#![forbid(unsafe_code)]

pub mod addblock;
pub mod bgtemplate;
pub mod chainntfns;
pub mod config;
pub mod cpuminer;
pub mod dispatch;
pub mod fees;
pub mod flags;
mod gostd;
pub mod indexes;
pub mod ipc;
pub mod logging;
pub mod logo;
pub mod logsubsys;
pub mod mining;
pub mod mixnode;
pub mod outbound;
pub mod params;
pub mod peerconn;
pub mod peerloop;
pub mod pipeserve;
pub mod rebroadcast;
pub mod rpcrun;
pub mod runtime;
pub mod seeding;
pub mod server;
pub mod socks;
pub mod sync;
pub mod transport;
pub mod txmempool;
pub mod version;
pub mod websocket;
pub mod wsframe;

pub use config::{
    AUTH_TYPE_BASIC, AUTH_TYPE_CLIENT_CERT, Assignment, Config, ConfigEnv, DialSelection,
    ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS, ERR_VERSION_REQUESTED, IfaceAddrs, IpNet,
    LookupSelection, NORMALIZE_INTERFACE_ADDRS, NORMALIZE_INTERFACE_FIRST_ADDR, OnionSelection,
    TlsCurve, app_data_dir, clean_and_expand_path, create_default_config_file, load_config,
    load_config_from_argv, normalize_addresses, parse_listeners, parse_network_interfaces,
    port_to_local_host_addr, remove_duplicate_addresses, sample_dcrd_conf, tls_curve,
    validate_profile_addr,
};
pub use flags::{OPTIONS, OptKind, OptSpec};
pub use gostd::{go_duration_string, go_parse_int, parse_go_duration};
pub use ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
pub use logsubsys::{LogLevel, LogLevels, parse_and_set_debug_levels, supported_subsystems};
pub use params::{ActiveNet, NodeParams};
pub use server::{
    DEFAULT_TARGET_OUTBOUND, MAX_CACHED_NA_SUBMISSIONS, NaSubmission, NaSubmissionCache,
    addrmgr_to_wire_net_address, has_services, host_to_net_address, is_supported_net_addr_type_v1,
    natf_supported, resolve_local_address, wire_to_addrmgr_net_address,
    wire_to_addrmgr_net_addresses,
};
