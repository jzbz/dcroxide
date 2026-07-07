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

pub mod config;
pub mod flags;
mod gostd;
pub mod ipc;
pub mod logsubsys;
pub mod params;
pub mod version;

pub use config::{
    AUTH_TYPE_BASIC, AUTH_TYPE_CLIENT_CERT, Assignment, Config, ConfigEnv, DialSelection,
    IfaceAddrs, IpNet, LookupSelection, NORMALIZE_INTERFACE_ADDRS, NORMALIZE_INTERFACE_FIRST_ADDR,
    OnionSelection, TlsCurve, app_data_dir, clean_and_expand_path, create_default_config_file,
    load_config, load_config_from_argv, normalize_addresses, parse_listeners,
    parse_network_interfaces, port_to_local_host_addr, remove_duplicate_addresses,
    sample_dcrd_conf, tls_curve, validate_profile_addr,
};
pub use flags::{OPTIONS, OptKind, OptSpec};
pub use gostd::{go_duration_string, parse_go_duration};
pub use ipc::{LifetimeAction, LifetimeEventId, PipeMessage};
pub use logsubsys::{LogLevel, LogLevels, parse_and_set_debug_levels, supported_subsystems};
pub use params::{ActiveNet, NodeParams};
