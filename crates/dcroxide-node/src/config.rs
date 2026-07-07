// SPDX-License-Identifier: ISC
//! The dcrd configuration pipeline (`config.go` at release-v2.1.5):
//! defaults, config file and command line precedence, and the full
//! validation and derivation gauntlet with dcrd's exact error
//! strings.  The command line front-end replicating go-flags syntax
//! arrives with a later piece; the pipeline consumes already-split
//! option assignments and reproduces go-flags' observable
//! application order (the help pre-parse applies the command line
//! before the config file, so repeated slice options accumulate
//! command-line values first, then file values, then the
//! command-line values again).
//!
//! Environment lookups (localhost resolution, network interfaces,
//! environment variables, user home directories, and randomness)
//! are injected; the filesystem operations (home directory
//! creation, config file reads, and default config creation) use
//! the real filesystem exactly as dcrd does.

// The pipeline mirrors Go's arithmetic over bounded configuration
// values.
#![allow(clippy::arithmetic_side_effects)]

use std::fmt;
use std::fs;

use dcroxide_rpc::server::RpcNetworkInfo;
use dcroxide_txscript::stdaddr::{self, Address};

use crate::gostd::{
    expand_env, filepath_abs, filepath_clean, filepath_join, go_atoi_ok, go_duration_string,
    go_parse_bool, go_quote, join_host_port, parse_go_duration, split_host_port,
};
use crate::logsubsys::{LogLevels, parse_and_set_debug_levels};
use crate::params::NodeParams;

// Defaults for general application behavior options.
const DEFAULT_CONFIG_FILENAME: &str = "dcrd.conf";
const DEFAULT_DATA_DIRNAME: &str = "data";
const DEFAULT_LOG_DIRNAME: &str = "logs";
const DEFAULT_LOG_SIZE: &str = "10M";
const DEFAULT_DB_TYPE: &str = "ffldb";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_SIG_CACHE_MAX_SIZE: u64 = 100000;
const DEFAULT_UTXO_CACHE_MAX_SIZE: u64 = 150;
const MIN_UTXO_CACHE_MAX_SIZE: u64 = 25;
const MAX_UTXO_CACHE_MAX_SIZE: u64 = 32768; // 32 GiB

// Defaults for RPC server options and policy.
const DEFAULT_TLS_CURVE: &str = "P-256";
const DEFAULT_MAX_RPC_CLIENTS: i64 = 10;
const DEFAULT_MAX_RPC_WEBSOCKETS: i64 = 25;
const DEFAULT_MAX_RPC_CONCURRENT_REQS: i64 = 20;

// Defaults for P2P network options.
const DEFAULT_MAX_SAME_IP: i64 = 5;
const DEFAULT_MAX_PEERS: i64 = 125;
const DEFAULT_DIAL_TIMEOUT_NANOS: i64 = 30 * 1_000_000_000;
const DEFAULT_PEER_IDLE_TIMEOUT_NANOS: i64 = 120 * 1_000_000_000;

// Defaults for banning options.
const DEFAULT_BAN_DURATION_NANOS: i64 = 24 * 3600 * 1_000_000_000;
const DEFAULT_BAN_THRESHOLD: u32 = 100;

// Defaults for relay and mempool policy options.
const DEFAULT_MAX_ORPHAN_TRANSACTIONS: i64 = 100;

// Defaults for mining options and policy.
const DEFAULT_BLOCK_MAX_SIZE: u32 = 375000;
const BLOCK_MAX_SIZE_MIN: u32 = 1000;

/// The basic RPC authorization type (dcrd `authTypeBasic`).
pub const AUTH_TYPE_BASIC: &str = "basic";
/// The client certificate RPC authorization type (dcrd
/// `authTypeClientCert`).
pub const AUTH_TYPE_CLIENT_CERT: &str = "clientcert";

/// The supported database backends (dcrd `database.SupportedDrivers`).
const KNOWN_DB_TYPES: [&str; 1] = ["ffldb"];

/// The embedded sample dcrd.conf (dcrd `sampleconfig.Dcrd`).
pub fn sample_dcrd_conf() -> &'static str {
    include_str!("sample-dcrd.conf")
}

/// A single option assignment, already split from whatever syntax
/// carried it: the long option name and its value (`None` for a
/// bare boolean flag).
#[derive(Debug, Clone)]
pub struct Assignment {
    /// The long option name.
    pub name: String,
    /// The value; `None` for a bare boolean flag.
    pub value: Option<String>,
}

/// The addresses of a network interface (the used subset of Go's
/// `net.Interface`).
#[derive(Debug, Clone)]
pub struct IfaceAddrs {
    /// The interface index (used for IPv6 zones).
    pub index: u32,
    /// The interface addresses.
    pub addrs: Vec<std::net::IpAddr>,
}

/// A network interface lookup by name.
pub type IfaceLookup<'a> = Box<dyn Fn(&str) -> Option<IfaceAddrs> + 'a>;
/// An environment variable or user home directory lookup.
pub type StringLookup<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;
/// A random byte source.
pub type RandSource<'a> = Box<dyn Fn(&mut [u8]) + 'a>;

/// The injected environment for the configuration pipeline.
pub struct ConfigEnv<'a> {
    /// The default application home directory
    /// (`dcrutil.AppDataDir("dcrd", false)`).
    pub default_home_dir: String,
    /// Resolve "localhost" like Go's `net.LookupHost`.
    pub lookup_localhost: Box<dyn Fn() -> Result<Vec<String>, String> + 'a>,
    /// Look up a network interface by name, if one exists.
    pub interface_by_name: IfaceLookup<'a>,
    /// An environment variable lookup for path expansion.
    pub getenv: StringLookup<'a>,
    /// A user home directory lookup; the empty name is the current
    /// user.
    pub user_home: StringLookup<'a>,
    /// A cryptographically random byte source for generated RPC
    /// credentials.
    pub rand_bytes: RandSource<'a>,
}

/// How ordinary connections are dialed (the observable selection of
/// dcrd's `cfg.dial`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialSelection {
    /// The standard dialer.
    Direct,
    /// The SOCKS5 proxy dialer.
    SocksProxy,
}

/// How DNS lookups resolve (the observable selection of dcrd's
/// `cfg.lookup`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupSelection {
    /// The system resolver.
    System,
    /// Tor-based resolution through the proxy.
    TorViaProxy,
}

/// How onion addresses are dialed and resolved (the observable
/// selection of dcrd's `cfg.oniondial`/`cfg.onionlookup`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnionSelection {
    /// Same as the ordinary dial and lookup functions.
    SameAsMain,
    /// The onion-specific proxy.
    OnionProxy,
    /// Tor has been disabled; onion dials and lookups error.
    Disabled,
}

/// An IP network entry from the whitelist (the used subset of Go's
/// `net.IPNet`); the address bytes are 4 for IPv4 and 16 for IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNet {
    /// The network address bytes, already masked.
    pub ip: Vec<u8>,
    /// The prefix length.
    pub ones: u32,
}

impl fmt::Display for IpNet {
    /// Format like Go's `net.IPNet.String` for canonical masks.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", go_ip_string(&self.ip), self.ones)
    }
}

/// Format IP bytes like Go's `net.IP.String`: dotted for IPv4 (and
/// IPv4-mapped IPv6), RFC 5952 for IPv6.
fn go_ip_string(ip: &[u8]) -> String {
    if ip.len() == 4 {
        return format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }
    if ip.len() == 16 {
        if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
            return format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        }
        // Find the longest run of zero 16-bit groups (length two or
        // more), preferring the earliest.
        let groups: Vec<u16> = (0..8)
            .map(|i| (u16::from(ip[2 * i]) << 8) | u16::from(ip[2 * i + 1]))
            .collect();
        let (mut best_start, mut best_len) = (usize::MAX, 0usize);
        let mut i = 0;
        while i < 8 {
            if groups[i] == 0 {
                let start = i;
                while i < 8 && groups[i] == 0 {
                    i += 1;
                }
                if i - start > best_len {
                    best_start = start;
                    best_len = i - start;
                }
            } else {
                i += 1;
            }
        }
        if best_len < 2 {
            best_start = usize::MAX;
        }
        let mut out = String::new();
        let mut g = 0;
        while g < 8 {
            if g == best_start {
                out.push_str("::");
                g += best_len;
                continue;
            }
            if !out.is_empty() && !out.ends_with(':') {
                out.push(':');
            }
            out.push_str(&format!("{:x}", groups[g]));
            g += 1;
        }
        if out.is_empty() {
            out.push_str("::");
        }
        return out;
    }
    // Not reachable with the pipeline's normalized entries.
    "?".to_string()
}

/// Parse an IP like Go's `net.ParseIP`, normalized to 4 bytes for
/// IPv4 (including the IPv4-mapped IPv6 form, matching Go's `To4`).
fn parse_ip_go(host: &str) -> Option<Vec<u8>> {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => Some(v4.octets().to_vec()),
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => Some(v4.octets().to_vec()),
            None => Some(v6.octets().to_vec()),
        },
        Err(_) => None,
    }
}

/// Parse a CIDR like Go's `net.ParseCIDR`, returning the masked
/// network; the address form (dotted vs colon) selects the mask
/// width exactly as Go's parser does.
fn parse_cidr_go(s: &str) -> Option<IpNet> {
    let (addr, mask) = s.split_once('/')?;
    let mut ip: Vec<u8> = if addr.contains(':') {
        addr.parse::<std::net::Ipv6Addr>().ok()?.octets().to_vec()
    } else {
        addr.parse::<std::net::Ipv4Addr>().ok()?.octets().to_vec()
    };
    let bits = (ip.len() * 8) as u32;
    if mask.is_empty() || mask.len() > 3 || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ones: u32 = mask.parse().ok()?;
    if ones > bits {
        return None;
    }
    // Mask the address to the network number.
    for (i, byte) in ip.iter_mut().enumerate() {
        let bit = (i as u32) * 8;
        let mask_byte: u8 = if ones >= bit + 8 {
            0xff
        } else if ones <= bit {
            0
        } else {
            0xffu8 << (8 - (ones - bit))
        };
        *byte &= mask_byte;
    }
    Some(IpNet { ip, ones })
}

/// The configuration options for dcrd (dcrd `config`), plus the
/// cooked options ready for use.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)] // Mirrors dcrd's option set.
pub struct Config {
    // General application behavior.
    /// Display version information and exit.
    pub show_version: bool,
    /// Path to application home directory.
    pub home_dir: String,
    /// Path to configuration file.
    pub config_file: String,
    /// Directory to store data.
    pub data_dir: String,
    /// Directory to log output.
    pub log_dir: String,
    /// Maximum size of log file before it is rotated.
    pub log_size: String,
    /// Disable file logging.
    pub no_file_logging: bool,
    /// Database backend to use for the block chain.
    pub db_type: String,
    /// Enable HTTP profiling on given `[addr:]port`.
    pub profile: String,
    /// Write CPU profile to the specified file.
    pub cpu_profile: String,
    /// Write mem profile to the specified file.
    pub mem_profile: String,
    /// Use the test network.
    pub test_net: bool,
    /// Use the simulation test network.
    pub sim_net: bool,
    /// Use the regression test network.
    pub reg_net: bool,
    /// Logging level for all subsystems.
    pub debug_level: String,
    /// The maximum number of entries in the signature verification
    /// cache.
    pub sig_cache_max_size: u64,
    /// The maximum size in MiB of the utxo cache.
    pub utxo_cache_max_size: u64,

    // RPC server options and policy.
    /// Disable built-in RPC server.
    pub disable_rpc: bool,
    /// Interfaces/ports to listen for RPC connections.
    pub rpc_listeners: Vec<String>,
    /// Username for RPC connections.
    pub rpc_user: String,
    /// Password for RPC connections.
    pub rpc_pass: String,
    /// Method for RPC client authentication.
    pub rpc_auth_type: String,
    /// File containing Certificate Authorities for TLS client
    /// certificates.
    pub rpc_client_cas: String,
    /// Username for limited RPC connections.
    pub rpc_limit_user: String,
    /// Password for limited RPC connections.
    pub rpc_limit_pass: String,
    /// File containing the certificate file.
    pub rpc_cert: String,
    /// File containing the certificate key.
    pub rpc_key: String,
    /// Curve to use when generating TLS keypairs.
    pub tls_curve: String,
    /// Additional DNS names for the RPC server certificate.
    pub alt_dns_names: Vec<String>,
    /// Disable TLS for the RPC server.
    pub disable_tls: bool,
    /// Max number of RPC clients.
    pub rpc_max_clients: i64,
    /// Max number of RPC websocket connections.
    pub rpc_max_websockets: i64,
    /// Max number of concurrent RPC requests.
    pub rpc_max_concurrent_reqs: i64,

    // P2P proxy and Tor settings.
    /// SOCKS5 proxy.
    pub proxy: String,
    /// Username for proxy server.
    pub proxy_user: String,
    /// Password for proxy server.
    pub proxy_pass: String,
    /// SOCKS5 proxy for tor hidden services.
    pub onion_proxy: String,
    /// Username for onion proxy server.
    pub onion_proxy_user: String,
    /// Password for onion proxy server.
    pub onion_proxy_pass: String,
    /// Disable connecting to tor hidden services.
    pub no_onion: bool,
    /// Enable Tor stream isolation.
    pub tor_isolation: bool,

    // P2P network options.
    /// Peers to connect with at startup.
    pub add_peers: Vec<String>,
    /// Connect only to the specified peers at startup.
    pub connect_peers: Vec<String>,
    /// Disable listening for incoming connections.
    pub disable_listen: bool,
    /// Interfaces/ports to listen for connections.
    pub listeners: Vec<String>,
    /// Max number of connections with the same IP.
    pub max_same_ip: i64,
    /// Max number of inbound and outbound peers.
    pub max_peers: i64,
    /// How long to wait for TCP connection completion, in
    /// nanoseconds.
    pub dial_timeout_nanos: i64,
    /// The duration of inactivity before a peer is timed out, in
    /// nanoseconds.
    pub peer_idle_timeout_nanos: i64,

    // P2P network discovery options.
    /// Disable seeding for peer discovery.
    pub disable_seeders: bool,
    /// Deprecated alias for `disable_seeders`.
    pub disable_dns_seed: bool,
    /// Public-facing IPs to advertise.
    pub external_ips: Vec<String>,
    /// Disable automatic network address discovery.
    pub no_discover_ip: bool,
    /// Use UPnP to map the listening port.
    pub upnp: bool,

    // Banning options.
    /// Disable banning of misbehaving peers.
    pub disable_banning: bool,
    /// How long to ban misbehaving peers, in nanoseconds.
    pub ban_duration_nanos: i64,
    /// Maximum allowed ban score.
    pub ban_threshold: u32,
    /// IP networks or IPs that will not be banned, as specified.
    pub whitelists_raw: Vec<String>,

    // Chain related options.
    /// Process forks deep in history.
    pub allow_old_forks: bool,
    /// Write blockchain as a flat file of blocks.
    pub dump_blockchain: String,
    /// Hash of an assumed valid block.
    pub assume_valid: String,

    // Relay and mempool policy.
    /// The minimum transaction fee in DCR/kB.
    pub min_relay_tx_fee: f64,
    /// Deprecated free transaction relay limit.
    pub free_tx_relay_limit: f64,
    /// Deprecated relay priority flag.
    pub no_relay_priority: bool,
    /// Max number of orphan transactions to keep in memory.
    pub max_orphan_txs: i64,
    /// Do not accept transactions from remote peers.
    pub blocks_only: bool,
    /// Accept and relay non-standard transactions.
    pub accept_non_std: bool,
    /// Reject non-standard transactions.
    pub reject_non_std: bool,
    /// Enable the addition of very old votes to the mempool.
    pub allow_old_votes: bool,

    // Mining options and policy.
    /// Generate (mine) coins using the CPU.
    pub generate: bool,
    /// Payment addresses for generated blocks, as specified.
    pub mining_addrs_raw: Vec<String>,
    /// Deprecated minimum block size.
    pub block_min_size: u32,
    /// Maximum block size in bytes when creating a block.
    pub block_max_size: u32,
    /// Deprecated block priority size.
    pub block_priority_size: u32,
    /// Offset the mining timestamp of a block by this many seconds.
    pub mining_time_offset: i64,
    /// Disable mining off of the parent block when there aren't
    /// enough voters.
    pub non_aggressive: bool,
    /// Disable synchronizing the mining state with other nodes.
    pub no_mining_state_sync: bool,
    /// Allow block templates while unsynced.
    pub allow_unsynced_mining: bool,

    // Indexing options.
    /// Maintain the full hash-based transaction index.
    pub tx_index: bool,
    /// Delete the transaction index and exit.
    pub drop_tx_index: bool,
    /// Disable the exists address index.
    pub no_exists_addr_index: bool,
    /// Delete the exists address index and exit.
    pub drop_exists_addr_index: bool,

    // IPC options.
    /// File descriptor of the read end pipe.
    pub pipe_rx: u64,
    /// File descriptor of the write end pipe.
    pub pipe_tx: u64,
    /// Send lifetime notifications over the TX pipe.
    pub lifetime_events: bool,
    /// Send bound address notifications over the TX pipe.
    pub bound_addr_events: bool,

    // Cooked options ready for use.
    /// The decoded mining addresses.
    pub mining_addrs: Vec<Address>,
    /// The minimum relay fee in atoms.
    pub min_relay_tx_fee_atoms: i64,
    /// The parsed whitelist networks.
    pub whitelists: Vec<IpNet>,
    /// The IPv4 network reachability description.
    pub ipv4_net_info: RpcNetworkInfo,
    /// The IPv6 network reachability description.
    pub ipv6_net_info: RpcNetworkInfo,
    /// The onion network reachability description.
    pub onion_net_info: RpcNetworkInfo,
    /// The selected network parameters.
    pub params: NodeParams,
    /// The subsystem log levels the debug level specification set.
    pub log_levels: LogLevels,
    /// The parsed log rotation size in KiB (when file logging is
    /// enabled).
    pub log_size_kib: i64,
    /// The ordinary dial selection.
    pub dial: DialSelection,
    /// The ordinary lookup selection.
    pub lookup: LookupSelection,
    /// The onion dial and lookup selection.
    pub onion: OnionSelection,
    /// Warnings dcrd prints to stderr or the daemon log (deprecated
    /// options, missing config file); informational only.
    pub warnings: Vec<String>,
}

fn empty_net_info(name: &str) -> RpcNetworkInfo {
    RpcNetworkInfo {
        name: name.to_string(),
        limited: false,
        reachable: false,
        proxy: String::new(),
        proxy_randomize_credentials: false,
    }
}

impl Config {
    /// The default configuration (the literal at the top of dcrd's
    /// `loadConfig`).
    pub fn defaults(default_home_dir: &str) -> Config {
        Config {
            show_version: false,
            home_dir: default_home_dir.to_string(),
            config_file: filepath_join(&[default_home_dir, DEFAULT_CONFIG_FILENAME]),
            data_dir: filepath_join(&[default_home_dir, DEFAULT_DATA_DIRNAME]),
            log_dir: filepath_join(&[default_home_dir, DEFAULT_LOG_DIRNAME]),
            log_size: DEFAULT_LOG_SIZE.to_string(),
            no_file_logging: false,
            db_type: DEFAULT_DB_TYPE.to_string(),
            profile: String::new(),
            cpu_profile: String::new(),
            mem_profile: String::new(),
            test_net: false,
            sim_net: false,
            reg_net: false,
            debug_level: DEFAULT_LOG_LEVEL.to_string(),
            sig_cache_max_size: DEFAULT_SIG_CACHE_MAX_SIZE,
            utxo_cache_max_size: DEFAULT_UTXO_CACHE_MAX_SIZE,
            disable_rpc: false,
            rpc_listeners: Vec::new(),
            rpc_user: String::new(),
            rpc_pass: String::new(),
            rpc_auth_type: AUTH_TYPE_BASIC.to_string(),
            rpc_client_cas: filepath_join(&[default_home_dir, "clients.pem"]),
            rpc_limit_user: String::new(),
            rpc_limit_pass: String::new(),
            rpc_cert: filepath_join(&[default_home_dir, "rpc.cert"]),
            rpc_key: filepath_join(&[default_home_dir, "rpc.key"]),
            tls_curve: DEFAULT_TLS_CURVE.to_string(),
            alt_dns_names: Vec::new(),
            disable_tls: false,
            rpc_max_clients: DEFAULT_MAX_RPC_CLIENTS,
            rpc_max_websockets: DEFAULT_MAX_RPC_WEBSOCKETS,
            rpc_max_concurrent_reqs: DEFAULT_MAX_RPC_CONCURRENT_REQS,
            proxy: String::new(),
            proxy_user: String::new(),
            proxy_pass: String::new(),
            onion_proxy: String::new(),
            onion_proxy_user: String::new(),
            onion_proxy_pass: String::new(),
            no_onion: false,
            tor_isolation: false,
            add_peers: Vec::new(),
            connect_peers: Vec::new(),
            disable_listen: false,
            listeners: Vec::new(),
            max_same_ip: DEFAULT_MAX_SAME_IP,
            max_peers: DEFAULT_MAX_PEERS,
            dial_timeout_nanos: DEFAULT_DIAL_TIMEOUT_NANOS,
            peer_idle_timeout_nanos: DEFAULT_PEER_IDLE_TIMEOUT_NANOS,
            disable_seeders: false,
            disable_dns_seed: false,
            external_ips: Vec::new(),
            no_discover_ip: false,
            upnp: false,
            disable_banning: false,
            ban_duration_nanos: DEFAULT_BAN_DURATION_NANOS,
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            whitelists_raw: Vec::new(),
            allow_old_forks: false,
            dump_blockchain: String::new(),
            assume_valid: String::new(),
            min_relay_tx_fee: dcroxide_mempool::DEFAULT_MIN_RELAY_TX_FEE as f64 / 1e8,
            free_tx_relay_limit: 0.0,
            no_relay_priority: false,
            max_orphan_txs: DEFAULT_MAX_ORPHAN_TRANSACTIONS,
            blocks_only: false,
            accept_non_std: false,
            reject_non_std: false,
            allow_old_votes: false,
            generate: false,
            mining_addrs_raw: Vec::new(),
            block_min_size: 0,
            block_max_size: DEFAULT_BLOCK_MAX_SIZE,
            block_priority_size: 0,
            mining_time_offset: 0,
            non_aggressive: false,
            no_mining_state_sync: false,
            allow_unsynced_mining: false,
            tx_index: false,
            drop_tx_index: false,
            no_exists_addr_index: false,
            drop_exists_addr_index: false,
            pipe_rx: 0,
            pipe_tx: 0,
            lifetime_events: false,
            bound_addr_events: false,
            mining_addrs: Vec::new(),
            min_relay_tx_fee_atoms: 0,
            whitelists: Vec::new(),
            ipv4_net_info: empty_net_info("IPV4"),
            ipv6_net_info: empty_net_info("IPV6"),
            onion_net_info: empty_net_info("Onion"),
            params: NodeParams::main_net(),
            log_levels: LogLevels::new(),
            log_size_kib: 0,
            dial: DialSelection::Direct,
            lookup: LookupSelection::System,
            onion: OnionSelection::SameAsMain,
            warnings: Vec::new(),
        }
    }
}

/// Tracks which slice options a parse pass has touched: go-flags
/// clears a slice option the first time each parse pass sets it, so
/// repeated occurrences within a pass accumulate while a later pass
/// (the final command line after the config file) wholly replaces
/// earlier values.
#[derive(Default)]
struct ParsePass(std::collections::BTreeSet<&'static str>);

/// Apply a single already-split option assignment to the config,
/// mirroring go-flags value conversion for the option types dcrd
/// uses.
fn apply_option(
    cfg: &mut Config,
    pass: &mut ParsePass,
    name: &str,
    value: Option<&str>,
) -> Result<(), String> {
    fn as_bool(name: &str, value: Option<&str>) -> Result<bool, String> {
        match value {
            None => Ok(true),
            Some(v) => {
                go_parse_bool(v).map_err(|()| format!("invalid boolean value `{v}' for {name}"))
            }
        }
    }
    fn req<'v>(name: &str, value: Option<&'v str>) -> Result<&'v str, String> {
        value.ok_or_else(|| format!("expected argument for flag `--{name}'"))
    }
    fn num<T: std::str::FromStr>(name: &str, value: Option<&str>) -> Result<T, String> {
        let v = req(name, value)?;
        v.parse::<T>()
            .map_err(|_| format!("invalid argument for flag `--{name}': {v}"))
    }
    fn dur(name: &str, value: Option<&str>) -> Result<i64, String> {
        parse_go_duration(req(name, value)?)
            .map_err(|e| format!("invalid argument for flag `--{name}': {e}"))
    }

    match name {
        "version" => cfg.show_version = as_bool(name, value)?,
        "appdata" => cfg.home_dir = req(name, value)?.to_string(),
        "configfile" => cfg.config_file = req(name, value)?.to_string(),
        "datadir" => cfg.data_dir = req(name, value)?.to_string(),
        "logdir" => cfg.log_dir = req(name, value)?.to_string(),
        "logsize" => cfg.log_size = req(name, value)?.to_string(),
        "nofilelogging" => cfg.no_file_logging = as_bool(name, value)?,
        "dbtype" => cfg.db_type = req(name, value)?.to_string(),
        "profile" => cfg.profile = req(name, value)?.to_string(),
        "cpuprofile" => cfg.cpu_profile = req(name, value)?.to_string(),
        "memprofile" => cfg.mem_profile = req(name, value)?.to_string(),
        "testnet" => cfg.test_net = as_bool(name, value)?,
        "simnet" => cfg.sim_net = as_bool(name, value)?,
        "regnet" => cfg.reg_net = as_bool(name, value)?,
        "debuglevel" => cfg.debug_level = req(name, value)?.to_string(),
        "sigcachemaxsize" => cfg.sig_cache_max_size = num(name, value)?,
        "utxocachemaxsize" => cfg.utxo_cache_max_size = num(name, value)?,
        "norpc" => cfg.disable_rpc = as_bool(name, value)?,
        "rpclisten" => {
            if pass.0.insert("rpclisten") {
                cfg.rpc_listeners.clear();
            }
            cfg.rpc_listeners.push(req(name, value)?.to_string());
        }
        "rpcuser" => cfg.rpc_user = req(name, value)?.to_string(),
        "rpcpass" => cfg.rpc_pass = req(name, value)?.to_string(),
        "authtype" => cfg.rpc_auth_type = req(name, value)?.to_string(),
        "clientcafile" => cfg.rpc_client_cas = req(name, value)?.to_string(),
        "rpclimituser" => cfg.rpc_limit_user = req(name, value)?.to_string(),
        "rpclimitpass" => cfg.rpc_limit_pass = req(name, value)?.to_string(),
        "rpccert" => cfg.rpc_cert = req(name, value)?.to_string(),
        "rpckey" => cfg.rpc_key = req(name, value)?.to_string(),
        "tlscurve" => cfg.tls_curve = req(name, value)?.to_string(),
        "altdnsnames" => {
            if pass.0.insert("altdnsnames") {
                cfg.alt_dns_names.clear();
            }
            cfg.alt_dns_names.push(req(name, value)?.to_string());
        }
        "notls" => cfg.disable_tls = as_bool(name, value)?,
        "rpcmaxclients" => cfg.rpc_max_clients = num(name, value)?,
        "rpcmaxwebsockets" => cfg.rpc_max_websockets = num(name, value)?,
        "rpcmaxconcurrentreqs" => cfg.rpc_max_concurrent_reqs = num(name, value)?,
        "proxy" => cfg.proxy = req(name, value)?.to_string(),
        "proxyuser" => cfg.proxy_user = req(name, value)?.to_string(),
        "proxypass" => cfg.proxy_pass = req(name, value)?.to_string(),
        "onion" => cfg.onion_proxy = req(name, value)?.to_string(),
        "onionuser" => cfg.onion_proxy_user = req(name, value)?.to_string(),
        "onionpass" => cfg.onion_proxy_pass = req(name, value)?.to_string(),
        "noonion" => cfg.no_onion = as_bool(name, value)?,
        "torisolation" => cfg.tor_isolation = as_bool(name, value)?,
        "addpeer" => {
            if pass.0.insert("addpeer") {
                cfg.add_peers.clear();
            }
            cfg.add_peers.push(req(name, value)?.to_string());
        }
        "connect" => {
            if pass.0.insert("connect") {
                cfg.connect_peers.clear();
            }
            cfg.connect_peers.push(req(name, value)?.to_string());
        }
        "nolisten" => cfg.disable_listen = as_bool(name, value)?,
        "listen" => {
            if pass.0.insert("listen") {
                cfg.listeners.clear();
            }
            cfg.listeners.push(req(name, value)?.to_string());
        }
        "maxsameip" => cfg.max_same_ip = num(name, value)?,
        "maxpeers" => cfg.max_peers = num(name, value)?,
        "dialtimeout" => cfg.dial_timeout_nanos = dur(name, value)?,
        "peeridletimeout" => cfg.peer_idle_timeout_nanos = dur(name, value)?,
        "noseeders" => cfg.disable_seeders = as_bool(name, value)?,
        "nodnsseed" => cfg.disable_dns_seed = as_bool(name, value)?,
        "externalip" => {
            if pass.0.insert("externalip") {
                cfg.external_ips.clear();
            }
            cfg.external_ips.push(req(name, value)?.to_string());
        }
        "nodiscoverip" => cfg.no_discover_ip = as_bool(name, value)?,
        "upnp" => cfg.upnp = as_bool(name, value)?,
        "nobanning" => cfg.disable_banning = as_bool(name, value)?,
        "banduration" => cfg.ban_duration_nanos = dur(name, value)?,
        "banthreshold" => cfg.ban_threshold = num(name, value)?,
        "whitelist" => {
            if pass.0.insert("whitelist") {
                cfg.whitelists_raw.clear();
            }
            cfg.whitelists_raw.push(req(name, value)?.to_string());
        }
        "allowoldforks" => cfg.allow_old_forks = as_bool(name, value)?,
        "dumpblockchain" => cfg.dump_blockchain = req(name, value)?.to_string(),
        "assumevalid" => cfg.assume_valid = req(name, value)?.to_string(),
        "minrelaytxfee" => cfg.min_relay_tx_fee = num(name, value)?,
        "limitfreerelay" => cfg.free_tx_relay_limit = num(name, value)?,
        "norelaypriority" => cfg.no_relay_priority = as_bool(name, value)?,
        "maxorphantx" => cfg.max_orphan_txs = num(name, value)?,
        "blocksonly" => cfg.blocks_only = as_bool(name, value)?,
        "acceptnonstd" => cfg.accept_non_std = as_bool(name, value)?,
        "rejectnonstd" => cfg.reject_non_std = as_bool(name, value)?,
        "allowoldvotes" => cfg.allow_old_votes = as_bool(name, value)?,
        "generate" => cfg.generate = as_bool(name, value)?,
        "miningaddr" => {
            if pass.0.insert("miningaddr") {
                cfg.mining_addrs_raw.clear();
            }
            cfg.mining_addrs_raw.push(req(name, value)?.to_string());
        }
        "blockminsize" => cfg.block_min_size = num(name, value)?,
        "blockmaxsize" => cfg.block_max_size = num(name, value)?,
        "blockprioritysize" => cfg.block_priority_size = num(name, value)?,
        "miningtimeoffset" => cfg.mining_time_offset = num(name, value)?,
        "nonaggressive" => cfg.non_aggressive = as_bool(name, value)?,
        "nominingstatesync" => cfg.no_mining_state_sync = as_bool(name, value)?,
        "allowunsyncedmining" => cfg.allow_unsynced_mining = as_bool(name, value)?,
        "txindex" => cfg.tx_index = as_bool(name, value)?,
        "droptxindex" => cfg.drop_tx_index = as_bool(name, value)?,
        "noexistsaddrindex" => cfg.no_exists_addr_index = as_bool(name, value)?,
        "dropexistsaddrindex" => cfg.drop_exists_addr_index = as_bool(name, value)?,
        "piperx" => cfg.pipe_rx = num(name, value)?,
        "pipetx" => cfg.pipe_tx = num(name, value)?,
        "lifetimeevents" => cfg.lifetime_events = as_bool(name, value)?,
        "boundaddrevents" => cfg.bound_addr_events = as_bool(name, value)?,
        other => return Err(format!("unknown flag `{other}'")),
    }
    Ok(())
}

/// Parse config file content into assignments: `key=value` lines
/// with `;`/`#` comments and `[section]` headers ignored.  The full
/// go-flags INI grammar arrives with the front-end piece.
fn parse_config_file(content: &str) -> Vec<Assignment> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with('[')
        {
            continue;
        }
        match line.split_once('=') {
            Some((key, value)) => out.push(Assignment {
                name: key.trim().to_string(),
                value: Some(value.trim().to_string()),
            }),
            None => out.push(Assignment {
                name: line.to_string(),
                value: None,
            }),
        }
    }
    out
}

/// Expand environment variables and a leading `~` in the path,
/// clean the result, and return it (dcrd `cleanAndExpandPath`).
pub fn clean_and_expand_path(
    path: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
    user_home: &dyn Fn(&str) -> Option<String>,
) -> String {
    // Nothing to do when no path is given.
    if path.is_empty() {
        return String::new();
    }

    let path = expand_env(path, getenv);
    if !path.starts_with('~') {
        return filepath_clean(&path);
    }

    // Expand initial ~ to the current user's home directory, or
    // ~otheruser to otheruser's home directory.  When no separator
    // follows, dcrd's index scan leaves the user name empty and the
    // remainder joins onto the current user's home.
    let rest = &path[1..];
    let mut user_name = "";
    let mut p = rest;
    if let Some(i) = rest.find('/') {
        user_name = &rest[..i];
        p = &rest[i..];
    }

    // Fall back to CWD when the lookup fails or the user has no
    // home directory.
    let home_dir = user_home(user_name)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| ".".to_string());

    filepath_join(&[&home_dir, p])
}

/// Remove duplicate entries preserving first occurrence (dcrd
/// `removeDuplicateAddresses`).
pub fn remove_duplicate_addresses(addrs: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !result.contains(a) {
            result.push(a.clone());
        }
    }
    result
}

/// Include every interface address (dcrd `normalizeInterfaceAddrs`).
pub const NORMALIZE_INTERFACE_ADDRS: u32 = 1;
/// Include only the first interface address (dcrd
/// `normalizeInterfaceFirstAddr`).
pub const NORMALIZE_INTERFACE_FIRST_ADDR: u32 = 2;

/// Normalize peer addresses with the default port, expanding
/// interface names per the flags, and remove duplicates (dcrd
/// `normalizeAddresses`).
pub fn normalize_addresses(
    addrs: &[String],
    default_port: &str,
    flags: u32,
    interface_by_name: &dyn Fn(&str) -> Option<IfaceAddrs>,
) -> Vec<String> {
    let mut norm: Vec<String> = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let mut host = addr.clone();
        let mut port = default_port.to_string();
        if let Ok((a, p)) = split_host_port(addr) {
            host = a;
            port = p;
        }
        let iface = if flags != 0 {
            interface_by_name(&host)
        } else {
            None
        };
        let Some(iface) = iface else {
            norm.push(join_host_port(&host, &port));
            continue;
        };
        for a in &iface.addrs {
            let bytes: Vec<u8> = match a {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => v4.octets().to_vec(),
                    None => v6.octets().to_vec(),
                },
            };
            let mut lis = go_ip_string(&bytes);
            if bytes.len() == 16 {
                // IPv6: zone link-local addresses by interface
                // index.
                let unicast_ll = bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80;
                let multicast_ll = bytes[0] == 0xff && bytes[1] & 0x0f == 0x02;
                if unicast_ll || multicast_ll {
                    lis.push('%');
                    lis.push_str(&iface.index.to_string());
                }
            }
            norm.push(join_host_port(&lis, &port));
            if flags & NORMALIZE_INTERFACE_FIRST_ADDR != 0 {
                break;
            }
        }
    }
    remove_duplicate_addresses(&norm)
}

/// Prepend a default host of 127.0.0.1 when the provided address is
/// solely a port number (dcrd `portToLocalHostAddr`).
pub fn port_to_local_host_addr(addr: &str) -> String {
    if go_atoi_ok(addr) {
        return join_host_port("127.0.0.1", addr);
    }
    addr.to_string()
}

/// Ensure the address is `host:port` with the port between 1024 and
/// 65535 (dcrd `validateProfileAddr`).
pub fn validate_profile_addr(addr: &str) -> Result<(), String> {
    // Ensure the address is valid host:port syntax.
    let (_, port_str) = split_host_port(addr)?;

    // Ensure the port is in range; a non-numeric port parses as
    // zero exactly as dcrd's ignored Atoi error leaves it.
    let port: i64 = port_str.parse().unwrap_or(0);
    if !(1024..=65535).contains(&port) {
        return Err(format!(
            "address {}: port must be between 1024 and 65535",
            go_quote(addr)
        ));
    }
    Ok(())
}

/// Parse listener addresses into tcp4/tcp6 entries (dcrd
/// `parseListeners`).
pub fn parse_listeners(addrs: &[String]) -> Result<Vec<(&'static str, String)>, String> {
    let mut net_addrs = Vec::with_capacity(addrs.len() * 2);
    for addr in addrs {
        let (host, _) = split_host_port(addr)?;

        // Empty host is both IPv4 and IPv6.
        if host.is_empty() {
            net_addrs.push(("tcp4", addr.clone()));
            net_addrs.push(("tcp6", addr.clone()));
            continue;
        }

        // Parse the IP, accepting an IPv6 zone like Go's
        // netip.ParseAddr.
        let bare = match host.split_once('%') {
            Some((ip_part, zone)) if !zone.is_empty() => ip_part,
            Some(_) => "",
            None => host.as_str(),
        };
        let parsed: Result<std::net::IpAddr, _> = if host.contains('%') {
            bare.parse::<std::net::Ipv6Addr>()
                .map(std::net::IpAddr::V6)
                .map_err(|_| ())
                .or(Err(()))
        } else {
            bare.parse().map_err(|_| ())
        };
        let Ok(ip) = parsed else {
            return Err(format!("'{host}' is not a valid IP address"));
        };

        // Determine the address type (v4-mapped addresses unmap to
        // IPv4).
        let is6 = match ip {
            std::net::IpAddr::V4(_) => false,
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().is_none(),
        };
        if is6 {
            net_addrs.push(("tcp6", addr.clone()));
        } else {
            net_addrs.push(("tcp4", addr.clone()));
        }
    }
    Ok(net_addrs)
}

/// Update the network interface states from the configuration (dcrd
/// `parseNetworkInterfaces`).
pub fn parse_network_interfaces(cfg: &mut Config) -> Result<(), String> {
    let mut v4_addrs: u32 = 0;
    let mut v6_addrs: u32 = 0;
    let listeners = parse_listeners(&cfg.listeners)?;

    for (net, _) in &listeners {
        if *net == "tcp4" {
            v4_addrs += 1;
            continue;
        }
        if *net == "tcp6" {
            v6_addrs += 1;
        }
    }

    // Set IPV4 interface state.
    if v4_addrs > 0 {
        cfg.ipv4_net_info.reachable = !cfg.disable_listen;
        cfg.ipv4_net_info.limited = v6_addrs == 0;
        cfg.ipv4_net_info.proxy = cfg.proxy.clone();
    }

    // Set IPV6 interface state.
    if v6_addrs > 0 {
        cfg.ipv6_net_info.reachable = !cfg.disable_listen;
        cfg.ipv6_net_info.limited = v4_addrs == 0;
        cfg.ipv6_net_info.proxy = cfg.proxy.clone();
    }

    // Set Onion interface state.
    if v6_addrs > 0 && (!cfg.proxy.is_empty() || !cfg.onion_proxy.is_empty()) {
        cfg.onion_net_info.reachable = !cfg.disable_listen && !cfg.no_onion;
        cfg.onion_net_info.limited = v4_addrs == 0;
        cfg.onion_net_info.proxy = cfg.proxy.clone();
        if !cfg.onion_proxy.is_empty() {
            cfg.onion_net_info.proxy = cfg.onion_proxy.clone();
        }
        cfg.onion_net_info.proxy_randomize_credentials = cfg.tor_isolation;
    }

    Ok(())
}

/// The supported TLS curves (dcrd `tlsCurve` results).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCurve {
    /// NIST P-256.
    P256,
    /// NIST P-521.
    P521,
}

/// The curve for a config option value or an error when unsupported
/// (dcrd `tlsCurve`).
pub fn tls_curve(curve: &str) -> Result<TlsCurve, String> {
    match curve {
        "P-521" => Ok(TlsCurve::P521),
        "P-256" => Ok(TlsCurve::P256),
        _ => Err(format!("unsupported curve {curve}")),
    }
}

/// Whether the database type is supported (dcrd `validDbType`).
fn valid_db_type(db_type: &str) -> bool {
    KNOWN_DB_TYPES.contains(&db_type)
}

/// The OS-specific application data directory (dcrd
/// `dcrutil.AppDataDir`); `goos` selects the platform branch.
pub fn app_data_dir(
    goos: &str,
    app_name: &str,
    roaming: bool,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> String {
    if app_name.is_empty() || app_name == "." {
        return ".".to_string();
    }

    // Strip a leading period gracefully.
    let app_name = app_name.strip_prefix('.').unwrap_or(app_name);
    let mut chars = app_name.chars();
    let first = chars.next().expect("non-empty");
    let rest: String = chars.collect();
    let app_name_upper = format!("{}{rest}", first.to_uppercase());
    let app_name_lower = format!("{}{rest}", first.to_lowercase());

    let home_dir = getenv("HOME").unwrap_or_default();

    match goos {
        "windows" => {
            let mut app_data = getenv("LOCALAPPDATA").unwrap_or_default();
            if roaming || app_data.is_empty() {
                app_data = getenv("APPDATA").unwrap_or_default();
            }
            if !app_data.is_empty() {
                return filepath_join(&[&app_data, &app_name_upper]);
            }
        }
        "darwin" => {
            if !home_dir.is_empty() {
                return filepath_join(&[
                    &home_dir,
                    "Library",
                    "Application Support",
                    &app_name_upper,
                ]);
            }
        }
        "plan9" => {
            if !home_dir.is_empty() {
                return filepath_join(&[&home_dir, &app_name_lower]);
            }
        }
        _ => {
            if !home_dir.is_empty() {
                return filepath_join(&[&home_dir, &format!(".{app_name_lower}")]);
            }
        }
    }

    // Fall back to the current directory.
    ".".to_string()
}

/// Encode with the standard base64 alphabet (Go
/// `base64.StdEncoding.EncodeToString`).
fn base64_std(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Whether a sample-config line matches dcrd's commented credential
/// pattern `^;\s*<key>=[^\s]*$`.
fn matches_commented_key(line: &str, key: &str) -> bool {
    let Some(rest) = line.strip_prefix(';') else {
        return false;
    };
    let rest = rest.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    let Some(value) = rest.strip_prefix(key) else {
        return false;
    };
    let Some(value) = value.strip_prefix('=') else {
        return false;
    };
    !value.contains([' ', '\t', '\n', '\u{b}', '\u{c}', '\r'])
}

/// Copy the sample config to the destination, populating randomly
/// generated RPC credentials under basic authorization (dcrd
/// `createDefaultConfigFile`).
pub fn create_default_config_file(
    dest_path: &str,
    auth_type: &str,
    rand_bytes: &dyn Fn(&mut [u8]),
) -> Result<(), String> {
    // Create the destination directory if it does not exist.
    if let Some(parent) = std::path::Path::new(dest_path).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut cfg = sample_dcrd_conf().to_string();

    // Set a randomized rpcuser and rpcpass under basic auth.
    if auth_type == AUTH_TYPE_BASIC {
        let mut random_bytes = [0u8; 20];
        rand_bytes(&mut random_bytes);
        let rpc_user_line = format!("rpcuser={}", base64_std(&random_bytes));
        rand_bytes(&mut random_bytes);
        let rpc_pass_line = format!("rpcpass={}", base64_std(&random_bytes));

        let lines: Vec<String> = cfg
            .split('\n')
            .map(|line| {
                if matches_commented_key(line, "rpcuser") {
                    rpc_user_line.clone()
                } else if matches_commented_key(line, "rpcpass") {
                    rpc_pass_line.clone()
                } else {
                    line.to_string()
                }
            })
            .collect();
        cfg = lines.join("\n");
    }

    fs::write(dest_path, cfg).map_err(|e| e.to_string())
}

/// Convert a floating point DCR amount to atoms (dcrd
/// `dcrutil.NewAmount`).
fn new_amount(f: f64) -> Result<i64, String> {
    if f.is_nan() || f.is_infinite() {
        return Err("invalid coin amount".to_string());
    }
    let f = f * 1e8;
    Ok(if f < 0.0 {
        (f - 0.5) as i64
    } else {
        (f + 0.5) as i64
    })
}

/// Whether the named file or directory exists (dcrd `fileExists`).
fn file_exists(name: &str) -> bool {
    std::path::Path::new(name).exists()
}

/// Initialize and parse the config from already-split option
/// assignments (dcrd `loadConfig` past the go-flags syntax layer);
/// returns the config and the remaining positional arguments.
pub fn load_config(
    cli: &[Assignment],
    positional: &[String],
    env: &ConfigEnv<'_>,
) -> Result<(Config, Vec<String>), String> {
    let func_name = "loadConfig";
    let default_home = env.default_home_dir.clone();
    let default_data_dir = filepath_join(&[&default_home, DEFAULT_DATA_DIRNAME]);
    let default_log_dir = filepath_join(&[&default_home, DEFAULT_LOG_DIRNAME]);
    let default_rpc_key_file = filepath_join(&[&default_home, "rpc.key"]);
    let default_rpc_cert_file = filepath_join(&[&default_home, "rpc.cert"]);
    let default_rpc_client_cas = filepath_join(&[&default_home, "clients.pem"]);
    // dcrd mutates the package-level defaultConfigFile in the home
    // directory rewrite below.
    let mut default_config_file = filepath_join(&[&default_home, DEFAULT_CONFIG_FILENAME]);

    // Default config.
    let mut cfg = Config::defaults(&default_home);

    // The help pre-parse applies the command line into cfg (with
    // unknown options ignored and errors discarded).
    let mut pass = ParsePass::default();
    for a in cli {
        let _ = apply_option(&mut cfg, &mut pass, &a.name, a.value.as_deref());
    }

    // Pre-parse the command line to check for an alternative config
    // file; preCfg starts as a copy of cfg and takes the command
    // line again.
    let mut pre_cfg = cfg.clone();
    let mut pass = ParsePass::default();
    for a in cli {
        let _ = apply_option(&mut pre_cfg, &mut pass, &a.name, a.value.as_deref());
    }

    // Update the home directory for dcrd if specified.  Since the
    // home directory is updated, other variables need to be updated
    // to reflect the new changes.
    if !pre_cfg.home_dir.is_empty() {
        cfg.home_dir = filepath_abs(&pre_cfg.home_dir);

        if pre_cfg.config_file == default_config_file {
            default_config_file = filepath_join(&[&cfg.home_dir, DEFAULT_CONFIG_FILENAME]);
            pre_cfg.config_file = default_config_file.clone();
            cfg.config_file = default_config_file.clone();
        } else {
            cfg.config_file = pre_cfg.config_file.clone();
        }
        if pre_cfg.data_dir == default_data_dir {
            cfg.data_dir = filepath_join(&[&cfg.home_dir, DEFAULT_DATA_DIRNAME]);
        } else {
            cfg.data_dir = pre_cfg.data_dir.clone();
        }
        if pre_cfg.rpc_key == default_rpc_key_file {
            cfg.rpc_key = filepath_join(&[&cfg.home_dir, "rpc.key"]);
        } else {
            cfg.rpc_key = pre_cfg.rpc_key.clone();
        }
        if pre_cfg.rpc_cert == default_rpc_cert_file {
            cfg.rpc_cert = filepath_join(&[&cfg.home_dir, "rpc.cert"]);
        } else {
            cfg.rpc_cert = pre_cfg.rpc_cert.clone();
        }
        if pre_cfg.rpc_client_cas == default_rpc_client_cas {
            cfg.rpc_client_cas = filepath_join(&[&cfg.home_dir, "clients.pem"]);
        } else {
            cfg.rpc_client_cas = pre_cfg.rpc_client_cas.clone();
        }
        if pre_cfg.log_dir == default_log_dir {
            cfg.log_dir = filepath_join(&[&cfg.home_dir, DEFAULT_LOG_DIRNAME]);
        } else {
            cfg.log_dir = pre_cfg.log_dir.clone();
        }
    }

    // Create a default config file when one does not exist and the
    // user did not specify an override.
    if !(pre_cfg.sim_net || pre_cfg.reg_net)
        && pre_cfg.config_file == default_config_file
        && !file_exists(&pre_cfg.config_file)
    {
        // Errors creating the default config are printed and
        // otherwise ignored.
        let _ = create_default_config_file(
            &pre_cfg.config_file,
            &pre_cfg.rpc_auth_type,
            &env.rand_bytes,
        );
    }

    // Load additional config from file.
    let mut config_file_error: Option<String> = None;
    if !(cfg.sim_net || cfg.reg_net) || pre_cfg.config_file != default_config_file {
        match fs::read_to_string(&pre_cfg.config_file) {
            Ok(content) => {
                let mut pass = ParsePass::default();
                for a in parse_config_file(&content) {
                    let applied = apply_option(&mut cfg, &mut pass, &a.name, a.value.as_deref());
                    if let Err(e) = applied {
                        return Err(format!("Error parsing config file: {e}"));
                    }
                }
            }
            Err(e) => {
                // Path errors are deferred to a warning after the
                // rest of the configuration succeeds.
                config_file_error = Some(format!("open {}: {e}", pre_cfg.config_file));
            }
        }
    }

    // Don't add peers from the config file when in regression test
    // mode.
    if pre_cfg.reg_net && !cfg.add_peers.is_empty() {
        cfg.add_peers.clear();
    }

    // Parse command line options again to ensure they take
    // precedence.
    let mut pass = ParsePass::default();
    for a in cli {
        apply_option(&mut cfg, &mut pass, &a.name, a.value.as_deref())?;
    }
    let remaining_args: Vec<String> = positional.to_vec();

    // Create the home directory if it doesn't already exist.
    if let Err(e) = fs::create_dir_all(&cfg.home_dir) {
        return Err(format!("{func_name}: failed to create home directory: {e}"));
    }

    if cfg.disable_dns_seed {
        cfg.disable_seeders = true;
        cfg.warnings
            .push("The --nodnsseed option is deprecated: use --noseeders".to_string());
    }

    // Multiple networks can't be selected simultaneously.
    let mut num_nets = 0;
    if cfg.test_net {
        num_nets += 1;
        cfg.params = NodeParams::test_net3();
    }
    if cfg.sim_net {
        num_nets += 1;
        // Also disable dns seeding on the simulation test network.
        cfg.params = NodeParams::sim_net();
        cfg.disable_seeders = true;
    }
    if cfg.reg_net {
        num_nets += 1;
        cfg.params = NodeParams::reg_net();
    }
    if num_nets > 1 {
        return Err(format!(
            "{func_name}: the testnet, regnet, and simnet params can't be used together -- choose one of the three"
        ));
    }

    // Warn on the deprecated rate-limiting options.
    if cfg.free_tx_relay_limit != 0.0 {
        cfg.warnings.push(
            "The --limitfreerelay option is deprecated and will be removed in a future version of the software: please remove it from your config".to_string(),
        );
    }
    if cfg.no_relay_priority {
        cfg.warnings.push(
            "The --norelaypriority option is deprecated and will be removed in a future version of the software: please remove it from your config".to_string(),
        );
    }

    // Set the default policy for relaying non-standard transactions
    // according to the default of the active network.
    let mut accept_non_std = cfg.params.params.accept_non_std_txs;
    if cfg.accept_non_std && cfg.reject_non_std {
        return Err(format!(
            "{func_name}: rejectnonstd and acceptnonstd cannot be used together -- choose only one"
        ));
    } else if cfg.reject_non_std {
        accept_non_std = false;
    } else if cfg.accept_non_std {
        accept_non_std = true;
    }
    cfg.accept_non_std = accept_non_std;

    // Append the network type to the data directory so it is
    // "namespaced" per network.
    cfg.data_dir = clean_and_expand_path(&cfg.data_dir, &env.getenv, &env.user_home);
    cfg.data_dir = filepath_join(&[&cfg.data_dir, cfg.params.params.name]);

    if !cfg.no_file_logging {
        // Append the network type to the log directory in the same
        // fashion.
        cfg.log_dir = clean_and_expand_path(&cfg.log_dir, &env.getenv, &env.user_home);
        cfg.log_dir = filepath_join(&[&cfg.log_dir, cfg.params.params.name]);

        let mut units = 0usize;
        for (i, r) in cfg.log_size.chars().enumerate() {
            if !r.is_ascii_digit() {
                units = i;
                break;
            }
        }
        let invalid_size = || format!("{func_name}: Invalid logsize: {} ", cfg.log_size);
        if units == 0 {
            return Err(invalid_size());
        }
        // Parsing a 32-bit number prevents 64-bit overflow after
        // unit multiplication.
        let Ok(logsize_i32) = cfg.log_size[..units].parse::<i32>() else {
            return Err(invalid_size());
        };
        let mut logsize = i64::from(logsize_i32);
        match &cfg.log_size[units..] {
            "k" | "K" | "KiB" => {}
            "m" | "M" | "MiB" => logsize <<= 10,
            "g" | "G" | "GiB" => logsize <<= 20,
            _ => return Err(invalid_size()),
        }
        cfg.log_size_kib = logsize;
    }

    // The special "show" debug level command is handled by the
    // front-end (dcrd prints the subsystems and exits).

    // Parse, validate, and set debug log level(s).
    let mut levels = LogLevels::new();
    if let Err(e) = parse_and_set_debug_levels(&mut levels, &cfg.debug_level) {
        return Err(format!("{func_name}: {e}"));
    }
    cfg.log_levels = levels;

    // Validate database type.
    if !valid_db_type(&cfg.db_type) {
        return Err(format!(
            "{func_name}: the specified database type [{}] is invalid -- supported types [{}]",
            cfg.db_type,
            KNOWN_DB_TYPES.join(" ")
        ));
    }

    // Enforce the minimum and maximum utxo cache max size.
    cfg.utxo_cache_max_size = cfg
        .utxo_cache_max_size
        .clamp(MIN_UTXO_CACHE_MAX_SIZE, MAX_UTXO_CACHE_MAX_SIZE);

    // Validate format of profile address.
    if !cfg.profile.is_empty() {
        cfg.profile = port_to_local_host_addr(&cfg.profile);
        if let Err(e) = validate_profile_addr(&cfg.profile) {
            return Err(format!("{func_name}: profile: {e}"));
        }
    }

    // Don't allow ban durations that are too short.
    if cfg.ban_duration_nanos < 1_000_000_000 {
        return Err(format!(
            "{func_name}: the banduration option may not be less than 1s -- parsed [{}]",
            go_duration_string(cfg.ban_duration_nanos)
        ));
    }

    // Don't allow dialtimeout durations that are too short.
    if cfg.dial_timeout_nanos < 1_000_000_000 {
        return Err(format!(
            "{func_name}: the dialtimeout option may not be less than 1s -- parsed [{}]",
            go_duration_string(cfg.dial_timeout_nanos)
        ));
    }

    // Don't allow peeridletimeout durations that are too short.
    if cfg.peer_idle_timeout_nanos < 15 * 1_000_000_000 {
        return Err(format!(
            "{func_name}: the peeridletimeout option may not be less than 15s -- parsed [{}]",
            go_duration_string(cfg.peer_idle_timeout_nanos)
        ));
    }

    // Validate any given whitelisted IP addresses and networks.
    if !cfg.whitelists_raw.is_empty() {
        cfg.whitelists = Vec::with_capacity(cfg.whitelists_raw.len());
        let whitelists_raw = cfg.whitelists_raw.clone();
        for addr in &whitelists_raw {
            let ipnet = match parse_cidr_go(addr) {
                Some(ipnet) => ipnet,
                None => {
                    let Some(ip) = parse_ip_go(addr) else {
                        return Err(format!(
                            "{func_name}: the whitelist value of '{addr}' is invalid"
                        ));
                    };
                    let ones = (ip.len() * 8) as u32;
                    IpNet { ip, ones }
                }
            };
            cfg.whitelists.push(ipnet);
        }
    }

    // --addPeer and --connect do not mix.
    if !cfg.add_peers.is_empty() && !cfg.connect_peers.is_empty() {
        return Err(format!(
            "{func_name}: the --addpeer and --connect options can not be mixed"
        ));
    }

    // --proxy or --connect without --listen disables listening.
    if (!cfg.proxy.is_empty() || !cfg.connect_peers.is_empty()) && cfg.listeners.is_empty() {
        cfg.disable_listen = true;
    }

    // Connect means no seeding.
    if !cfg.connect_peers.is_empty() {
        cfg.disable_seeders = true;
    }

    // Add the default listener if none were specified.
    if cfg.listeners.is_empty() {
        cfg.listeners = vec![join_host_port("", cfg.params.params.default_port)];
    }

    // Check to make sure limited and admin users don't have the
    // same username.
    if cfg.rpc_user == cfg.rpc_limit_user && !cfg.rpc_user.is_empty() {
        return Err(format!(
            "{func_name}: --rpcuser and --rpclimituser must not specify the same username"
        ));
    }

    // Check to make sure limited and admin users don't have the
    // same password.
    if cfg.rpc_pass == cfg.rpc_limit_pass && !cfg.rpc_pass.is_empty() {
        return Err(format!(
            "{func_name}: --rpcpass and --rpclimitpass must not specify the same password"
        ));
    }

    // The RPC server is disabled if no username or password is
    // provided under basic user/pass authentication.
    if cfg.rpc_auth_type == AUTH_TYPE_BASIC
        && (cfg.rpc_user.is_empty() || cfg.rpc_pass.is_empty())
        && (cfg.rpc_limit_user.is_empty() || cfg.rpc_limit_pass.is_empty())
    {
        cfg.disable_rpc = true;
    }

    // RPC usernames and passwords are not allowed with client cert
    // authentication.
    if cfg.rpc_auth_type == AUTH_TYPE_CLIENT_CERT
        && (!cfg.rpc_user.is_empty()
            || !cfg.rpc_pass.is_empty()
            || !cfg.rpc_limit_user.is_empty()
            || !cfg.rpc_limit_pass.is_empty())
    {
        return Err(format!(
            "{func_name}: RPC usernames and passwords are not allowed with --authtype=clientcert"
        ));
    }

    // Default RPC to listen on localhost only.
    if !cfg.disable_rpc && cfg.rpc_listeners.is_empty() {
        let addrs = (env.lookup_localhost)()?;
        cfg.rpc_listeners = addrs
            .iter()
            .map(|addr| join_host_port(addr, cfg.params.rpc_port))
            .collect();
    }

    if cfg.rpc_max_concurrent_reqs < 0 {
        return Err(format!(
            "{func_name}: the rpcmaxwebsocketconcurrentrequests option may not be less than 0 -- parsed [{}]",
            cfg.rpc_max_concurrent_reqs
        ));
    }

    // Validate the minrelaytxfee.
    match new_amount(cfg.min_relay_tx_fee) {
        Ok(atoms) => cfg.min_relay_tx_fee_atoms = atoms,
        Err(e) => {
            return Err(format!("{func_name}: invalid minrelaytxfee: {e}"));
        }
    }

    // Warn on the deprecated block sizing options.
    if cfg.block_min_size != 0 {
        cfg.warnings.push(
            "The --blockminsize option is deprecated and will be removed in a future version of the software: please remove it from your config".to_string(),
        );
    }
    if cfg.block_priority_size != 0 {
        cfg.warnings.push(
            "The --blockprioritysize option is deprecated and will be removed in a future version of the software: please remove it from your config".to_string(),
        );
    }

    // Ensure the specified max block size is not larger than the
    // network will allow; 1000 bytes is subtracted from the max to
    // account for overhead.
    let block_max_size_max = cfg.params.params.maximum_block_sizes[0] as u32 - 1000;
    if cfg.block_max_size < BLOCK_MAX_SIZE_MIN || cfg.block_max_size > block_max_size_max {
        return Err(format!(
            "{func_name}: the blockmaxsize option must be in between {BLOCK_MAX_SIZE_MIN} and {block_max_size_max} -- parsed [{}]",
            cfg.block_max_size
        ));
    }

    // Limit the max orphan count to a sane value.
    if cfg.max_orphan_txs < 0 {
        return Err(format!(
            "{func_name}: the maxorphantx option may not be less than 0 -- parsed [{}]",
            cfg.max_orphan_txs
        ));
    }

    // --txindex and --droptxindex do not mix.
    if cfg.tx_index && cfg.drop_tx_index {
        return Err(format!(
            "{func_name}: the --txindex and --droptxindex options may  not be activated at the same time"
        ));
    }

    // !--noexistsaddrindex and --dropexistsaddrindex do not mix.
    if !cfg.no_exists_addr_index && cfg.drop_exists_addr_index {
        return Err(
            "dropexistsaddrindex cannot be activated when existsaddressindex is on (try setting --noexistsaddrindex)".to_string(),
        );
    }

    // Check mining addresses are valid and save parsed versions.
    cfg.mining_addrs = Vec::with_capacity(cfg.mining_addrs_raw.len());
    let mining_addrs_raw = cfg.mining_addrs_raw.clone();
    for str_addr in &mining_addrs_raw {
        match stdaddr::decode_address(str_addr, &cfg.params.params) {
            Ok(addr) => cfg.mining_addrs.push(addr),
            Err(e) => {
                return Err(format!(
                    "{func_name}: mining address '{str_addr}' failed to decode: {e}"
                ));
            }
        }
    }

    // Ensure there is at least one mining address when the generate
    // flag is set.
    if cfg.generate && cfg.mining_addrs.is_empty() {
        return Err(format!(
            "{func_name}: the generate flag is set, but there are no mining addresses specified "
        ));
    }

    // Don't allow unsynchronized mining on mainnet.
    if cfg.allow_unsynced_mining && cfg.params.net == crate::params::ActiveNet::MainNet {
        return Err(format!(
            "{func_name}: allowunsyncedmining cannot be activated on mainnet"
        ));
    }

    // Always allow unsynchronized mining on simnet and regnet.
    if cfg.sim_net || cfg.reg_net {
        cfg.allow_unsynced_mining = true;
    }

    // Add default port to all listener addresses if needed and
    // remove duplicate addresses.
    cfg.listeners = normalize_addresses(
        &cfg.listeners,
        cfg.params.params.default_port,
        NORMALIZE_INTERFACE_ADDRS,
        &env.interface_by_name,
    );

    // Add default port to all rpc listener addresses if needed and
    // remove duplicate addresses.
    cfg.rpc_listeners = normalize_addresses(
        &cfg.rpc_listeners,
        cfg.params.rpc_port,
        NORMALIZE_INTERFACE_ADDRS,
        &env.interface_by_name,
    );

    // The authtype config must be one of "basic" or "clientcert".
    if cfg.rpc_auth_type != AUTH_TYPE_BASIC && cfg.rpc_auth_type != AUTH_TYPE_CLIENT_CERT {
        return Err(format!(
            "{func_name}: invalid authtype option {}",
            go_quote(&cfg.rpc_auth_type)
        ));
    }

    // Only allow TLS to be disabled if the RPC is bound to localhost
    // addresses, and when client cert auth is not used.
    if !cfg.disable_rpc && cfg.disable_tls {
        for addr in &cfg.rpc_listeners {
            let host = match split_host_port(addr) {
                Ok((host, _)) => host,
                Err(e) => {
                    return Err(format!(
                        "{func_name}: RPC listen interface '{addr}' is invalid: {e}"
                    ));
                }
            };
            if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                return Err(format!(
                    "{func_name}: the --notls option may not be used when binding RPC to non localhost addresses: {addr}"
                ));
            }
        }

        if cfg.rpc_auth_type == AUTH_TYPE_CLIENT_CERT {
            return Err(format!(
                "{func_name}: TLS may not be disabled with authtype=clientcert"
            ));
        }
    }

    // Add default port to all added peer addresses if needed and
    // remove duplicate addresses.
    cfg.add_peers = normalize_addresses(
        &cfg.add_peers,
        cfg.params.params.default_port,
        NORMALIZE_INTERFACE_FIRST_ADDR,
        &env.interface_by_name,
    );
    cfg.connect_peers = normalize_addresses(
        &cfg.connect_peers,
        cfg.params.params.default_port,
        NORMALIZE_INTERFACE_FIRST_ADDR,
        &env.interface_by_name,
    );

    // Tor stream isolation requires either proxy or onion proxy to
    // be set.
    if cfg.tor_isolation && cfg.proxy.is_empty() && cfg.onion_proxy.is_empty() {
        return Err(format!(
            "{func_name}: Tor stream isolation requires either proxy or onionproxy to be set"
        ));
    }

    // Setup dial and DNS resolution (lookup) selections depending
    // on the specified options.
    cfg.dial = DialSelection::Direct;
    cfg.lookup = LookupSelection::System;
    if !cfg.proxy.is_empty() {
        let (host, port) = match split_host_port(&cfg.proxy) {
            Ok(parts) => parts,
            Err(e) => {
                return Err(format!(
                    "{func_name}: proxy address '{}' is invalid: {e}",
                    cfg.proxy
                ));
            }
        };
        cfg.proxy = normalize_addresses(
            &[host],
            &port,
            NORMALIZE_INTERFACE_FIRST_ADDR,
            &env.interface_by_name,
        )[0]
        .clone();

        if cfg.tor_isolation && (!cfg.proxy_user.is_empty() || !cfg.proxy_pass.is_empty()) {
            cfg.warnings.push(
                "Tor isolation set -- overriding specified proxy user credentials".to_string(),
            );
        }

        cfg.dial = DialSelection::SocksProxy;
        if !cfg.no_onion {
            cfg.lookup = LookupSelection::TorViaProxy;
        }
    }

    // Setup onion address dial and DNS resolution (lookup)
    // selections.
    if !cfg.onion_proxy.is_empty() {
        let (host, port) = match split_host_port(&cfg.onion_proxy) {
            Ok(parts) => parts,
            Err(e) => {
                return Err(format!(
                    "{func_name}: Onion proxy address '{}' is invalid: {e}",
                    cfg.onion_proxy
                ));
            }
        };
        cfg.onion_proxy = normalize_addresses(
            &[host],
            &port,
            NORMALIZE_INTERFACE_FIRST_ADDR,
            &env.interface_by_name,
        )[0]
        .clone();

        if cfg.tor_isolation
            && (!cfg.onion_proxy_user.is_empty() || !cfg.onion_proxy_pass.is_empty())
        {
            cfg.warnings.push(
                "Tor isolation set -- overriding specified onionproxy user credentials "
                    .to_string(),
            );
        }

        cfg.onion = OnionSelection::OnionProxy;
    } else {
        cfg.onion = OnionSelection::SameAsMain;
    }

    // Specifying --noonion means the onion address dial and DNS
    // resolution (lookup) functions result in an error.
    if cfg.no_onion {
        cfg.onion = OnionSelection::Disabled;
    }

    // The old-testnet-directory warning is a log-only concern
    // handled by the daemon.

    // Parse information regarding the state of the supported
    // network interfaces.
    parse_network_interfaces(&mut cfg)?;

    // Prevent using an unsupported curve.
    tls_curve(&cfg.tls_curve)?;

    // Warn about a missing config file only after all other
    // configuration is done.
    if let Some(err) = config_file_error {
        cfg.warnings.push(err);
    }

    Ok((cfg, remaining_args))
}
