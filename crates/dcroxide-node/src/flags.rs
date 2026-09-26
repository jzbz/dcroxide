// SPDX-License-Identifier: ISC
//! The go-flags v1.6.1 front-end for the dcrd option set: the
//! command line scanner (long and short options, concatenated and
//! separate arguments, double-dash handling, and the exact parse
//! error texts), the INI config file grammar, and the environment
//! variable defaults — everything `loadConfig` observes from the
//! library, reproduced over the option registry.

// The scanner mirrors go-flags' bounded index arithmetic.
#![allow(clippy::arithmetic_side_effects)]

use crate::config::{Config, ParsePass};
use crate::gostd::go_unquote;

/// The value kind of an option, driving conversion and the
/// "(expected TYPE)" fragment of go-flags' marshal errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptKind {
    /// A boolean flag.
    Bool,
    /// A string value.
    Str,
    /// A repeatable string value.
    StrSlice,
    /// A Go `int`.
    Int,
    /// A Go `uint`.
    Uint,
    /// A Go `uint32`.
    Uint32,
    /// A Go `float64`.
    Float64,
    /// A Go `time.Duration`.
    Duration,
}

impl OptKind {
    /// The reflected type name go-flags embeds in marshal errors.
    fn expected(self) -> &'static str {
        match self {
            OptKind::Bool => "bool",
            OptKind::Str => "string",
            OptKind::StrSlice => "[]string",
            OptKind::Int => "int",
            OptKind::Uint => "uint",
            OptKind::Uint32 => "uint32",
            OptKind::Float64 => "float64",
            OptKind::Duration => "time.Duration",
        }
    }

    /// Whether values of this kind may begin with a dash followed by
    /// a digit when consumed as a separate argument (go-flags
    /// `isSignedNumber`: signed integers, floats, and `time.Duration`
    /// via its int64 kind).
    fn signed_number(self) -> bool {
        matches!(self, OptKind::Int | OptKind::Float64 | OptKind::Duration)
    }
}

/// One option of the dcrd config surface: the long name, the short
/// name, the Go struct field name (matched by the INI parser), and
/// the value kind.
pub struct OptSpec {
    /// The long option name.
    pub long: &'static str,
    /// The short option name.
    pub short: Option<char>,
    /// The Go struct field name.
    pub field: &'static str,
    /// The value kind.
    pub kind: OptKind,
}

/// The dcrd option registry in struct order.
pub const OPTIONS: [OptSpec; 86] = [
    OptSpec {
        long: "version",
        short: Some('V'),
        field: "ShowVersion",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "appdata",
        short: Some('A'),
        field: "HomeDir",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "configfile",
        short: Some('C'),
        field: "ConfigFile",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "datadir",
        short: Some('b'),
        field: "DataDir",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "logdir",
        short: None,
        field: "LogDir",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "logsize",
        short: None,
        field: "LogSize",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "nofilelogging",
        short: None,
        field: "NoFileLogging",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "dbtype",
        short: None,
        field: "DbType",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "profile",
        short: None,
        field: "Profile",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "cpuprofile",
        short: None,
        field: "CPUProfile",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "memprofile",
        short: None,
        field: "MemProfile",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "testnet",
        short: None,
        field: "TestNet",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "simnet",
        short: None,
        field: "SimNet",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "regnet",
        short: None,
        field: "RegNet",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "debuglevel",
        short: Some('d'),
        field: "DebugLevel",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "sigcachemaxsize",
        short: None,
        field: "SigCacheMaxSize",
        kind: OptKind::Uint,
    },
    OptSpec {
        long: "utxocachemaxsize",
        short: None,
        field: "UtxoCacheMaxSize",
        kind: OptKind::Uint,
    },
    OptSpec {
        long: "norpc",
        short: None,
        field: "DisableRPC",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "rpclisten",
        short: None,
        field: "RPCListeners",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "rpcuser",
        short: Some('u'),
        field: "RPCUser",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "rpcpass",
        short: Some('P'),
        field: "RPCPass",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "authtype",
        short: None,
        field: "RPCAuthType",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "clientcafile",
        short: None,
        field: "RPCClientCAs",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "rpclimituser",
        short: None,
        field: "RPCLimitUser",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "rpclimitpass",
        short: None,
        field: "RPCLimitPass",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "rpccert",
        short: None,
        field: "RPCCert",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "rpckey",
        short: None,
        field: "RPCKey",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "tlscurve",
        short: None,
        field: "TLSCurve",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "altdnsnames",
        short: None,
        field: "AltDNSNames",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "notls",
        short: None,
        field: "DisableTLS",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "rpcmaxclients",
        short: None,
        field: "RPCMaxClients",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "rpcmaxwebsockets",
        short: None,
        field: "RPCMaxWebsockets",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "rpcmaxconcurrentreqs",
        short: None,
        field: "RPCMaxConcurrentReqs",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "proxy",
        short: None,
        field: "Proxy",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "proxyuser",
        short: None,
        field: "ProxyUser",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "proxypass",
        short: None,
        field: "ProxyPass",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "onion",
        short: None,
        field: "OnionProxy",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "onionuser",
        short: None,
        field: "OnionProxyUser",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "onionpass",
        short: None,
        field: "OnionProxyPass",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "noonion",
        short: None,
        field: "NoOnion",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "torisolation",
        short: None,
        field: "TorIsolation",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "addpeer",
        short: Some('a'),
        field: "AddPeers",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "connect",
        short: None,
        field: "ConnectPeers",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "nolisten",
        short: None,
        field: "DisableListen",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "listen",
        short: None,
        field: "Listeners",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "maxsameip",
        short: None,
        field: "MaxSameIP",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "maxpeers",
        short: None,
        field: "MaxPeers",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "dialtimeout",
        short: None,
        field: "DialTimeout",
        kind: OptKind::Duration,
    },
    OptSpec {
        long: "peeridletimeout",
        short: None,
        field: "PeerIdleTimeout",
        kind: OptKind::Duration,
    },
    OptSpec {
        long: "noseeders",
        short: None,
        field: "DisableSeeders",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "nodnsseed",
        short: None,
        field: "DisableDNSSeed",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "externalip",
        short: None,
        field: "ExternalIPs",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "nodiscoverip",
        short: None,
        field: "NoDiscoverIP",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "upnp",
        short: None,
        field: "Upnp",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "nobanning",
        short: None,
        field: "DisableBanning",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "banduration",
        short: None,
        field: "BanDuration",
        kind: OptKind::Duration,
    },
    OptSpec {
        long: "banthreshold",
        short: None,
        field: "BanThreshold",
        kind: OptKind::Uint32,
    },
    OptSpec {
        long: "whitelist",
        short: None,
        field: "Whitelists",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "allowoldforks",
        short: None,
        field: "AllowOldForks",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "dumpblockchain",
        short: None,
        field: "DumpBlockchain",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "assumevalid",
        short: None,
        field: "AssumeValid",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "minrelaytxfee",
        short: None,
        field: "MinRelayTxFee",
        kind: OptKind::Float64,
    },
    OptSpec {
        long: "limitfreerelay",
        short: None,
        field: "FreeTxRelayLimit",
        kind: OptKind::Float64,
    },
    OptSpec {
        long: "norelaypriority",
        short: None,
        field: "NoRelayPriority",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "maxorphantx",
        short: None,
        field: "MaxOrphanTxs",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "blocksonly",
        short: None,
        field: "BlocksOnly",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "acceptnonstd",
        short: None,
        field: "AcceptNonStd",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "rejectnonstd",
        short: None,
        field: "RejectNonStd",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "allowoldvotes",
        short: None,
        field: "AllowOldVotes",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "generate",
        short: None,
        field: "Generate",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "miningaddr",
        short: None,
        field: "MiningAddrs",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "blockminsize",
        short: None,
        field: "BlockMinSize",
        kind: OptKind::Uint32,
    },
    OptSpec {
        long: "blockmaxsize",
        short: None,
        field: "BlockMaxSize",
        kind: OptKind::Uint32,
    },
    OptSpec {
        long: "blockprioritysize",
        short: None,
        field: "BlockPrioritySize",
        kind: OptKind::Uint32,
    },
    OptSpec {
        long: "miningtimeoffset",
        short: None,
        field: "MiningTimeOffset",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "nonaggressive",
        short: None,
        field: "NonAggressive",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "nominingstatesync",
        short: None,
        field: "NoMiningStateSync",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "allowunsyncedmining",
        short: None,
        field: "AllowUnsyncedMining",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "txindex",
        short: None,
        field: "TxIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "droptxindex",
        short: None,
        field: "DropTxIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "noexistsaddrindex",
        short: None,
        field: "NoExistsAddrIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "dropexistsaddrindex",
        short: None,
        field: "DropExistsAddrIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "piperx",
        short: None,
        field: "PipeRx",
        kind: OptKind::Uint,
    },
    OptSpec {
        long: "pipetx",
        short: None,
        field: "PipeTx",
        kind: OptKind::Uint,
    },
    OptSpec {
        long: "lifetimeevents",
        short: None,
        field: "LifetimeEvents",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "boundaddrevents",
        short: None,
        field: "BoundAddrEvents",
        kind: OptKind::Bool,
    },
];

/// The environment default keys (go-flags `env` tags): the option
/// long name, the variable, and the delimiter for slice values.
///
/// dcrd names these `DCRD_APPDATA` and `DCRD_ALT_DNSNAMES`; the port
/// answers to its own names for the same reason it uses its own data
/// directory and config file (`809c4c2`).  `DCRD_APPDATA` exported for a
/// dcrd running alongside would otherwise redirect this node's entire
/// data directory at dcrd's, silently, and a shared datadir is the one
/// thing the exclusive database lock exists to prevent.  Deliberately no
/// fallback to the `DCRD_*` names: honouring them would reintroduce
/// exactly that collision.
///
/// The `[$VAR]` annotation `render_help` prints comes from
/// [`HELP_DESCRIPTIONS`], which carries the same names, so the rendered
/// help advertises what is actually read.  That makes the rendering
/// diverge from dcrd's by more than the name — `DCROXIDE_APPDATA` is four
/// characters longer, which pushes the annotation onto its own line under
/// go-flags' wrapping.  The parity vector is a byte-exact dump of dcrd's
/// own help, so it is compared against a rendering fed dcrd's names; see
/// `help_text_matches_the_go_flags_vector`.  That keeps the layout
/// algorithm under test, which is what the vector is for, while
/// `the_env_annotations_name_the_variables_actually_read` pins the
/// production rendering separately.
pub const ENV_DEFAULTS: [(&str, &str, Option<&str>); 2] = [
    ("appdata", "DCROXIDE_APPDATA", None),
    ("altdnsnames", "DCROXIDE_ALT_DNSNAMES", Some(",")),
];

/// The help description and environment-variable annotation for each
/// dcrd option, in registry order (the `description:`/`env:` struct
/// tags go-flags renders; extracted verbatim from dcrd v1.10.7
/// config.go by tools/helpgen).
pub const HELP_DESCRIPTIONS: [(&str, &str, Option<&str>); 86] = [
    ("version", "Display version information and exit", None),
    (
        "appdata",
        "Path to application home directory",
        Some("DCROXIDE_APPDATA"),
    ),
    ("configfile", "Path to configuration file", None),
    ("datadir", "Directory to store data", None),
    ("logdir", "Directory to log output", None),
    (
        "logsize",
        "Maximum size of log file before it is rotated",
        None,
    ),
    ("nofilelogging", "Disable file logging", None),
    (
        "dbtype",
        "Database backend to use for the block chain",
        None,
    ),
    (
        "profile",
        "Enable HTTP profiling on given [addr:]port -- NOTE port must be between 1024 and 65536",
        None,
    ),
    (
        "cpuprofile",
        "Write CPU profile to the specified file",
        None,
    ),
    (
        "memprofile",
        "Write mem profile to the specified file",
        None,
    ),
    ("testnet", "Use the test network", None),
    ("simnet", "Use the simulation test network", None),
    ("regnet", "Use the regression test network", None),
    (
        "debuglevel",
        "Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems",
        None,
    ),
    (
        "sigcachemaxsize",
        "The maximum number of entries in the signature verification cache",
        None,
    ),
    (
        "utxocachemaxsize",
        "The maximum size in MiB of the utxo cache; (min: 25, max: 32768)",
        None,
    ),
    (
        "norpc",
        "Disable built-in RPC server -- NOTE: The RPC server is disabled by default if no rpcuser/rpcpass or rpclimituser/rpclimitpass is specified",
        None,
    ),
    (
        "rpclisten",
        "Add an interface/port to listen for RPC connections (default port: 9109, testnet: 19109)",
        None,
    ),
    ("rpcuser", "Username for RPC connections", None),
    ("rpcpass", "Password for RPC connections", None),
    (
        "authtype",
        "Method for RPC client authentication (basic or clientcert)",
        None,
    ),
    (
        "clientcafile",
        "File containing Certificate Authorities to verify TLS client certificates; requires authtype=clientcert",
        None,
    ),
    ("rpclimituser", "Username for limited RPC connections", None),
    ("rpclimitpass", "Password for limited RPC connections", None),
    ("rpccert", "File containing the certificate file", None),
    ("rpckey", "File containing the certificate key", None),
    (
        "tlscurve",
        "Curve to use when generating TLS keypairs",
        None,
    ),
    (
        "altdnsnames",
        "Specify additional DNS names to use when generating the RPC server certificate",
        Some("DCROXIDE_ALT_DNSNAMES"),
    ),
    (
        "notls",
        "Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost",
        None,
    ),
    (
        "rpcmaxclients",
        "Max number of RPC clients for standard connections",
        None,
    ),
    (
        "rpcmaxwebsockets",
        "Max number of RPC websocket connections",
        None,
    ),
    (
        "rpcmaxconcurrentreqs",
        "Max number of concurrent RPC requests that may be processed concurrently",
        None,
    ),
    (
        "proxy",
        "Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)",
        None,
    ),
    ("proxyuser", "Username for proxy server", None),
    ("proxypass", "Password for proxy server", None),
    (
        "onion",
        "Connect to tor hidden services via SOCKS5 proxy (eg. 127.0.0.1:9050)",
        None,
    ),
    ("onionuser", "Username for onion proxy server", None),
    ("onionpass", "Password for onion proxy server", None),
    ("noonion", "Disable connecting to tor hidden services", None),
    (
        "torisolation",
        "Enable Tor stream isolation by randomizing user credentials for each connection",
        None,
    ),
    ("addpeer", "Add a peer to connect with at startup", None),
    (
        "connect",
        "Connect only to the specified peers at startup",
        None,
    ),
    (
        "nolisten",
        "Disable listening for incoming connections -- NOTE: Listening is automatically disabled if the --connect or --proxy options are used without also specifying listen interfaces via --listen",
        None,
    ),
    (
        "listen",
        "Add an interface/port to listen for connections (default all interfaces port: 9108, testnet: 19108)",
        None,
    ),
    (
        "maxsameip",
        "Max number of connections with the same IP -- 0 to disable",
        None,
    ),
    ("maxpeers", "Max number of inbound and outbound peers", None),
    (
        "dialtimeout",
        "How long to wait for TCP connection completion.  Valid time units are {s, m, h}.  Minimum 1 second",
        None,
    ),
    (
        "peeridletimeout",
        "The duration of inactivity before a peer is timed out.  Valid time units are {s,m,h}.  Minimum 15 seconds",
        None,
    ),
    ("noseeders", "Disable seeding for peer discovery", None),
    ("nodnsseed", "DEPRECATED: use --noseeders", None),
    (
        "externalip",
        "Add a public-facing IP to the list of local external IPs that dcrd will advertise to other peers",
        None,
    ),
    (
        "nodiscoverip",
        "Disable automatic network address discovery of local external IPs",
        None,
    ),
    (
        "upnp",
        "REMOVED: This feature is no longer available and this flag will be removed in a future version",
        None,
    ),
    ("nobanning", "Disable banning of misbehaving peers", None),
    (
        "banduration",
        "How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second",
        None,
    ),
    (
        "banthreshold",
        "Maximum allowed ban score before disconnecting and banning misbehaving peers",
        None,
    ),
    (
        "whitelist",
        "Add an IP network or IP that will not be banned (eg. 192.168.1.0/24 or ::1)",
        None,
    ),
    (
        "allowoldforks",
        "Process forks deep in history.  Don't do this unless you know what you're doing",
        None,
    ),
    (
        "dumpblockchain",
        "Write blockchain as a flat file of blocks for use with addblock, to the specified filename",
        None,
    ),
    (
        "assumevalid",
        "Hash of an assumed valid block.  Defaults to the hard-coded assumed valid block that is updated periodically with new releases.  Don't use a different hash unless you understand the implications.  Set to 0 to disable",
        None,
    ),
    (
        "minrelaytxfee",
        "The minimum transaction fee in DCR/kB to be considered a non-zero fee",
        None,
    ),
    (
        "limitfreerelay",
        "DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software",
        None,
    ),
    (
        "norelaypriority",
        "DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software",
        None,
    ),
    (
        "maxorphantx",
        "Max number of orphan transactions to keep in memory",
        None,
    ),
    (
        "blocksonly",
        "Do not accept transactions from remote peers",
        None,
    ),
    (
        "acceptnonstd",
        "Accept and relay non-standard transactions to the network regardless of the default settings for the active network",
        None,
    ),
    (
        "rejectnonstd",
        "Reject non-standard transactions regardless of the default settings for the active network",
        None,
    ),
    (
        "allowoldvotes",
        "Enable the addition of very old votes to the mempool",
        None,
    ),
    ("generate", "Generate (mine) coins using the CPU", None),
    (
        "miningaddr",
        "Add the specified payment address to the list of addresses to use for generated blocks.  At least one address is required if the generate option is set",
        None,
    ),
    (
        "blockminsize",
        "DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software",
        None,
    ),
    (
        "blockmaxsize",
        "Maximum block size in bytes to be used when creating a block",
        None,
    ),
    (
        "blockprioritysize",
        "DEPRECATED: This behavior is no longer available and this option will be removed in a future version of the software",
        None,
    ),
    (
        "miningtimeoffset",
        "Offset the mining timestamp of a block by this many seconds (positive values are in the past)",
        None,
    ),
    (
        "nonaggressive",
        "Disable mining off of the parent block of the blockchain if there aren't enough voters",
        None,
    ),
    (
        "nominingstatesync",
        "Disable synchronizing the mining state with other nodes",
        None,
    ),
    (
        "allowunsyncedmining",
        "Allow block templates to be generated even when the chain is not considered synced on networks other than the main network.  This is automatically enabled when the simnet option is set.  Don't do this unless you know what you're doing",
        None,
    ),
    (
        "txindex",
        "Maintain a full hash-based transaction index which makes all transactions available via the getrawtransaction RPC",
        None,
    ),
    (
        "droptxindex",
        "Deletes the hash-based transaction index from the database on start up and then exits",
        None,
    ),
    (
        "noexistsaddrindex",
        "Disable the exists address index, which tracks whether or not an address has even been used",
        None,
    ),
    (
        "dropexistsaddrindex",
        "Deletes the exists address index from the database on start up and then exits",
        None,
    ),
    (
        "piperx",
        "File descriptor of read end pipe to enable parent -> child process communication",
        None,
    ),
    (
        "pipetx",
        "File descriptor of write end pipe to enable parent <- child process communication",
        None,
    ),
    (
        "lifetimeevents",
        "Send lifetime notifications over the TX pipe",
        None,
    ),
    (
        "boundaddrevents",
        "Send notifications with the locally bound addresses of the P2P and RPC subsystems over the TX pipe",
        None,
    ),
];

/// Render dcrd's `-h` help text (go-flags v1.6.1's `writeHelp` over
/// the option registry, byte-for-byte): the usage line over the app
/// name, the Application Options section with the option column
/// padded two spaces past the longest entry, descriptions (with their
/// `(default: X)` notes and `[$ENV]` annotations) wrapped to the
/// terminal width onto continuation lines aligned to the description
/// column, and the Help Options tail.  dcrd's dedicated help pre-parse
/// never adds the Windows service group, so neither does this.
///
/// `default_home_dir` is the application data directory the defaults
/// derive from (dcrd's `defaultHomeDir`), as the load was given it in
/// [`crate::config::ConfigEnv::default_home_dir`].  `terminal_columns`
/// is go-flags' `getTerminalColumns` result, which the daemon takes
/// from [`terminal_columns`]; zero means eighty, as in
/// `getAlignmentInfo`.
///
/// The text comes back as bytes because go-flags wraps by bytes: a
/// hyphenating split of a long default path can fall inside a
/// multibyte character, and dcrd writes those partial bytes as they
/// are.
pub fn render_help(app_name: &str, default_home_dir: &str, terminal_columns: usize) -> Vec<u8> {
    render_help_with(
        app_name,
        &HELP_DESCRIPTIONS,
        default_home_dir,
        terminal_columns,
    )
}

/// [`render_help`] over an explicit description table.
///
/// The table supplies each option's help text and its optional
/// environment-variable annotation, both of which feed go-flags' line
/// wrapping — so substituting it is how the parity test renders with
/// dcrd's variable names and keeps comparing byte for byte against dcrd's
/// dumped help.  Production always passes [`HELP_DESCRIPTIONS`].
pub fn render_help_with(
    app_name: &str,
    descriptions: &[(&str, &str, Option<&str>)],
    default_home_dir: &str,
    terminal_columns: usize,
) -> Vec<u8> {
    // go-flags `getAlignmentInfo`: a width that is not positive, as a
    // terminal reporting no size gives, is eighty columns.
    let terminal_columns = if terminal_columns == 0 {
        80
    } else {
        terminal_columns
    };

    // dcrd runs its help pre-parse over the config it has just filled
    // with its defaults, and go-flags' `ParseArgs` records each option's
    // value as its default literal before it parses anything
    // (`updateDefaultLiteral`), so the help shows the defaults whatever
    // the command line says.
    let defaults = Config::defaults(default_home_dir);

    // The alignment column counts "  " + the short slot + "--long"
    // WITHOUT the value marker: go-flags appends the "=" after
    // computing the alignment, so the marker eats into the padding
    // (down to a single space) rather than widening the column.
    let base = |spec: &OptSpec| -> String {
        let short = match spec.short {
            Some(c) => format!("-{c}, "),
            None => "    ".to_string(),
        };
        format!("  {short}--{}", spec.long)
    };
    let prefix = |spec: &OptSpec| -> String {
        let value = if matches!(spec.kind, OptKind::Bool) {
            ""
        } else {
            "="
        };
        format!("{}{value}", base(spec))
    };
    let help_prefix = "  -h, --help".to_string();
    let column = OPTIONS
        .iter()
        .map(|o| base(o).chars().count())
        .chain(core::iter::once(help_prefix.chars().count()))
        .max()
        .unwrap_or(0)
        .saturating_add(2);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"Usage:\n");
    out.extend_from_slice(format!("  {app_name} [OPTIONS]\n").as_bytes());
    out.extend_from_slice(b"\nApplication Options:\n");
    for spec in OPTIONS.iter() {
        let (_, desc, env) = descriptions
            .iter()
            .find(|(long, _, _)| *long == spec.long)
            .copied()
            .unwrap_or((spec.long, "", None));
        let def = default_literal(&defaults, spec);
        let mut text = if def.is_empty() {
            desc.to_string()
        } else {
            format!("{desc} (default: {def})")
        };
        if let Some(env) = env {
            text.push_str(&format!(" [${env}]"));
        }
        push_entry(&mut out, &prefix(spec), &text, column, terminal_columns);
    }
    out.extend_from_slice(b"\nHelp Options:\n");
    push_entry(
        &mut out,
        &help_prefix,
        "Show this help message",
        column,
        terminal_columns,
    );
    // dcrd prints the help error through Println, appending a final
    // blank line.
    out.push(b'\n');
    out
}

/// go-flags' `getTerminalColumns` (`termsize.go`): the column count of
/// the terminal on standard input, read with `TIOCGWINSZ` on descriptor
/// 0, or eighty when that fails -- so a help that is piped or
/// redirected still follows the terminal it was typed in, and one run
/// with no terminal on stdin wraps at eighty.  A terminal reporting
/// zero columns gives zero, which [`render_help`] treats as eighty.
///
/// The workspace forbids unsafe code, so the ioctl runs through
/// `stty size` over this process's own stdin (the stand-in
/// `promptsecret` uses for its termios calls): it prints the rows and
/// columns `TIOCGWINSZ` reports and fails on a descriptor that is not
/// a terminal.  A missing `stty` falls back to eighty as well.
#[cfg(all(unix, not(target_os = "aix")))]
pub fn terminal_columns() -> usize {
    std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| stty_size_columns(&out.stdout))
        .unwrap_or(80)
}

/// go-flags' `getTerminalColumns` where it asks no terminal: eighty
/// columns on AIX (`termsize_nosysioctl.go`), and on Windows, where
/// go-flags reads `MaximumWindowSize.X` of the console behind standard
/// output (`termsize_windows.go`) through a console call that needs
/// unsafe code, which the workspace forbids -- so the port keeps the
/// eighty go-flags falls back to when stdout is not a console.
#[cfg(not(all(unix, not(target_os = "aix"))))]
pub fn terminal_columns() -> usize {
    80
}

/// The column count out of `stty size` output (`rows cols`, the
/// `ws_row` and `ws_col` of `TIOCGWINSZ`), as the `uint16` go-flags
/// widens to an `int`.
#[cfg(all(unix, not(target_os = "aix")))]
fn stty_size_columns(out: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(out).ok()?;
    let mut fields = text.split_ascii_whitespace();
    let _rows: u16 = fields.next()?.parse().ok()?;
    let cols: u16 = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some(usize::from(cols))
}

/// The default go-flags prints for an option: `updateDefaultLiteral`
/// over dcrd's defaulted config, rendered by `convertToString` -- the
/// string itself, `[a, b]` for a slice, decimal integers, `FormatFloat`
/// with `'g'` and the shortest precision, and `Duration.String`.  An
/// option that takes no argument (a bool), a zero value, and the four
/// passwords with `default-mask:"-"` show none.
fn default_literal(cfg: &Config, spec: &OptSpec) -> String {
    let string = |v: &str| v.to_string();
    let slice = |v: &[String]| {
        if v.is_empty() {
            String::new()
        } else {
            format!("[{}]", v.join(", "))
        }
    };
    let int = |v: i64| if v == 0 { String::new() } else { v.to_string() };
    let uint = |v: u64| if v == 0 { String::new() } else { v.to_string() };
    let float = |v: f64| {
        // `reflect.DeepEqual` against the zero value compares with
        // `==`, so a negative zero shows no default and a NaN does.
        if v == 0.0 {
            String::new()
        } else {
            dcroxide_dcrjson::gojson::format_float_g(v)
        }
    };
    let duration = |nanos: i64| {
        if nanos == 0 {
            String::new()
        } else {
            crate::gostd::go_duration_string(nanos)
        }
    };
    match spec.long {
        "appdata" => string(&cfg.home_dir),
        "configfile" => string(&cfg.config_file),
        "datadir" => string(&cfg.data_dir),
        "logdir" => string(&cfg.log_dir),
        "logsize" => string(&cfg.log_size),
        "dbtype" => string(&cfg.db_type),
        "profile" => string(&cfg.profile),
        "cpuprofile" => string(&cfg.cpu_profile),
        "memprofile" => string(&cfg.mem_profile),
        "debuglevel" => string(&cfg.debug_level),
        "sigcachemaxsize" => uint(cfg.sig_cache_max_size),
        "utxocachemaxsize" => uint(cfg.utxo_cache_max_size),
        "rpclisten" => slice(&cfg.rpc_listeners),
        "rpcuser" => string(&cfg.rpc_user),
        "authtype" => string(&cfg.rpc_auth_type),
        "clientcafile" => string(&cfg.rpc_client_cas),
        "rpclimituser" => string(&cfg.rpc_limit_user),
        "rpccert" => string(&cfg.rpc_cert),
        "rpckey" => string(&cfg.rpc_key),
        "tlscurve" => string(&cfg.tls_curve),
        "altdnsnames" => slice(&cfg.alt_dns_names),
        "rpcmaxclients" => int(cfg.rpc_max_clients),
        "rpcmaxwebsockets" => int(cfg.rpc_max_websockets),
        "rpcmaxconcurrentreqs" => int(cfg.rpc_max_concurrent_reqs),
        "proxy" => string(&cfg.proxy),
        "proxyuser" => string(&cfg.proxy_user),
        "onion" => string(&cfg.onion_proxy),
        "onionuser" => string(&cfg.onion_proxy_user),
        "addpeer" => slice(&cfg.add_peers),
        "connect" => slice(&cfg.connect_peers),
        "listen" => slice(&cfg.listeners),
        "maxsameip" => int(cfg.max_same_ip),
        "maxpeers" => int(cfg.max_peers),
        "dialtimeout" => duration(cfg.dial_timeout_nanos),
        "peeridletimeout" => duration(cfg.peer_idle_timeout_nanos),
        "externalip" => slice(&cfg.external_ips),
        "banduration" => duration(cfg.ban_duration_nanos),
        "banthreshold" => uint(u64::from(cfg.ban_threshold)),
        "whitelist" => slice(&cfg.whitelists_raw),
        "dumpblockchain" => string(&cfg.dump_blockchain),
        "assumevalid" => string(&cfg.assume_valid),
        "minrelaytxfee" => float(cfg.min_relay_tx_fee),
        "limitfreerelay" => float(cfg.free_tx_relay_limit),
        "maxorphantx" => int(cfg.max_orphan_txs),
        "miningaddr" => slice(&cfg.mining_addrs_raw),
        "blockminsize" => uint(u64::from(cfg.block_min_size)),
        "blockmaxsize" => uint(u64::from(cfg.block_max_size)),
        "blockprioritysize" => uint(u64::from(cfg.block_priority_size)),
        "miningtimeoffset" => int(cfg.mining_time_offset),
        "piperx" => uint(cfg.pipe_rx),
        "pipetx" => uint(cfg.pipe_tx),
        // The bools, which take no argument, and the passwords
        // (`rpcpass`, `rpclimitpass`, `proxypass`, `onionpass`), whose
        // `default-mask:"-"` hides any default.
        _ => String::new(),
    }
}

/// One help entry (go-flags `writeHelpOption`): the option column
/// padded to the description start (a value marker may squeeze the
/// padding down to one space), then the description through
/// [`wrap_text`] over the columns the terminal leaves past the
/// description start, with continuation lines aligned under the
/// description column.
fn push_entry(
    out: &mut Vec<u8>,
    prefix: &str,
    description: &str,
    column: usize,
    terminal_columns: usize,
) {
    // `info.terminalColumns-descstart`; a negative width is below
    // `wrapText`'s floor of ten either way.
    let width = terminal_columns.saturating_sub(column);
    out.extend_from_slice(prefix.as_bytes());
    let pad = column.saturating_sub(prefix.chars().count()).max(1);
    out.resize(out.len() + pad, b' ');
    let indent = vec![b' '; column];
    out.extend_from_slice(&wrap_text(description.as_bytes(), width, &indent));
    out.push(b'\n');
}

/// go-flags' `wrapText`, over bytes as Go indexes strings: for each
/// `\n`-separated line, trimmed, while the rest is LONGER than the
/// width, split at the last space within the first width bytes --
/// keeping an exactly-width remainder whole -- or, with no space,
/// after width-1 bytes with a `-` and a newline, which the next
/// segment's own newline and prefix then follow (so a hyphenated split
/// leaves a blank line); continuation lines start with `prefix`.
fn wrap_text(s: &[u8], width: usize, prefix: &[u8]) -> Vec<u8> {
    let l = width.max(10);
    let mut ret: Vec<u8> = Vec::new();
    for raw in s.split(|&b| b == b'\n') {
        let mut retline: Vec<u8> = Vec::new();
        let mut line = go_trim_space(raw);
        while line.len() > l {
            // Try to split on space.
            let (pos, suffix): (usize, &[u8]) = match line[..l].iter().rposition(|&b| b == b' ') {
                Some(pos) => (pos, b""),
                None => (l - 1, b"-\n"),
            };
            if !retline.is_empty() {
                retline.push(b'\n');
                retline.extend_from_slice(prefix);
            }
            retline.extend_from_slice(go_trim_space(&line[..pos]));
            retline.extend_from_slice(suffix);
            line = go_trim_space(&line[pos..]);
        }
        if !line.is_empty() {
            if !retline.is_empty() {
                retline.push(b'\n');
                retline.extend_from_slice(prefix);
            }
            retline.extend_from_slice(line);
        }
        if !ret.is_empty() {
            ret.push(b'\n');
            if !retline.is_empty() {
                ret.extend_from_slice(prefix);
            }
        }
        ret.extend_from_slice(&retline);
    }
    ret
}

/// Go's `strings.TrimSpace` over bytes that may end in part of a UTF-8
/// sequence (a split of [`wrap_text`]): leading and trailing Unicode
/// white space is removed, and an incomplete sequence, which Go decodes
/// as `RuneError`, stops the trim.
fn go_trim_space(mut b: &[u8]) -> &[u8] {
    let edge_char = |bytes: &[u8], front: bool| -> Option<char> {
        (1..=bytes.len().min(4)).find_map(|n| {
            let part = if front {
                &bytes[..n]
            } else {
                &bytes[bytes.len() - n..]
            };
            let text = std::str::from_utf8(part).ok()?;
            let mut chars = text.chars();
            let c = if front {
                chars.next()
            } else {
                chars.next_back()
            }?;
            chars.next().is_none().then_some(c)
        })
    };
    while let Some(c) = edge_char(b, true).filter(|c| c.is_whitespace()) {
        b = &b[c.len_utf8()..];
    }
    while let Some(c) = edge_char(b, false).filter(|c| c.is_whitespace()) {
        b = &b[..b.len() - c.len_utf8()];
    }
    b
}

/// Find an option by its long name.
pub fn find_long(name: &str) -> Option<&'static OptSpec> {
    find_long_in(&OPTIONS, name)
}

/// The Windows service options group (dcrd `serviceOptions`): dcrd's
/// `newConfigParser` adds it to the parser only on Windows, so the
/// `-s/--service` flag is an unknown-option error everywhere else —
/// pinned by the flags vectors.
pub const SERVICE_OPTIONS: [OptSpec; 1] = [OptSpec {
    long: "service",
    short: Some('s'),
    field: "ServiceCommand",
    kind: OptKind::Str,
}];

/// Find an option by its long name in the given registry
/// (short-only options carry an empty long name and never match).
/// go-flags' built-in help option, registered only on the parser dcrd
/// builds with `flags.HelpFlag` -- the help pre-parse at
/// `config.go:653-659`.  The config-file pre-parse (`flags.None`) and
/// the final parse (`flags.PassDoubleDash`) do not have it, which is
/// why `--help=x` ends as ``unknown flag `help'``.
/// A `static` rather than a `const`: the store callback identifies the
/// injected spec by address, and `&CONST` is const-promoted per use
/// site, so two promotions of the same const need not compare equal.
pub static HELP_OPTION: OptSpec = OptSpec {
    long: "help",
    short: Some('h'),
    field: "Help",
    kind: OptKind::Bool,
};

/// Registry lookup that also consults the built-in help option, on the
/// one parse that registers it.  That parse is also the one without the
/// Windows service group: dcrd builds it as `flags.NewParser(&cfg,
/// helpOpts)` rather than through `newConfigParser`, so there
/// `-s/--service` is an unknown option, skipped like any other, and only
/// the config-file pre-parse sets the service command dcrd acts on.
fn find_long_for(
    registry: &'static [OptSpec],
    mode: ScanMode,
    name: &str,
) -> Option<&'static OptSpec> {
    let service_group = has_service_group(registry) && mode != ScanMode::IgnoreUnknown;
    find_long_with(registry, name, service_group).or(match mode {
        ScanMode::IgnoreUnknown if name == "help" => Some(&HELP_OPTION),
        _ => None,
    })
}

fn find_short_for(
    registry: &'static [OptSpec],
    mode: ScanMode,
    name: char,
) -> Option<&'static OptSpec> {
    let service_group = has_service_group(registry) && mode != ScanMode::IgnoreUnknown;
    find_short_with(registry, name, service_group).or(match mode {
        ScanMode::IgnoreUnknown if name == 'h' => Some(&HELP_OPTION),
        _ => None,
    })
}

fn find_long_in(registry: &'static [OptSpec], name: &str) -> Option<&'static OptSpec> {
    find_long_with(registry, name, has_service_group(registry))
}

/// Whether lookups over the registry also consult the Windows service
/// options group: dcrd's `newConfigParser` adds that group to the
/// daemon parser only on Windows, and the tool registries never carry
/// it.
fn has_service_group(registry: &'static [OptSpec]) -> bool {
    // OPTIONS is a const, so identity is by content: the dcrd registry
    // is the only 86-entry one and its first option is `version`.
    cfg!(windows)
        && registry.len() == OPTIONS.len()
        && registry.first().is_some_and(|o| o.long == "version")
}

fn find_long_with(
    registry: &'static [OptSpec],
    name: &str,
    service_group: bool,
) -> Option<&'static OptSpec> {
    registry
        .iter()
        .chain(if service_group {
            SERVICE_OPTIONS.iter()
        } else {
            [].iter()
        })
        .find(|o| !o.long.is_empty() && o.long == name)
}

fn find_short_with(
    registry: &'static [OptSpec],
    name: char,
    service_group: bool,
) -> Option<&'static OptSpec> {
    registry
        .iter()
        .chain(if service_group {
            SERVICE_OPTIONS.iter()
        } else {
            [].iter()
        })
        .find(|o| o.short == Some(name))
}

/// Find an option the way go-flags' INI parser matches names
/// (`Group.optionByName`, `group.go:147-176`) over the option groups a
/// section matches, walked in order: the `ini-name` matcher first, then
/// the exact Go field name, then the exact long name, then the exact
/// short name, each across every group before the next.
fn find_ini_name(name: &str, groups: &[&'static [OptSpec]]) -> Option<&'static OptSpec> {
    let walk = || groups.iter().flat_map(|group| group.iter());
    // The matcher compares the lowercased `ini-name` tag with the
    // lowercased key.  No dcrd option carries the tag, so every option
    // matches the empty key, and the first one walked -- `ShowVersion`,
    // the first field of the config struct -- takes it: a stray `=` or
    // `=1` line sets the version flag of the final config, which dcrd
    // never reads, and `=foo` fails its `ParseBool`.
    if name.is_empty() {
        return walk().next();
    }
    walk()
        .find(|o| o.field == name)
        .or_else(|| walk().find(|o| o.long == name))
        .or_else(|| {
            let mut chars = name.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => walk().find(|o| o.short == Some(c)),
                _ => None,
            }
        })
}

/// The option rendered as go-flags' `Option.String` for error
/// messages: `-u, --rpcuser` or `--maxpeers`.
fn opt_display(spec: &OptSpec) -> String {
    match spec.short {
        Some(short) if spec.long.is_empty() => format!("-{short}"),
        Some(short) => format!("-{short}, --{}", spec.long),
        None => format!("--{}", spec.long),
    }
}

/// Convert and store a value like go-flags' `Option.Set`, returning
/// the raw conversion error (the callers add the command line or
/// INI context).  A `None` value is the bare-flag form.
pub(crate) fn set_option(
    cfg: &mut Config,
    pass: &mut ParsePass,
    spec: &OptSpec,
    value: Option<&str>,
) -> Result<(), String> {
    let val = value.unwrap_or("");
    crate::config::store_option(cfg, pass, spec.long, spec.kind, val)
}

/// A parse error from the scanner with go-flags' exact texts; the
/// unknown-flag case is distinguished for `IgnoreUnknown`.
pub enum ScanError {
    /// An unknown option name.
    UnknownFlag(String),
    /// Any other parse failure.
    Other(String),
}

impl ScanError {
    /// The go-flags error text for this failure.
    pub fn message(self) -> String {
        match self {
            ScanError::UnknownFlag(name) => format!("unknown flag `{name}'"),
            ScanError::Other(msg) => msg,
        }
    }
}

/// The parser mode differences `loadConfig`'s three parses exhibit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// The help pre-parse: unknown options are ignored, `--` is not
    /// special, and errors abort silently.
    IgnoreUnknown,
    /// The config-file pre-parse: no options set, `--` is not
    /// special, and any error aborts silently.
    Plain,
    /// The final parse: `--` terminates option parsing and errors
    /// surface.
    PassDoubleDash,
}

/// Whether an argument is an option (go-flags `argumentIsOption` on
/// POSIX): `-x...` or `--x...` but not `-`, `--`, or `---...`.
fn argument_is_option(arg: &str) -> bool {
    let b = arg.as_bytes();
    if b.len() > 1 && b[0] == b'-' && b[1] != b'-' {
        return true;
    }
    if b.len() > 2 && b[0] == b'-' && b[1] == b'-' && b[2] != b'-' {
        return true;
    }
    false
}

/// Validate a popped separate argument like go-flags
/// `isValidValue`: option-looking values are rejected unless the
/// option is a signed number type and the value is `-<digit>...`.
fn valid_separate_value(spec: &OptSpec, arg: &str) -> Result<(), String> {
    let b = arg.as_bytes();
    let neg_number =
        spec.kind.signed_number() && b.len() > 1 && b[0] == b'-' && b[1].is_ascii_digit();
    if argument_is_option(arg) && !neg_number {
        return Err(format!(
            "expected argument for flag `{}', but got option `{arg}'",
            opt_display(spec)
        ));
    }
    Ok(())
}

/// The value sink a scan applies options through: the daemon stores
/// into its `Config` via `set_option`, and each tool binary stores
/// into its own config struct (go-flags reflecting into whatever
/// struct the parser was built over).
type StoreFn<'s> = dyn FnMut(&'static OptSpec, Option<&str>) -> Result<(), String> + 's;

/// Apply a value to an option like go-flags `parseOption`: bare
/// bools reject arguments, values unquote when they look quoted,
/// and conversion failures wrap as marshal errors.
fn parse_option(
    store: &mut StoreFn<'_>,
    state: &mut ScanState<'_>,
    spec: &'static OptSpec,
    canarg: bool,
    argument: Option<String>,
) -> Result<(), ScanError> {
    if spec.kind == OptKind::Bool {
        if argument.is_some() {
            return Err(ScanError::Other(format!(
                "bool flag `{}' cannot have an argument",
                opt_display(spec)
            )));
        }
        state.record_set(spec);
        store(spec, None).map_err(|e| ScanError::Other(marshal_error(spec, &e)))?;
        return Ok(());
    }

    let arg = if let Some(arg) = argument {
        arg
    } else if canarg && !state.eof() {
        let arg = state.pop();
        if let Err(e) = valid_separate_value(spec, &arg) {
            return Err(ScanError::Other(e));
        }
        if state.mode == ScanMode::PassDoubleDash && arg == "--" {
            return Err(ScanError::Other(format!(
                "expected argument for flag `{}', but got double dash `--'",
                opt_display(spec)
            )));
        }
        arg
    } else {
        return Err(ScanError::Other(format!(
            "expected argument for flag `{}'",
            opt_display(spec)
        )));
    };

    // Values that look quoted are unquoted.
    let arg = if arg.starts_with('"') {
        go_unquote(&arg).map_err(|e| ScanError::Other(marshal_error(spec, &e)))?
    } else {
        arg
    };

    state.record_set(spec);
    store(spec, Some(&arg)).map_err(|e| ScanError::Other(marshal_error(spec, &e)))
}

/// Wrap a conversion error like go-flags `marshalError`.
fn marshal_error(spec: &OptSpec, err: &str) -> String {
    format!(
        "invalid argument for flag `{}' (expected {}): {err}",
        opt_display(spec),
        spec.kind.expected()
    )
}

/// The scanner state over the argument list.
pub struct ScanState<'a> {
    args: &'a [String],
    pos: usize,
    mode: ScanMode,
    /// The non-option arguments collected (go-flags `retargs`).
    pub retargs: Vec<String>,
    /// The long names set by this parser (feeding the environment
    /// default suppression, go-flags `preventDefault`).
    pub set_names: Vec<&'static str>,
}

impl<'a> ScanState<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.args.len()
    }

    fn pop(&mut self) -> String {
        let arg = self.args[self.pos].clone();
        self.pos += 1;
        arg
    }

    fn record_set(&mut self, spec: &'static OptSpec) {
        if !self.set_names.contains(&spec.long) {
            self.set_names.push(spec.long);
        }
    }
}

/// Scan and apply the command line like go-flags `ParseArgs` for the
/// dcrd parser configurations; on success the collected non-option
/// arguments are in `state.retargs`.
pub(crate) fn scan_args<'a>(
    cfg: &mut Config,
    args: &'a [String],
    mode: ScanMode,
    help: &mut bool,
) -> (ScanState<'a>, Option<ScanError>) {
    let mut pass = ParsePass::default();
    let (state, err) = scan_args_in(
        &OPTIONS,
        &mut |spec, value| {
            // The injected help spec has no `Config` field; it is the
            // parse's own result, like go-flags' `ErrHelp`, and like it
            // ends the scan where it stands: the help option's handler
            // returns `ErrHelp`, so go-flags never reaches the arguments
            // after it, nor an error one of them would raise.
            if core::ptr::eq(spec, &HELP_OPTION) {
                *help = true;
                Err(String::new())
            } else {
                set_option(cfg, &mut pass, spec, value)
            }
        },
        args,
        mode,
    );
    // The stop above is the help result, not an error of the parse.
    if *help { (state, None) } else { (state, err) }
}

/// Scan and apply a command line like go-flags `ParseArgs` over any
/// option registry and value sink — the shared scanner behind the
/// daemon and the tool binaries (each of dcrd's commands builds its
/// own go-flags parser over its own config struct, all with the same
/// scanning semantics).
pub fn scan_args_in<'a>(
    registry: &'static [OptSpec],
    store: &mut StoreFn<'_>,
    args: &'a [String],
    mode: ScanMode,
) -> (ScanState<'a>, Option<ScanError>) {
    let mut state = ScanState {
        args,
        pos: 0,
        mode,
        retargs: Vec::new(),
        set_names: Vec::new(),
    };

    while !state.eof() {
        let arg = state.pop();

        // When PassDoubleDash is set and we encounter a --, then
        // simply append all the rest as arguments and break out.
        if state.mode == ScanMode::PassDoubleDash && arg == "--" {
            while !state.eof() {
                let rest = state.pop();
                state.retargs.push(rest);
            }
            break;
        }

        if !argument_is_option(&arg) {
            state.retargs.push(arg);
            continue;
        }

        let result = if let Some(rest) = arg.strip_prefix("--") {
            // Long option, with an optional =argument.
            let (name, argument) = match rest.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (rest, None),
            };
            match find_long_for(registry, state.mode, name) {
                Some(spec) => parse_option(store, &mut state, spec, true, argument),
                None => Err(ScanError::UnknownFlag(name.to_string())),
            }
        } else {
            // Short option(s), with an optional =argument at
            // position 1 or a concatenated argument.
            let rest = &arg[1..];
            let (names, argument) = match rest.split_once('=') {
                Some((name, value)) if name.chars().count() == 1 => {
                    (name.to_string(), Some(value.to_string()))
                }
                _ => (rest.to_string(), None),
            };
            parse_shorts(registry, store, &mut state, &names, argument)
        };

        if let Err(err) = result {
            match err {
                ScanError::UnknownFlag(_) if mode == ScanMode::IgnoreUnknown => {
                    // The whole original argument becomes a
                    // remaining argument.
                    state.retargs.push(arg);
                }
                other => return (state, Some(other)),
            }
        }
    }

    (state, None)
}

/// Parse a short option cluster like go-flags `parseShort` with
/// `splitShortConcatArg`.
fn parse_shorts(
    registry: &'static [OptSpec],
    store: &mut StoreFn<'_>,
    state: &mut ScanState<'_>,
    names: &str,
    mut argument: Option<String>,
) -> Result<(), ScanError> {
    let mut names = names.to_string();

    // A concatenated argument splits off after the first short name
    // when that option can take an argument.
    if argument.is_none() {
        let mut chars = names.chars();
        if let Some(first) = chars.next() {
            let rest: String = chars.collect();
            if !rest.is_empty()
                && let Some(spec) = find_short_for(registry, state.mode, first)
                && spec.kind != OptKind::Bool
            {
                argument = Some(rest);
                names = first.to_string();
            }
        }
    }

    let total = names.chars().count();
    for (i, c) in names.chars().enumerate() {
        let Some(spec) = find_short_for(registry, state.mode, c) else {
            return Err(ScanError::UnknownFlag(c.to_string()));
        };
        // Only the last short option may consume a separate
        // argument.
        let canarg = i + 1 == total;
        parse_option(store, state, spec, canarg, argument.take())?;
    }
    Ok(())
}

/// Apply the environment defaults like go-flags `clearDefault` at
/// the end of a successful parse: options this parser never set
/// take their `env` tag values.
pub(crate) fn apply_env_defaults(
    cfg: &mut Config,
    set_names: &[&'static str],
    getenv: &dyn Fn(&str) -> Option<String>,
) {
    for (long, key, delim) in ENV_DEFAULTS {
        if set_names.contains(&long) {
            continue;
        }
        let Some(value) = getenv(key) else {
            continue;
        };
        let spec = find_long(long).expect("registered option");
        // The default application empties the value and sets each
        // part; errors cannot happen for the string kinds involved.
        let mut pass = ParsePass::default();
        match delim {
            Some(delim) => {
                for part in value.split(delim) {
                    let _ = set_option(cfg, &mut pass, spec, Some(part));
                }
            }
            None => {
                let _ = set_option(cfg, &mut pass, spec, Some(&value));
            }
        }
    }
}

/// One parsed INI assignment.
pub(crate) struct IniAssignment {
    /// The matched option.
    pub spec: &'static OptSpec,
    /// The value (`None` is the empty-value bare-bool form).
    pub value: Option<String>,
    /// The 1-based line number, for error texts.
    pub line: usize,
}

/// One step of go-flags' INI apply pass (`IniParser.parse`), in its
/// order.
pub(crate) enum IniStep {
    /// A value to convert and store; a conversion error stops the pass
    /// here, reported with the file/line context by the caller.
    Set(IniAssignment),
    /// The error the apply pass stops with on reaching this point (an
    /// unknown option group or option name), in `loadConfig`'s text.
    Fail(String),
}

/// One `key=value` line as go-flags' `readIni` keeps it: the name, the
/// (unquoted) value, and the 1-based line number.
type IniValue<'a> = (&'a str, String, usize);

/// Parse the INI config file like go-flags' `IniParser`, in its two
/// passes.  `readIni` reads the whole file first and fails only on
/// syntax -- a malformed section header, an empty section name, a line
/// without `=`, a quoted value `strconv.Unquote` refuses -- which is
/// returned as the error.  `parse` then walks each section's values in
/// file order, looking up and converting each: the steps returned are
/// that walk, ending at the first unknown group or option, and the
/// caller converts the values in order, so the first bad line of the
/// walk is the one reported, whatever made it bad.
///
/// Go walks the sections map in random order; the port takes them in
/// order of first appearance (the global section first, as the file
/// must have it), one of the orders dcrd can take.
pub(crate) fn parse_ini(content: &str, filename: &str) -> Result<Vec<IniStep>, String> {
    parse_ini_with(content, filename, has_service_group(&OPTIONS))
}

/// [`parse_ini`] over dcrd's parser with the Windows service options
/// group (`service_group`) or without it.
fn parse_ini_with(
    content: &str,
    filename: &str,
    service_group: bool,
) -> Result<Vec<IniStep>, String> {
    let ini_error = |line: usize, message: &str| format!("{filename}:{line}: {message}");

    // readIni.  The empty global section always exists; a section named
    // again continues its earlier values.
    let mut sections: Vec<(&str, Vec<IniValue<'_>>)> = vec![("", Vec::new())];
    let mut current = 0;
    for (idx, raw) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(ini_error(lineno, "malformed section header"));
            }
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() {
                return Err(ini_error(lineno, "empty section name"));
            }
            current = match sections.iter().position(|(n, _)| *n == name) {
                Some(i) => i,
                None => {
                    sections.push((name, Vec::new()));
                    sections.len() - 1
                }
            };
            continue;
        }

        // Parse option here.
        let Some((rawkey, rawvalue)) = line.split_once('=') else {
            return Err(ini_error(lineno, &format!("malformed key=value ({line})")));
        };
        let name = rawkey.trim();
        let mut value = rawvalue.trim().to_string();

        if value.starts_with('"') {
            value = go_unquote(&value).map_err(|e| ini_error(lineno, &e))?;
        }

        sections[current].1.push((name, value, lineno));
    }

    // parse.
    let mut steps = Vec::new();
    for (section, values) in sections {
        // go-flags' `matchingGroups` (`ini.go:479-497`): the global
        // (empty) section searches every group of the parser, and a
        // named one only the group whose description it names, compared
        // case-insensitively (`Group.Find`).  dcrd's parser has the
        // Application Options group and, on Windows only, the Service
        // Options group `newConfigParser` adds, so there `service=` and
        // a `[Service Options]` section are taken (and the value never
        // read: dcrd acts on the pre-parse's service command alone).
        let groups: &[&'static [OptSpec]] = match section.to_lowercase().as_str() {
            "" if service_group => &[&OPTIONS, &SERVICE_OPTIONS],
            "" | "application options" => &[&OPTIONS],
            "service options" if service_group => &[&SERVICE_OPTIONS],
            _ => {
                steps.push(IniStep::Fail(format!(
                    "could not find option group `{section}'"
                )));
                return Ok(steps);
            }
        };

        for (name, value, line) in values {
            let Some(spec) = find_ini_name(name, groups) else {
                steps.push(IniStep::Fail(ini_error(
                    line,
                    &format!("unknown option: {name}"),
                )));
                return Ok(steps);
            };

            // A bool option with an empty value is the bare-flag form.
            let value = if spec.kind == OptKind::Bool && value.is_empty() {
                None
            } else {
                Some(value)
            };

            steps.push(IniStep::Set(IniAssignment { spec, value, line }));
        }
    }

    Ok(steps)
}

/// The process arguments after the program name, as UTF-8 strings.
///
/// `std::env::args` panics on an argument that is not valid Unicode, and
/// release builds abort on panic, so a single bad byte in argv kills the
/// process before anything can say why.  Go strings are arbitrary bytes,
/// so dcrd simply takes such an argument -- on unix a path need not be
/// UTF-8 at all.
///
/// Matching that byte for byte would mean threading `OsStr` through every
/// option, value, and config-file path; short of that, the offending
/// argument is returned so the caller can report it and exit cleanly
/// rather than abort silently.  Callers deliberately reject where dcrd
/// would accept, which only affects argv this port could not represent
/// anyway.
pub fn args_after_program() -> Result<Vec<String>, std::ffi::OsString> {
    std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect()
}

/// An environment variable of the process, for the configuration's
/// lookups ([`crate::config::ConfigEnv::getenv`] and
/// [`crate::config::app_data_dir`]).
///
/// Go's `os.Getenv` returns a variable's raw bytes (on Windows, its
/// UTF-16 decoded as WTF-8), so dcrd takes a `DCRD_APPDATA`, a `HOME` or
/// a `$VAR` in `--datadir` that is not UTF-8 as the bytes it holds.
/// `std::env::var(..).ok()` read such a value as unset, and the port
/// then ran on the default home -- for `HOME`, on the current
/// directory -- with nothing said.  A `String` cannot hold it, so it is
/// refused instead, as argv is ([`args_after_program`]): the first such
/// value is recorded in `refused` as the error to fail with, and the
/// lookup returns `None`.  The port looks a variable up only where dcrd
/// does, so only one dcrd would have read is refused, and the load fails
/// with it before acting on what it read
/// ([`crate::config::load_config_from_argv_with_notices`]).
pub fn getenv_utf8(name: &str, refused: &std::cell::RefCell<Option<String>>) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(raw)) => {
            refused.borrow_mut().get_or_insert_with(|| {
                format!(
                    "invalid UTF-8 in environment variable {name}: {}",
                    raw.to_string_lossy()
                )
            });
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service group chains into lookups only when requested — the
    /// Windows-only behavior, testable on every platform through the
    /// forced flag (the posix rejection is pinned by the flags
    /// vectors).
    #[test]
    fn service_group_chains_when_requested() {
        assert!(find_long_with(&OPTIONS, "service", true).is_some());
        assert!(find_long_with(&OPTIONS, "service", false).is_none());
        assert!(find_short_with(&OPTIONS, 's', true).is_some());
        assert!(find_short_with(&OPTIONS, 's', false).is_none());
    }

    /// The config file on Windows, where dcrd's parser has the Service
    /// Options group: the global section finds `service` by its long,
    /// field and short names, a `[Service Options]` section is that
    /// group alone, and `[Application Options]` never reaches it.  The
    /// port looked the global names up in the application options only
    /// and knew no section but `application options`, so a dcrd.conf
    /// dcrd starts with failed the start.  Without the group (every
    /// other platform) both are refused as dcrd refuses them.
    #[test]
    fn the_ini_service_group_matches_as_go_flags_does() {
        let resolved = |content: &str, service_group: bool| -> Vec<String> {
            parse_ini_with(content, "f.conf", service_group)
                .expect("the file reads")
                .into_iter()
                .map(|step| match step {
                    IniStep::Set(a) => {
                        format!("{}={}", a.spec.long, a.value.unwrap_or_default())
                    }
                    IniStep::Fail(e) => format!("fail: {e}"),
                })
                .collect()
        };

        assert_eq!(
            resolved(
                "service=install\nServiceCommand=stop\ns=start\nrpcuser=u\n",
                true
            ),
            [
                "service=install",
                "service=stop",
                "service=start",
                "rpcuser=u"
            ]
        );
        assert_eq!(
            resolved("[Service Options]\nservice=remove\n", true),
            ["service=remove"]
        );
        assert_eq!(
            resolved("[service options]\nrpcuser=u\n", true),
            ["fail: f.conf:2: unknown option: rpcuser"]
        );
        assert_eq!(
            resolved("[Application Options]\nservice=install\n", true),
            ["fail: f.conf:2: unknown option: service"]
        );
        assert_eq!(
            resolved("[Application Options]\ns=install\n", true),
            ["fail: f.conf:2: unknown option: s"]
        );

        assert_eq!(
            resolved("service=install\n", false),
            ["fail: f.conf:1: unknown option: service"]
        );
        assert_eq!(
            resolved("[Service Options]\nservice=install\n", false),
            ["fail: could not find option group `Service Options'"]
        );
    }

    /// The help pre-parse never knows the service group, which dcrd's
    /// `flags.NewParser(&cfg, helpOpts)` lacks on every platform; the
    /// other two parses have it wherever dcrd registers it.  On Windows
    /// the help pass used to take `--service` too, so `--bogus
    /// --service=stop` ran the command dcrd's pre-parse never reached.
    #[test]
    fn the_help_pre_parse_has_no_service_group() {
        assert!(find_long_for(&OPTIONS, ScanMode::IgnoreUnknown, "service").is_none());
        assert!(find_short_for(&OPTIONS, ScanMode::IgnoreUnknown, 's').is_none());
        for mode in [ScanMode::Plain, ScanMode::PassDoubleDash] {
            assert_eq!(
                find_long_for(&OPTIONS, mode, "service").is_some(),
                cfg!(windows)
            );
            assert_eq!(find_short_for(&OPTIONS, mode, 's').is_some(), cfg!(windows));
        }
        assert!(find_long_for(&OPTIONS, ScanMode::IgnoreUnknown, "help").is_some());
    }

    /// go-flags wraps the help by bytes, so a hyphenating split of a
    /// long non-ASCII default path cuts a character in two and dcrd
    /// writes the halves as they are.  The expected `--configfile`
    /// entry is `tools/helpgen`'s output with its home set to `/home/`
    /// and forty `é`; the render used to go through `from_utf8_lossy`,
    /// which turned each half into U+FFFD.
    #[test]
    fn help_keeps_the_bytes_of_a_split_character() {
        let home = format!("/home/{}", "é".repeat(40));
        let help = render_help("dcroxide", &home, 80);
        let e = "é".as_bytes();
        let pad = [b' '; 30];
        let mut expected =
            b"  -C, --configfile=           Path to configuration file (default:\n".to_vec();
        expected.extend_from_slice(&pad);
        expected.extend_from_slice(b"/home/");
        expected.extend_from_slice(&e.repeat(21));
        expected.extend_from_slice(b"\xc3-\n\n");
        expected.extend_from_slice(&pad);
        expected.extend_from_slice(b"\xa9");
        expected.extend_from_slice(&e.repeat(18));
        expected.extend_from_slice(b"/dcroxide.co-\n\n");
        expected.extend_from_slice(&pad);
        expected.extend_from_slice(b"nf)\n");
        assert!(
            help.windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "the split character must keep its raw bytes"
        );
        assert!(!help.windows(3).any(|w| w == "\u{fffd}".as_bytes()));
    }

    /// `stty size` prints `rows cols`; anything else, as from a
    /// descriptor that is not a terminal, leaves go-flags' eighty to the
    /// caller.  Zero columns come through as zero for `render_help`'s
    /// `getAlignmentInfo` rule.
    #[cfg(all(unix, not(target_os = "aix")))]
    #[test]
    fn stty_size_output_gives_the_columns() {
        assert_eq!(stty_size_columns(b"50 140\n"), Some(140));
        assert_eq!(stty_size_columns(b"0 0\n"), Some(0));
        assert_eq!(stty_size_columns(b""), None);
        assert_eq!(stty_size_columns(b"50\n"), None);
        assert_eq!(stty_size_columns(b"rows 50; columns 140;\n"), None);
        assert_eq!(stty_size_columns(b"50 70000\n"), None);
    }

    /// With no terminal on stdin -- the `TIOCGWINSZ` failure go-flags
    /// answers with eighty -- the probe gives eighty.
    #[cfg(all(unix, not(target_os = "aix")))]
    #[test]
    fn no_terminal_on_stdin_is_eighty_columns() {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "flags::tests::terminal_columns_child",
                "--nocapture",
            ])
            .env("DCROXIDE_TERMINAL_COLUMNS_CHILD", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the child test");
        assert!(out.status.success(), "{out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("columns=80;"), "{stdout}");
    }

    /// The child half of `no_terminal_on_stdin_is_eighty_columns`: it
    /// reports the probe over the stdin its parent gave it.
    #[cfg(all(unix, not(target_os = "aix")))]
    #[test]
    fn terminal_columns_child() {
        if std::env::var_os("DCROXIDE_TERMINAL_COLUMNS_CHILD").is_some() {
            println!("columns={};", terminal_columns());
        }
    }
}
