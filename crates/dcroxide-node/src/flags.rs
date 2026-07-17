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
pub const ENV_DEFAULTS: [(&str, &str, Option<&str>); 2] = [
    ("appdata", "DCRD_APPDATA", None),
    ("altdnsnames", "DCRD_ALT_DNSNAMES", Some(",")),
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
        Some("DCRD_APPDATA"),
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
        Some("DCRD_ALT_DNSNAMES"),
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
        "Use UPnP to map our listening port outside of NAT",
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
/// `[$ENV]` annotations) wrapped at eighty columns onto
/// continuation lines aligned to the description column, and the Help
/// Options tail.  dcrd's dedicated help pre-parse never adds the
/// Windows service group, so neither does this.
pub fn render_help(app_name: &str) -> String {
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

    let mut out = String::new();
    out.push_str("Usage:\n");
    out.push_str(&format!("  {app_name} [OPTIONS]\n"));
    out.push_str("\nApplication Options:\n");
    for spec in OPTIONS.iter() {
        let (_, desc, env) = HELP_DESCRIPTIONS
            .iter()
            .find(|(long, _, _)| *long == spec.long)
            .copied()
            .unwrap_or((spec.long, "", None));
        let mut text = desc.to_string();
        if let Some(env) = env {
            text.push_str(&format!(" [${env}]"));
        }
        push_entry(&mut out, &prefix(spec), &text, column);
    }
    out.push_str("\nHelp Options:\n");
    push_entry(&mut out, &help_prefix, "Show this help message", column);
    // dcrd prints the help error through Println, appending a final
    // blank line.
    out.push('\n');
    out
}

/// One help entry: the option column padded to the description start
/// (a value marker may squeeze the padding down to one space), then
/// the description through go-flags' `wrapText` — while the remaining
/// text is LONGER than the width, split at the last space within the
/// first width bytes (hyphenating when there is none), keeping an
/// exactly-width remainder whole — with continuation lines aligned
/// under the description column.  Descriptions are ASCII, matching
/// go-flags' byte indexing.
fn push_entry(out: &mut String, prefix: &str, description: &str, column: usize) {
    let width = 80usize.saturating_sub(column);
    out.push_str(prefix);
    let pad = column.saturating_sub(prefix.chars().count()).max(1);
    for _ in 0..pad {
        out.push(' ');
    }
    let indent = " ".repeat(column);
    let mut line = description.trim();
    let mut first = true;
    while line.len() > width {
        let (segment, rest) = match line[..width].rfind(' ') {
            Some(pos) => (line[..pos].trim_end().to_string(), line[pos..].trim_start()),
            None => {
                let cut = width.saturating_sub(1);
                (format!("{}-", &line[..cut]), &line[cut..])
            }
        };
        if !first {
            out.push_str(&indent);
        }
        out.push_str(&segment);
        out.push('\n');
        first = false;
        line = rest;
    }
    if !line.is_empty() {
        if !first {
            out.push_str(&indent);
        }
        out.push_str(line);
    }
    out.push('\n');
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

/// Find an option by its short name.
fn find_short(name: char) -> Option<&'static OptSpec> {
    find_short_in(&OPTIONS, name)
}

/// Find an option by its short name in the given registry.
fn find_short_in(registry: &'static [OptSpec], name: char) -> Option<&'static OptSpec> {
    find_short_with(registry, name, has_service_group(registry))
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

/// Find an option the way go-flags' INI parser matches names:
/// the exact Go field name wins over the exact long name, which
/// wins over the exact short name.
fn find_ini_name(name: &str) -> Option<&'static OptSpec> {
    OPTIONS
        .iter()
        .find(|o| o.field == name)
        .or_else(|| OPTIONS.iter().find(|o| o.long == name))
        .or_else(|| {
            let mut chars = name.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => find_short(c),
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
) -> (ScanState<'a>, Option<ScanError>) {
    let mut pass = ParsePass::default();
    scan_args_in(
        &OPTIONS,
        &mut |spec, value| set_option(cfg, &mut pass, spec, value),
        args,
        mode,
    )
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
            match find_long_in(registry, name) {
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
                && let Some(spec) = find_short_in(registry, first)
                && spec.kind != OptKind::Bool
            {
                argument = Some(rest);
                names = first.to_string();
            }
        }
    }

    let total = names.chars().count();
    for (i, c) in names.chars().enumerate() {
        let Some(spec) = find_short_in(registry, c) else {
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

/// Parse the INI config file like go-flags' `IniParser`, returning
/// the assignments to apply or the error text `loadConfig` would
/// see.  Application errors are reported by the caller with the
/// file/line context from the assignment.
pub(crate) fn parse_ini(content: &str, filename: &str) -> Result<Vec<IniAssignment>, String> {
    let ini_error = |line: usize, message: &str| format!("{filename}:{line}: {message}");
    let mut out = Vec::new();
    let mut section_ok = true;

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
            // The parser has a single group; section names resolve
            // case-insensitively against its description, and the
            // global (empty) section always matches.
            section_ok = name.to_lowercase() == "application options";
            if !section_ok {
                // go-flags reports unknown groups when their values
                // are reached (the sections map is keyed by name, so
                // the error fires during the apply walk); with a
                // single unknown section this is equivalent.
                return Err(format!("could not find option group `{name}'"));
            }
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

        if !section_ok {
            continue;
        }

        let Some(spec) = find_ini_name(name) else {
            return Err(ini_error(lineno, &format!("unknown option: {name}")));
        };

        // A bool option with an empty value is the bare-flag form.
        let value = if spec.kind == OptKind::Bool && value.is_empty() {
            None
        } else {
            Some(value)
        };

        out.push(IniAssignment {
            spec,
            value,
            line: lineno,
        });
    }

    Ok(out)
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
}
