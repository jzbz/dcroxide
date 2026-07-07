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

/// Find an option by its long name.
pub fn find_long(name: &str) -> Option<&'static OptSpec> {
    OPTIONS.iter().find(|o| o.long == name)
}

/// Find an option by its short name.
fn find_short(name: char) -> Option<&'static OptSpec> {
    OPTIONS.iter().find(|o| o.short == Some(name))
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
pub(crate) enum ScanError {
    /// An unknown option name.
    UnknownFlag(String),
    /// Any other parse failure.
    Other(String),
}

impl ScanError {
    pub(crate) fn message(self) -> String {
        match self {
            ScanError::UnknownFlag(name) => format!("unknown flag `{name}'"),
            ScanError::Other(msg) => msg,
        }
    }
}

/// The parser mode differences `loadConfig`'s three parses exhibit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanMode {
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

/// Apply a value to an option like go-flags `parseOption`: bare
/// bools reject arguments, values unquote when they look quoted,
/// and conversion failures wrap as marshal errors.
fn parse_option(
    cfg: &mut Config,
    pass: &mut ParsePass,
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
        set_option(cfg, pass, spec, None).map_err(|e| ScanError::Other(marshal_error(spec, &e)))?;
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
    set_option(cfg, pass, spec, Some(&arg)).map_err(|e| ScanError::Other(marshal_error(spec, &e)))
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
pub(crate) struct ScanState<'a> {
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
            match find_long(name) {
                Some(spec) => parse_option(cfg, &mut pass, &mut state, spec, true, argument),
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
            parse_shorts(cfg, &mut pass, &mut state, &names, argument)
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
    cfg: &mut Config,
    pass: &mut ParsePass,
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
                && let Some(spec) = find_short(first)
                && spec.kind != OptKind::Bool
            {
                argument = Some(rest);
                names = first.to_string();
            }
        }
    }

    let total = names.chars().count();
    for (i, c) in names.chars().enumerate() {
        let Some(spec) = find_short(c) else {
            return Err(ScanError::UnknownFlag(c.to_string()));
        };
        // Only the last short option may consume a separate
        // argument.
        let canarg = i + 1 == total;
        parse_option(cfg, pass, state, spec, canarg, argument.take())?;
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
