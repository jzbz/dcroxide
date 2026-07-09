// SPDX-License-Identifier: ISC
//! The dcroxide daemon binary — the runtime front-end of dcrd's
//! `dcrd.go` `dcrdMain`: build the configuration environment from the
//! real operating system, parse the command line through the ported
//! configuration pipeline, handle the help, version, and
//! debug-level-show exits with dcrd's exit codes, print the startup
//! banner, open the block database and initialize the chain state,
//! create the address manager, bind the peer-to-peer listeners and
//! serve inbound peers, and idle on a shutdown-signal listener until
//! interrupted, then stop accepting connections.
//!
//! The UTXO database, the connection manager (outbound dialing and
//! seeding), the sync manager, the RPC server, and the server-handler
//! dispatch that a served peer's messages are forwarded to arrive with
//! later pieces.  The rotating file-logging backend is likewise not yet
//! wired, so startup output goes to standard streams.

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_node::{
    Config, ConfigEnv, ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS, ERR_VERSION_REQUESTED,
    app_data_dir, load_config_from_argv, logo, parse_listeners, supported_subsystems, version,
};
use dcroxide_peer::{DEFAULT_IDLE_TIMEOUT, PING_INTERVAL};
use dcroxide_wire::ServiceFlag;

const APP_NAME: &str = "dcroxide";

fn main() -> ExitCode {
    // dcrd derives the application data directory with Go's GOOS; map
    // Rust's target OS onto the same names (notably macos -> darwin).
    let goos = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let home = app_data_dir(goos, "dcrd", false, &|name| std::env::var(name).ok());

    let env = ConfigEnv {
        default_home_dir: home,
        lookup_localhost: Box::new(|| {
            use std::net::ToSocketAddrs;
            match ("localhost", 0u16).to_socket_addrs() {
                Ok(addrs) => Ok(addrs.map(|a| a.ip().to_string()).collect()),
                Err(e) => Err(e.to_string()),
            }
        }),
        // Network interface enumeration is not yet wired, so
        // interface-name listeners do not expand; IP listeners are
        // unaffected.
        interface_by_name: Box::new(|_name| None),
        getenv: Box::new(|name| std::env::var(name).ok()),
        user_home: Box::new(|name| {
            if name.is_empty() {
                std::env::var("HOME").ok()
            } else {
                // Resolving other users' home directories is not yet
                // wired.
                None
            }
        }),
        rand_bytes: Box::new(|buf| getrandom::fill(buf).expect("system random source")),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    match load_config_from_argv(&args, &env) {
        Ok((cfg, _remaining_args)) => run(cfg),
        Err(msg) => match msg.as_str() {
            ERR_HELP_REQUESTED => {
                // The full go-flags help text is not yet generated.
                println!("Usage: {APP_NAME} [OPTIONS]");
                println!("(the full option help text is not yet generated)");
                ExitCode::SUCCESS
            }
            ERR_VERSION_REQUESTED => {
                println!("{APP_NAME} version {}", version::version_string());
                ExitCode::SUCCESS
            }
            ERR_SHOW_SUBSYSTEMS => {
                println!("Supported subsystems {}", supported_subsystems());
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("{other}");
                eprintln!("Use {APP_NAME} -h to show usage");
                ExitCode::FAILURE
            }
        },
    }
}

/// Announce startup and idle until a shutdown signal.  This is the
/// portion of `dcrdMain` after a successful configuration load and
/// before the block database and server are brought up.
fn run(cfg: Config) -> ExitCode {
    print!("{}", logo::startup_banner(version::version_string()));
    println!();

    log_info(&format!(
        "Version {} ({})",
        version::version_string(),
        std::env::consts::OS
    ));
    log_info(&format!("Home dir: {}", cfg.home_dir));
    if cfg.no_file_logging {
        log_info("File logging disabled");
    }

    // Load the block database and initialize the chain state, creating
    // the genesis state when the database is fresh.
    log_info("Loading block database from disk...");
    let chain = match open_chain(&cfg) {
        Ok(chain) => chain,
        Err(e) => {
            log_info(&format!("Unable to load block database: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let best = chain.best_snapshot();
    log_info(&format!(
        "Block database loaded with best block height {} hash {}",
        best.height, best.hash
    ));
    // Share the chain with the served peers' message handlers (dcrd's
    // server holding the chain the serverPeer callbacks consult).
    let chain = Arc::new(Mutex::new(chain));

    // Create the address manager and load any persisted peers (dcrd
    // `newServer`'s `addrmgr.New(cfg.DataDir)`).
    let mut addr_manager = AddrManager::new(Path::new(&cfg.data_dir));
    addr_manager.load_peers();
    let known_addrs = addr_manager.address_cache(|_: NetAddressType| true).len();
    log_info(&format!(
        "Address manager loaded {known_addrs} known address(es)"
    ));

    // Bind the peer-to-peer listeners and start serving inbound peers
    // unless listening is disabled (dcrd's server listeners).
    let listeners = if cfg.disable_listen {
        log_info("Listening for peer-to-peer connections is disabled");
        None
    } else {
        match start_listeners(&cfg, Arc::clone(&chain)) {
            Ok((runtime, connected)) => {
                let addrs: Vec<String> = runtime
                    .bound_addrs()
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();
                log_info(&format!(
                    "Serving peer-to-peer connections on {}",
                    if addrs.is_empty() {
                        "(no listeners bound)".to_string()
                    } else {
                        addrs.join(", ")
                    }
                ));
                Some((runtime, connected))
            }
            Err(e) => {
                log_info(&format!("Unable to start peer-to-peer listeners: {e}"));
                return ExitCode::FAILURE;
            }
        }
    };
    if cfg.disable_seeders {
        log_info("Peer discovery through seeders is disabled");
    }

    log_info(
        "The UTXO database, connection manager, sync manager, and RPC server \
         are not yet wired; serving inbound peers until a shutdown signal is \
         received.",
    );

    // Idle until an interrupt (SIGINT) or termination (SIGTERM) signal
    // arrives, mirroring dcrd's shutdown listener.
    let (tx, rx) = mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        log_info(&format!("unable to install signal handler: {e}"));
        return ExitCode::FAILURE;
    }
    let _ = rx.recv();

    // Disconnect the live peers and stop accepting new connections
    // (dcrd's server shutdown disconnecting all peers).
    if let Some((runtime, connected)) = listeners {
        connected.disconnect_all();
        runtime.shutdown();
    }

    log_info("Shutdown complete");
    ExitCode::SUCCESS
}

/// Bind the configured peer-to-peer listeners and start serving inbound
/// peers (dcrd `newServer`'s listener setup plus `inboundPeerConnected`).
/// Returns the listener runtime and the registry of the peers it serves.
fn start_listeners(
    cfg: &Config,
    chain: Arc<Mutex<Chain>>,
) -> Result<(ListenerRuntime, ConnectedPeers), String> {
    let params = &cfg.params.params;
    let template = PeerTemplate {
        net: params.net,
        // 0 selects the package's maximum protocol version.
        protocol_version: 0,
        // dcrd's `defaultServices`.
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: APP_NAME.to_string(),
        user_agent_version: version::version_string().to_string(),
        idle_timeout: Duration::from_nanos(DEFAULT_IDLE_TIMEOUT as u64),
        ping_interval: Duration::from_nanos(PING_INTERVAL as u64),
    };
    // The daemon-wide state the served peers' message handlers consult
    // (dcrd `newServer` deriving `minKnownWork` from the params).
    let server = Arc::new(ServerContext {
        chain,
        min_known_work: params.min_known_chain_work,
        disable_banning: cfg.disable_banning,
        ban_threshold: cfg.ban_threshold,
        whitelists: cfg.whitelists.clone(),
    });
    let connected = ConnectedPeers::new();
    let specs = parse_listeners(&cfg.listeners)?;
    let runtime = ListenerRuntime::start(
        &specs,
        inbound_peer_handler(template, connected.clone(), Some(server)),
    )
    .map_err(|e| e.to_string())?;
    Ok((runtime, connected))
}

/// Open (or create) the block database and initialize the chain state
/// (dcrd `dcrdMain`'s `loadBlockDB` plus the chain construction inside
/// `newServer`).  The block database lives at
/// `<datadir>/blocks_<dbtype>`; a fresh database creates the genesis
/// chain state.
fn open_chain(cfg: &Config) -> Result<Chain, String> {
    let params = &cfg.params.params;
    let db_path = Path::new(&cfg.data_dir).join(format!("blocks_{}", cfg.db_type));
    let opts = Options::new(&db_path, params.net.0);

    // Open the existing database, creating it when it does not yet
    // exist (dcrd's `database.Open` then `database.Create` fallback).
    let db = match Database::open(&opts) {
        Ok(db) => db,
        Err(e) if e.kind == ErrorKind::DbDoesNotExist => {
            std::fs::create_dir_all(&db_path)
                .map_err(|e| format!("unable to create database directory: {e}"))?;
            Database::create(&opts).map_err(|e| format!("unable to create database: {e}"))?
        }
        Err(e) => return Err(format!("unable to open database: {e}")),
    };

    // The assume-valid hash defaults to the network's hard-coded value
    // and is overridden by the command line when provided.
    let assume_valid = if cfg.assume_valid.is_empty() {
        params.assume_valid
    } else {
        cfg.assume_valid
            .parse::<Hash>()
            .map_err(|e| format!("invalid assumevalid hash: {e:?}"))?
    };

    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Chain::open(db, params, assume_valid, cfg.allow_old_forks, created_unix)
        .map_err(|e| format!("unable to initialize chain: {e:?}"))
}

/// A minimal startup log line until the rotating logging subsystem is
/// wired.
fn log_info(msg: &str) {
    println!("[INF] DCRD: {msg}");
}
