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
//! Served peers, inbound and dialed, run through the sync-manager
//! dispatch, and the connection manager keeps the permanent `--connect`
//! peers up while also dialing discovered peers from the address manager
//! (off simnet/regnet), which the HTTPS seeder bootstrap primes; the
//! chain carries a live UTXO cache flushed to the block database on
//! shutdown; and the JSON-RPC/websocket server binds unless `--norpc`.
//! Log lines render in slog's exact header format with their dcrd
//! subsystem tags, gated by `--debuglevel`, to stdout only — the
//! rotating file backend remains unwired.

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::{AddrManager, PeersLoad};
use dcroxide_blockchain::process::{Chain, OpenConfig};
use dcroxide_chainhash::Hash;
use dcroxide_connmgr::DEFAULT_RETRY_DURATION;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::outbound::{OutboundConfig, start_outbound};
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_node::{
    Config, ConfigEnv, ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS, ERR_VERSION_REQUESTED,
    app_data_dir, logo, parse_listeners, supported_subsystems, version,
};
use dcroxide_rpc::server::RpcCpuMiner;
use dcroxide_wire::ServiceFlag;

const APP_NAME: &str = "dcroxide";

/// The graceful-shutdown trigger the Windows service control handler
/// fires (dcrd's package-level `shutdownRequestChannel`): `run` stores
/// its interrupt flag and shutdown sender here once they exist, and a
/// stop arriving before then is latched for `run` to honor on arming.
static SERVICE_SHUTDOWN: std::sync::OnceLock<(dcroxide_indexers::Interrupt, mpsc::Sender<()>)> =
    std::sync::OnceLock::new();
static SERVICE_STOP_EARLY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Request the same graceful shutdown as an interrupt signal, from the
/// service control handler's thread.
#[cfg_attr(not(windows), allow(dead_code))] // Only the SCM path calls it.
fn request_service_shutdown() {
    SERVICE_STOP_EARLY.store(true, core::sync::atomic::Ordering::SeqCst);
    if let Some((interrupt, shutdown)) = SERVICE_SHUTDOWN.get() {
        request_process_shutdown(interrupt, shutdown);
    }
}

/// A shutdown request from one of the daemon's own subsystems -- the
/// `stop` RPC, the parent closing `--piperx`, the service control
/// manager -- as dcrd's `shutdownListener` takes one from its
/// `shutdownRequestChannel`: the first request cancels the daemon
/// context (the interrupt flag and the idle wait's channel here) and
/// logs `Shutdown requested.  Shutting down...`, and every later one
/// logs the `Already shutting down...` form, so an operator can tell
/// the process has not hung.  A request after a signal is a later one.
fn request_process_shutdown(interrupt: &dcroxide_indexers::Interrupt, shutdown: &mpsc::Sender<()>) {
    if interrupt.swap(true, core::sync::atomic::Ordering::SeqCst) {
        log_info("Shutdown requested.  Already shutting down...");
    } else {
        log_info("Shutdown requested.  Shutting down...");
    }
    let _ = shutdown.send(());
}

/// A termination signal, as dcrd's `shutdownListener` takes one from
/// its signal channel: the first cancels the daemon context and logs
/// `Received signal (<name>).  Shutting down...`, and every later one,
/// or one after a shutdown request, logs the `Already shutting down...`
/// form (`signal.go:34`, `:47-49`).  Only the Windows console close,
/// logoff and shutdown events arrive here, as `terminated`, the SIGTERM
/// Go's runtime turns them into (`runtime/os_windows.go`
/// `ctrlHandler`); ctrlc does not say which signal it caught, so the
/// others still cancel without a line.
#[cfg_attr(not(windows), allow(dead_code))] // Only the console handler calls it.
fn signal_process_shutdown(
    signal: &str,
    interrupt: &dcroxide_indexers::Interrupt,
    shutdown: &mpsc::Sender<()>,
) {
    let repeat = interrupt.swap(true, core::sync::atomic::Ordering::SeqCst);
    log_info(&signal_line(signal, repeat));
    let _ = shutdown.send(());
}

/// dcrd's `shutdownListener` line for a signal, the first or a repeat.
#[cfg_attr(not(windows), allow(dead_code))] // Only the console handler calls it.
fn signal_line(signal: &str, repeat: bool) -> String {
    if repeat {
        format!("Received signal ({signal}).  Already shutting down...")
    } else {
        format!("Received signal ({signal}).  Shutting down...")
    }
}

fn main() -> ExitCode {
    let code = process_main();
    // The daemon has shut down, the block database closed and the
    // service, if it ran as one, reported stopped: release a console
    // close, logoff or shutdown the console handler is holding (see
    // `run_node`).  Go's handler holds dcrd's until its `main` exits the
    // process.
    #[cfg(windows)]
    dcroxide_winsvc::shutdown_complete();
    code
}

/// dcrd's `main`: the process setup, then the daemon, under the service
/// control manager or interactively.
fn process_main() -> ExitCode {
    // Lift the soft descriptor limit to just below the hard one, which
    // the Go runtime's `syscall` package init does for dcrd before any
    // of its code runs (`syscall/rlimit.go`).  Without it the daemon
    // ran at whatever soft limit it inherited, 1024 under systemd.
    dcroxide_node::limits::raise_nofile_like_go_runtime();

    // Seed the process-wide CSPRNG before anything else, where Go runs
    // `crypto/rand`'s package `init` (`crypto/rand/prng.go:116-122`).
    // This is the one kernel read the daemon is allowed to die on, and
    // taking it here is what makes every later draw infallible -- the
    // handshake nonce on an accepted connection and the address shuffle
    // on a getaddr included.  Before the service dispatch below, since
    // Go's `init` also precedes `winServiceMain`.
    dcroxide_crypto::rand::init();

    // Up some limits (dcrd `main`, before the service dispatch).
    if let Err(e) = dcroxide_node::limits::set_limits() {
        eprintln!("failed to set limits: {e}");
        return ExitCode::FAILURE;
    }

    // Run under the service control manager when invoked as a Windows
    // service (dcrd `main` calling `winServiceMain` first); interactive
    // operation falls through.
    #[cfg(windows)]
    {
        match dcroxide_winsvc::service_main(
            Box::new(|| {
                let _ = real_main();
            }),
            Box::new(request_service_shutdown),
        ) {
            Ok(true) => return ExitCode::SUCCESS,
            Ok(false) => {}
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }
    real_main()
}

fn real_main() -> ExitCode {
    // dcrd derives the application data directory with Go's GOOS; map
    // Rust's target OS onto the same names (notably macos -> darwin).
    let goos = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    // A variable the configuration reads that a `String` cannot hold is
    // refused, as argv is, rather than read as unset; the load fails
    // with it before acting on it (`flags::getenv_utf8`).
    let env_refused = std::cell::RefCell::new(None);
    let getenv = |name: &str| dcroxide_node::flags::getenv_utf8(name, &env_refused);
    let home = app_data_dir(goos, "dcroxide", false, &getenv);

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
        getenv: Box::new(getenv),
        user_home: Box::new(|name| {
            if name.is_empty() {
                current_user_home()
            } else {
                // Resolving other users' home directories is not yet
                // wired.
                None
            }
        }),
        rand_bytes: Box::new(|buf| getrandom::fill(buf).expect("system random source")),
    };

    let args: Vec<String> = match dcroxide_node::flags::args_after_program() {
        Ok(args) => args,
        Err(bad) => {
            eprintln!(
                "invalid UTF-8 in command line argument: {}",
                bad.to_string_lossy()
            );
            eprintln!("Use {APP_NAME} -h to show usage");
            return ExitCode::FAILURE;
        }
    };
    // dcrd writes its parse-time notices to stderr as it reaches them
    // (the help pre-parse's go-flags error echo, a failed default
    // config creation, the deprecation and Tor-isolation notices), so
    // they print even when the load fails later.
    let mut notice = |line: &str| eprintln!("{line}");
    match dcroxide_node::config::load_config_from_argv_with_notices(
        &args,
        &env,
        &mut notice,
        &env_refused,
    ) {
        Ok((cfg, _remaining_args)) => run(cfg),
        // Perform a requested service command and exit (dcrd's
        // loadConfig hook, run straight after the version check on the
        // command-line pre-parse alone, so no config file or validation
        // error can block it; only Windows registers the option, and
        // dcrd prints any error and exits zero either way).
        #[cfg(windows)]
        Err(msg) if msg.starts_with(dcroxide_node::config::ERR_SERVICE_COMMAND_PREFIX) => {
            let command = &msg[dcroxide_node::config::ERR_SERVICE_COMMAND_PREFIX.len()..];
            if let Err(e) = dcroxide_winsvc::run_service_command(command) {
                eprintln!("{e}");
            }
            ExitCode::SUCCESS
        }
        Err(msg) => match msg.as_str() {
            ERR_HELP_REQUESTED => {
                // dcrd's help pre-parse prints the go-flags help to
                // stdout and exits zero.  The text is written as the
                // bytes go-flags wraps it into, at the width it reads
                // from the terminal on stdin.
                dcroxide_node::logging::write_stdout(&dcroxide_node::flags::render_help(
                    APP_NAME,
                    &env.default_home_dir,
                    dcroxide_node::flags::terminal_columns(),
                ));
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
                // dcrd leaves the usage line off the one error it wraps
                // in `errSuppressUsage` (`dcrd.go:44-50`).
                if dcroxide_node::config::error_shows_usage(other) {
                    eprintln!("Use {APP_NAME} -h to show usage");
                }
                ExitCode::FAILURE
            }
        },
    }
}

/// The current user's home directory as Go's `user.Current().HomeDir`
/// reports it to dcrd's `cleanAndExpandPath` for a leading `~`.
///
/// On the unixes other than Apple's, dcrd's cgo-free build reads the
/// password file: the entry for the real user id (`os/user`'s
/// `lookupUserId`), and only when the account has none does it fall
/// back to `$HOME`, which it then takes only alongside a non-empty
/// `$USER` (`lookup_stubs.go` `current`).
#[cfg(all(unix, not(target_vendor = "apple")))]
fn current_user_home() -> Option<String> {
    let uid = rustix::process::getuid().as_raw().to_string();
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| passwd_home(&passwd, &uid))
        .or_else(|| {
            // Go wants only a non-empty `$USER`, whatever its bytes.  A
            // `$HOME` that is not UTF-8 never gets here: `app_data_dir`
            // read it first, and the load refused it.
            let user = std::env::var_os("USER").is_some_and(|user| !user.is_empty());
            let home = std::env::var("HOME").ok().filter(|home| !home.is_empty());
            home.filter(|_| user)
        })
}

/// Elsewhere std's lookup stands in, and it is not quite Go's.  On Apple
/// platforms Go asks the directory service for the real user id's entry
/// (`getpwuid_r`, `cgo_lookup_unix.go` `current`) and nothing else,
/// where std takes `$HOME` first and asks the directory service only
/// without one.  On Windows Go takes the process token's profile
/// directory (`GetUserProfileDirectory`, `lookup_windows.go` `current`)
/// and nothing else, where std takes a non-empty `%USERPROFILE%` first.
/// The two differ only when that variable points away from the
/// account's own directory.
#[cfg(not(all(unix, not(target_vendor = "apple"))))]
fn current_user_home() -> Option<String> {
    std::env::home_dir().and_then(|home| home.into_os_string().into_string().ok())
}

/// The home directory of the password-file entry for `uid`, parsed as
/// Go's cgo-free `lookupUserId` does (`os/user/lookup_unix.go`): lines
/// are trimmed, blank and `#` lines skipped, and an entry must carry
/// six colons, the uid in its third field, a name that is not empty and
/// does not start with `+` or `-`, and integer uid and gid fields.
#[cfg(any(all(unix, not(target_vendor = "apple")), test))]
fn passwd_home(passwd: &str, uid: &str) -> Option<String> {
    let needle = format!(":{uid}:");
    passwd.lines().map(str::trim).find_map(|line| {
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        if !line.contains(&needle) || line.matches(':').count() < 6 {
            return None;
        }
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 6
            || parts[2] != uid
            || parts[0].is_empty()
            || parts[0].starts_with(['+', '-'])
            || parts[2].parse::<i64>().is_err()
            || parts[3].parse::<i64>().is_err()
        {
            return None;
        }
        Some(parts[5].to_string())
    })
}

/// Closes the block database however [`run_node`] returns once it has
/// opened it (dcrd's deferred `db.Close()` straight after `loadBlockDB`,
/// with its `lifetimeEventDBOpen` shutdown event and log line), so the
/// metadata committed since the last flush reaches disk on every path:
/// the index-drop exits, the startup failures and the shutdown-request
/// checks as well as the normal shutdown.  Held from right after the
/// open, it drops after everything built later.
struct BlockDbCloser {
    db: Database,
    pipe_notifier: dcroxide_node::pipeserve::PipeNotifier,
}

impl Drop for BlockDbCloser {
    fn drop(&mut self) {
        // Ensure the database is sync'd and closed on shutdown.
        self.pipe_notifier
            .notify_shutdown_event(dcroxide_node::ipc::LifetimeAction::DbOpen);
        log_info("Gracefully shutting down the block database...");
        if let Err(e) = self.db.close() {
            // dcrd discards the error; it is logged here so a close
            // whose flush failed does not pass silently.
            log_error(&format!("Unable to close the block database: {e}"));
        }
    }
}

/// Waits for the `--pipetx` writer to write what the daemon queued
/// before [`run_node`] returns, however it returns (see
/// `PipeNotifier::wait_written`).  Held from right after the notifier is
/// built, it drops after [`BlockDbCloser`], whose `DbOpen` shutdown
/// event is the last message queued.
struct PipeDrainOnExit(dcroxide_node::pipeserve::PipeNotifier);

impl Drop for PipeDrainOnExit {
    fn drop(&mut self) {
        self.0.wait_written(PIPE_DRAIN_TIMEOUT);
    }
}

/// How long the exit waits for the queued pipe messages to be written,
/// so a parent that stopped reading its pipe cannot hold the process up.
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Whether a shutdown has been requested -- an interrupt or termination
/// signal, the `stop` RPC, the service control manager, or the parent
/// closing `--piperx` (dcrd `shutdownRequested`, a non-blocking check of
/// the daemon context).
fn shutdown_requested(interrupt: &dcroxide_indexers::Interrupt) -> bool {
    interrupt.load(core::sync::atomic::Ordering::SeqCst)
}

/// Run the daemon and log `Shutdown complete` however it returns (dcrd's
/// `defer dcrdLog.Info("Shutdown complete")` at the top of `dcrdMain`,
/// which runs on the failure returns too).
fn run(cfg: Config) -> ExitCode {
    let code = run_node(cfg);
    log_info("Shutdown complete");
    code
}

/// Bring the daemon up and idle until a shutdown signal.  This is the
/// portion of `dcrdMain` after a successful configuration load: it opens
/// the block database and chain, creates the address manager, binds the
/// peer listeners, starts outbound dialing, seeding, and the RPC server,
/// then idles on the shutdown listener before tearing everything down.
fn run_node(cfg: Config) -> ExitCode {
    // Install the per-subsystem log levels the configuration parsed
    // (dcrd's loadConfig calling parseAndSetDebugLevels).
    dcroxide_node::logging::set_levels(cfg.log_levels.clone());
    // The RPC server's package logger (dcrd's `log.go:96`,
    // `rpcserver.UseLogger(rpcsLog)`).
    dcroxide_rpc::log::use_logger(dcroxide_node::logging::rpcs_log_sink());
    // The banner shares the log's sink and its tolerance of a stdout
    // that stopped taking writes.
    dcroxide_node::logging::write_stdout(
        logo::startup_banner(version::version_string()).as_bytes(),
    );
    // Logged rather than printed, and only here: dcrd logs these from
    // `loadConfig` through `dcrdLog`, so under DCRD -- the
    // previous-testnet directories found, then the missing config file
    // it defers until the rest of the configuration succeeds
    // (`config.go:1328-1352`).
    for warning in &cfg.log_warnings {
        log_warn(warning);
    }
    dcroxide_node::logging::write_stdout(b"\n");

    log_info(&format!(
        "Version {} ({})",
        version::version_string(),
        std::env::consts::OS
    ));
    // The zone every timestamp in this log is rendered in.  It is fixed
    // for the life of the process (see `logging::local_offset`), so saying
    // it once means a reader never has to infer it — and would have made
    // the mixed-zone bug this replaced obvious on sight.
    log_info(&format!(
        "Log timestamps are UTC{}",
        dcroxide_node::logging::local_offset_label()
    ));
    log_info(&format!("Home dir: {}", cfg.home_dir));
    if cfg.no_file_logging {
        log_info("File logging disabled");
    }

    if cfg.upnp {
        log_warn(
            "The --upnp option is no longer supported.  Make sure to manually map the \
             listening port on your router if you are behind NAT and wish to receive \
             inbound connections",
        );
    }

    // The shared interrupt flag standing in for dcrd's daemon context
    // cancellation, armed before the block database work so an
    // interrupt (SIGINT) or termination (SIGTERM) signal aborts the
    // long-running index drops and catch-up too (dcrd installs its
    // shutdown listener at the top of `dcrdMain`, before
    // `loadBlockDB`).  The channel carries the same signal to the
    // idle wait at the end of startup.
    let interrupt: dcroxide_indexers::Interrupt =
        Arc::new(core::sync::atomic::AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    // Publish the handles for the Windows service control handler and
    // honor a stop that arrived before they existed.
    let _ = SERVICE_SHUTDOWN.set((Arc::clone(&interrupt), shutdown_tx.clone()));
    if SERVICE_STOP_EARLY.load(core::sync::atomic::Ordering::SeqCst)
        && !shutdown_requested(&interrupt)
    {
        request_process_shutdown(&interrupt, &shutdown_tx);
    }
    {
        let signal_interrupt = Arc::clone(&interrupt);
        // Clone the sender for the signal handler so the original stays
        // owned by `run` and can be handed to the RPC server's
        // `request_shutdown` seam, letting the `stop` command trigger the
        // same graceful shutdown as SIGINT (dcrd's `requestProcessShutdown`
        // channel, which its signal handler also sends on).
        let signal_shutdown = shutdown_tx.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            // dcrd's `shutdownListener` logs `Received signal (%s).
            // Shutting down...` here, and the `Already shutting down...`
            // form for a repeat, but both name the signal, and ctrlc does
            // not report which of SIGINT, SIGTERM and SIGHUP arrived, so a
            // signal cancels without a line.  A later `stop` or pipe close
            // still logs as a repeat.
            signal_interrupt.store(true, core::sync::atomic::Ordering::SeqCst);
            let _ = signal_shutdown.send(());
        }) {
            log_error(&format!("unable to install signal handler: {e}"));
            return ExitCode::FAILURE;
        }
    }
    // On Windows a console close, logoff or shutdown ends the process as
    // soon as a console handler returns, and ctrlc's returns at once.
    // Go's runtime turns the three into SIGTERM and holds the event
    // while dcrd shuts down, so this handler requests the same shutdown
    // and holds the event until `main` reports the daemon has shut down
    // (`dcroxide_winsvc::install_console_handler`).  Registered after
    // ctrlc's, it is asked first, and passes Ctrl-C and Ctrl-Break on to
    // ctrlc.
    #[cfg(windows)]
    {
        let term_interrupt = Arc::clone(&interrupt);
        let term_shutdown = shutdown_tx.clone();
        if let Err(e) = dcroxide_winsvc::install_console_handler(Box::new(move || {
            signal_process_shutdown("terminated", &term_interrupt, &term_shutdown);
        })) {
            log_error(&format!("unable to install signal handler: {e}"));
            return ExitCode::FAILURE;
        }
    }

    // The pipe IPC lifecycle (dcrd `dcrdMain`'s lifetimeNotifier and
    // service control pipes): the writer serves --pipetx, the watcher
    // treats the parent closing --piperx as a shutdown request, the
    // lifetime events fire only under --lifetimeevents, and the bound
    // listener addresses only under --boundaddrevents.
    let pipe_notifier =
        dcroxide_node::pipeserve::new_pipe_notifier(cfg.pipe_tx, cfg.lifetime_events)
            .with_bound_addr_events(cfg.bound_addr_events);
    let _pipe_drain = PipeDrainOnExit(pipe_notifier.clone());
    if cfg.pipe_rx != 0 {
        let rx_interrupt = Arc::clone(&interrupt);
        let rx_shutdown = shutdown_tx.clone();
        dcroxide_node::pipeserve::start_pipe_rx(
            cfg.pipe_rx,
            Box::new(move || request_process_shutdown(&rx_interrupt, &rx_shutdown)),
        );
    }

    // Return now if a shutdown signal was triggered (dcrd's check ahead
    // of `loadBlockDB`).
    if shutdown_requested(&interrupt) {
        return ExitCode::SUCCESS;
    }

    // Load the block database (dcrd `loadBlockDB`, which reports the
    // load itself); the chain state is initialized over it later, as
    // part of creating the server.
    pipe_notifier.notify_startup_event(dcroxide_node::ipc::LifetimeAction::DbOpen);
    let db = match open_block_db(&cfg) {
        Ok(db) => db,
        Err(e) => {
            log_error(&format!("Unable to load block database: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let _db_closer = BlockDbCloser {
        db: db.clone(),
        pipe_notifier: pipe_notifier.clone(),
    };

    // Return now if a shutdown signal was triggered (dcrd checks after
    // `loadBlockDB` and again after `LoadUtxoDB`; the port keeps the
    // UTXO set in the block database, so the two are one check here).
    if shutdown_requested(&interrupt) {
        return ExitCode::SUCCESS;
    }

    // The indexers' package logger, which dcrd binds to INDX at init
    // (`log.go:90`, `indexers.UseLogger(indxLog)`): the drops below and
    // the index startup log through it.
    let indx_log = dcroxide_node::logging::indx_log_sink();

    // Always drop the legacy address index, drop any other indexes
    // and exit if requested, then drop the legacy v1 committed filter
    // index (dcrd `dcrdMain` between `loadBlockDB` and `newServer`;
    // the order matters because dropping the tx index also drops the
    // address index since it relied on it).
    if let Err(e) = dcroxide_indexers::drop_addr_index(&interrupt, &db, Some(&indx_log)) {
        log_error(&format!("{e}"));
        return ExitCode::FAILURE;
    }
    if cfg.drop_tx_index {
        if let Err(e) = dcroxide_indexers::drop_tx_index(&interrupt, &db, Some(&indx_log)) {
            log_error(&format!("{e}"));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    if cfg.drop_exists_addr_index {
        if let Err(e) = dcroxide_indexers::drop_exists_addr_index(&interrupt, &db, Some(&indx_log))
        {
            log_error(&format!("{e}"));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    if let Err(e) = dcroxide_indexers::drop_cf_index(&db, Some(&indx_log)) {
        log_error(&format!("{e}"));
        return ExitCode::FAILURE;
    }

    // Create the server: dcrd sends this event just ahead of
    // `newServer`, and everything from here to the startup-complete
    // event is `newServer`'s work -- the fee estimator, the chain load
    // with its UTXO catch-up replay, the index catch-up, the address
    // manager, the mempool and the listeners -- so a parent sees those
    // phases as the P2P server starting.
    pipe_notifier.notify_startup_event(dcroxide_node::ipc::LifetimeAction::P2pServer);

    // The shared fee estimator dcrd always builds in `newServer` and
    // hands to both the mempool (fed as transactions enter and leave)
    // and the RPC server (read by estimatesmartfee).  It starts
    // disabled until the first accepted block and empty each run — the
    // on-disk statistics store is deferred in the port.  dcrd builds it
    // ahead of the chain (`server.go:3959-3976`), and a configuration it
    // refuses -- `--minrelaytxfee=0` makes both bucket bounds zero, so
    // "maximum bucket fee should not be lower than minimum bucket fee"
    // -- fails `newServer`, which `dcrdMain` reports as it reports every
    // server construction failure.
    let fee_estimator = match dcroxide_node::fees::new_shared_estimator(cfg.min_relay_tx_fee_atoms)
    {
        Ok(estimator) => estimator,
        Err(e) => {
            log_error(&format!("Unable to start server: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // The chain is built inside dcrd's `newServer`, so a failure logs
    // as that one's does (`dcrd.go:243`): an interrupted startup catch-up
    // reads "Unable to start server: interrupt requested".  The loaded
    // tip is reported by the chain itself, in CHAN's closing "Chain
    // state: ..." line; dcrd logs nothing of its own after it.
    let chain = match open_chain(&cfg, db.clone(), &interrupt) {
        Ok(chain) => chain,
        Err(e) => {
            log_error(&format!("Unable to start server: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Share the chain with the served peers' message handlers (dcrd's
    // server holding the chain the serverPeer callbacks consult).
    let chain = Arc::new(Mutex::new(chain));

    // Create the enabled indexes and catch them up to the main chain
    // (dcrd `newServer`'s index block: the transaction index under
    // --txindex, the exists address index unless disabled, one
    // catch-up over the shared subscriber).  dcrd announces each index
    // under INDX just ahead of creating it.
    let indexes = if cfg.tx_index || !cfg.no_exists_addr_index {
        let logs = dcroxide_node::indexes::IndexLogs {
            indexers: Some(Arc::clone(&indx_log)),
            announce: Some(indx_log),
        };
        match dcroxide_node::indexes::start_indexes(
            Arc::clone(&interrupt),
            Arc::new(db.clone()),
            Arc::clone(&chain),
            cfg.params.params.clone(),
            cfg.tx_index,
            !cfg.no_exists_addr_index,
            &logs,
        ) {
            Ok(indexes) => Some(indexes),
            Err(e) => {
                log_error(&format!("Unable to start the indexes: {e}"));
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // The flat-file dump runs here and the daemon then stops: dcrd
    // puts it inside `newServer` after the index catch-up and returns
    // an error, so nothing binds a listener and the exit is non-zero
    // even on success (`server.go:4149-4157`).
    if !cfg.dump_blockchain.is_empty() {
        let tip_height = {
            let guard = chain.lock().expect("chain poisoned");
            guard.best_snapshot().height
        };
        let dump = dcroxide_node::blockdb::dump_block_chain(
            cfg.params.params.net.0,
            &cfg.dump_blockchain,
            tip_height,
            &|height| {
                chain
                    .lock()
                    .expect("chain poisoned")
                    .block_by_height(height)
            },
            &mut |subsystem, line| dcroxide_node::logging::info(subsystem, &line),
        );
        if let Err(e) = dump {
            log_error(&format!("Unable to start server: {e}"));
            return ExitCode::FAILURE;
        }
        log_error("Unable to start server: closing after dumping blockchain");
        return ExitCode::FAILURE;
    }

    // Return now if a shutdown signal was triggered: dcrd checks once
    // more when `newServer` returns, before `Run` accepts or dials
    // anything.  The chain load and the index catch-up above are the
    // long part of `newServer`; what follows here is quick, and starts
    // the threads dcrd's `Run` starts -- the RPC and peer listeners, the
    // dialer and the seeders among them -- so the check sits ahead of it.
    if shutdown_requested(&interrupt) {
        return ExitCode::SUCCESS;
    }

    // Create the address manager and load any persisted peers (dcrd
    // `newServer`'s `addrmgr.New(cfg.DataDir)`).
    let mut addr_manager = AddrManager::new(Path::new(&cfg.data_dir));
    // dcrd `loadPeers`'s three log lines.
    let peers_file = addr_manager.peers_file().display().to_string();
    match addr_manager.load_peers() {
        PeersLoad::Loaded(count) => dcroxide_node::logging::info(
            "AMGR",
            &format!("Loaded {count} addresses from file '{peers_file}'"),
        ),
        PeersLoad::Failed { err, remove_err } => {
            dcroxide_node::logging::error(
                "AMGR",
                &format!("Failed to parse file {peers_file}: {err}"),
            );
            if let Some(remove_err) = remove_err {
                dcroxide_node::logging::warn(
                    "AMGR",
                    &format!("Failed to remove corrupt peers file {peers_file}: {remove_err}"),
                );
            }
        }
    }
    // Share the manager with the served peers' addr exchange.
    let addr_manager = Arc::new(Mutex::new(addr_manager));
    // Dump the address book periodically for crash resilience (the
    // ticker half of dcrd addrmgr's addressHandler; the final save
    // still runs at shutdown).
    let address_dump = dcroxide_node::seeding::start_address_dump(
        Arc::clone(&addr_manager),
        dcroxide_node::seeding::DUMP_ADDRESS_INTERVAL,
    );

    // Build the daemon-wide server state shared by every peer, inbound
    // or outbound (dcrd's single `server`).
    // The shared transaction memory pool over the chain (dcrd
    // `newServer` building the pool before the rest of the server).
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &cfg.params.params,
        cfg.accept_non_std,
        cfg.max_orphan_txs,
        cfg.min_relay_tx_fee_atoms,
        cfg.allow_old_votes,
        !cfg.mining_addrs.is_empty(),
    );
    // Feed the fee estimator built above from the pool.
    tx_pool
        .lock()
        .expect("tx pool mutex poisoned")
        .set_fee_estimator(Box::new(dcroxide_node::fees::NodeFeeEstimatorSink::new(
            Arc::clone(&fee_estimator),
        )));
    // The pool records every added unconfirmed transaction's
    // addresses in the exists address index when it is enabled
    // (dcrd's mempool config carrying `ExistsAddrIndex`).
    if let Some(exists) = indexes
        .as_ref()
        .and_then(|indexes| indexes.exists_addr_index.as_ref())
    {
        tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .set_exists_addr_index(Box::new(
                dcroxide_node::indexes::NodeUnconfirmedAddrIndexer::new(Arc::clone(exists)),
            ));
    }
    // The websocket notification manager exists whenever the RPC
    // server will run, so the peer handlers can announce accepted
    // transactions (dcrd's nil rpcServer checks).
    let ntfn = if cfg.disable_rpc {
        None
    } else {
        Some(dcroxide_node::websocket::NodeNtfnMgr::with_max_websockets(
            cfg.rpc_max_websockets.max(0) as usize,
        ))
    };
    let (server, connected, template, stall_timer) = build_server(
        &cfg,
        Arc::clone(&chain),
        Arc::clone(&addr_manager),
        Arc::clone(&tx_pool),
        ntfn.clone(),
    );

    // Track user-submitted transactions and periodically rebroadcast
    // them until they make it into a block (dcrd `server.Run`
    // launching `rebroadcastHandler` only when the RPC server runs —
    // only RPC submissions are ever tracked).
    let rebroadcaster = if cfg.disable_rpc {
        None
    } else {
        Some(dcroxide_node::rebroadcast::start_rebroadcaster(
            Arc::clone(&chain),
            server.sync_peers.clone(),
            Arc::clone(&server.recently_advertised),
        ))
    };

    // The mining policy the background template generator and the
    // getwork seam share (dcrd's mining `Policy`).
    let mining_policy = dcroxide_mining::MiningPolicy {
        block_max_size: cfg.block_max_size,
        tx_min_free_fee: cfg.min_relay_tx_fee_atoms,
        aggressive_mining: !cfg.non_aggressive,
    };

    // Feed the chain's events into the daemon handler as blocks
    // connect, disconnect, and reorganize (dcrd installing
    // handleBlockchainNotification as its blockchain notification
    // callback inside `newServer`, before any peer activity): the
    // mempool maintenance and index notifications run whether or not
    // the RPC server does — only the websocket sends need the
    // manager — and the sync adapter drains the handler's deferred
    // work after each processing call.
    // The netsync is-current gate the relay, estimator-enable, and
    // generator paths consult (dcrd wiring `s.syncManager.IsCurrent`
    // into those sites rather than the chain's own view).
    let sync_gate = dcroxide_node::sync::SyncGate::from_manager(
        &server
            .sync_manager
            .lock()
            .expect("sync manager mutex poisoned"),
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        ntfn.clone(),
        cfg.params.params.clone(),
        cfg.allow_unsynced_mining,
        sync_gate.clone(),
        Some(Arc::clone(&server.mix_pool)),
        Arc::clone(&tx_pool),
        server.sync_peers.clone(),
        Arc::clone(&server.recently_advertised),
    );
    // The drained block events also feed the subscribed indexes
    // (dcrd's handler notifying `s.indexSubscriber`).
    if let Some(indexes) = &indexes {
        handler.set_index_subscriber(Arc::clone(&indexes.subscriber));
    }
    // Confirmed transactions feed the recently-confirmed filter the
    // sync manager consults, and — when the RPC server runs — remove
    // their rebroadcast entries and trigger the block-change prunes
    // (dcrd `TransactionConfirmed` and the `rpcServer != nil` gates).
    handler.set_recently_confirmed(
        server
            .sync_manager
            .lock()
            .expect("sync manager mutex poisoned")
            .recently_confirmed_txns(),
    );
    if let Some(rebroadcaster) = &rebroadcaster {
        handler.set_rebroadcast(rebroadcaster.sink());
    }
    // Every connected block feeds the fee estimator, and the first
    // accepted block enables it (dcrd's `s.feeEstimator` driven from
    // the chain notifications, run whether or not the RPC server does).
    handler.set_fee_estimator(Arc::clone(&fee_estimator));

    // Run the background block template generator when mining addresses
    // are configured (dcrd only constructs `s.bg` and serves getwork
    // with `--miningaddr` set): a dedicated thread drives the
    // regeneration state machine over the live chain and mempool,
    // feeding the getwork RPC and the websocket work notifications.  It
    // starts after the chain handler exists so its drain hook can run
    // the handler's deferred maintenance for reorgs the generator
    // itself initiates (which the sync adapter's post-process drain
    // never covers).
    let generator = if cfg.mining_addrs.is_empty() {
        None
    } else {
        let drain_handler = handler.clone();
        let drain_chain = Arc::clone(&chain);
        let drain_hook: Box<dyn Fn() + Send> = Box::new(move || {
            drain_handler.drain_pending(&drain_chain, now_unix());
        });
        Some(dcroxide_node::bgtemplate::start_generator(
            Arc::clone(&chain),
            Arc::clone(&tx_pool),
            cfg.params.params.clone(),
            cfg.mining_addrs.clone(),
            mining_policy.clone(),
            cfg.mining_time_offset,
            cfg.allow_unsynced_mining,
            sync_gate.clone(),
            ntfn.clone(),
            Some(drain_hook),
        ))
    };

    // Forward accepted votes from the pool into the generator (dcrd's
    // mempool `OnVoteReceived` firing `s.bg.VoteReceived`).
    if let Some(generator) = &generator {
        tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .set_vote_receiver(Box::new(dcroxide_node::bgtemplate::NodeVoteReceiver::new(
                generator.sink(),
            )));
    }

    // Forward accepted treasury spends from the pool to the websocket
    // notification manager (dcrd's mempool `OnTSpendReceived` firing
    // `s.rpcServer.NotifyTSpend`, guarded there by a non-nil rpc server
    // exactly as this is guarded by the manager's presence).
    if let Some(ntfn) = &ntfn {
        tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .set_tspend_receiver(Box::new(dcroxide_node::websocket::NodeTSpendReceiver::new(
                ntfn.clone(),
            )));
    }

    // The chain's block and reorganization events feed the background
    // template generator (dcrd's chain notifications driving `s.bg`).
    if let Some(generator) = &generator {
        handler.set_generator(generator.sink());
    }
    {
        let callback_handler = handler.clone();
        chain
            .lock()
            .expect("chain mutex poisoned")
            .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
    }
    // The RPC chain adapter drains the same handler after the manual
    // invalidateblock/reconsiderblock reorganizations (dcrd runs
    // `handleBlockchainNotification` whichever caller moved the tip).
    let rpc_ntfn_handler = handler.clone();
    server
        .sync_manager
        .lock()
        .expect("sync manager mutex poisoned")
        .chain_mut()
        .set_chain_ntfn_handler(handler);

    // The CPU miner (dcrd `s.cpuMiner`), built and started whenever a
    // block template generator runs — i.e. mining addresses are
    // configured — so it can mine under `--norpc` too, exactly as dcrd
    // runs `go s.cpuMiner.Run(ctx)` unconditionally in `newServer`.  The
    // background threads start idle; `--generate` kicks off continuous
    // mining with the default worker count (dcrd's `if cfg.Generate {
    // SetNumWorkers(-1) }`).  The RPC-facing `NodeCpuMiner` moves into
    // the RPC server config below; the `MinerRuntime` stays here to be
    // shut down at the end.
    let mut cpu_miner: Option<dcroxide_node::cpuminer::NodeCpuMiner> = None;
    let mut miner_runtime: Option<dcroxide_node::cpuminer::MinerRuntime> = None;
    if let Some(generator) = &generator {
        let mut miner = dcroxide_node::cpuminer::NodeCpuMiner::new(
            generator.current_handle(),
            generator.subscribers_handle(),
            generator.sink(),
            Arc::clone(&chain),
            Arc::clone(&server.sync_manager),
            Arc::clone(&tx_pool),
            cfg.params.params.clone(),
            mining_policy.clone(),
            cfg.mining_time_offset,
            server.sync_peers.clone(),
            cfg.sim_net || cfg.reg_net,
        );
        let runtime = miner.start();
        if cfg.generate {
            miner.set_num_workers(-1);
        }
        cpu_miner = Some(miner);
        miner_runtime = Some(runtime);
    }

    // The outbound driver's command channel is created ahead of the RPC
    // server so its control handle can back the manual peer-control
    // RPCs (`addnode`, `node connect`/`remove`); the driver itself
    // starts below with the other peer activity.  Their targets resolve
    // through the configured routing (dcrd's dcrdLookup), so a proxied
    // daemon resolves them over Tor.
    let outbound_channel = dcroxide_node::outbound::outbound_channel_with_dialer(
        dcroxide_node::socks::NodeDialer::from_config(&cfg),
    );

    // Serve the JSON-RPC endpoint (dcrd's RPC server): TLS over the
    // generated certificate pair by default, plain HTTP under the
    // localhost-validated --notls.  This runs before the peer-to-peer
    // listeners come up, like dcrd's rpc server existing before
    // `server.Run` starts any peer activity (the chain notification
    // callback installs even earlier, above, with the handler).
    // The bound RPC addresses are kept for the --boundaddrevents pipe
    // messages, which follow the peer-to-peer ones below.
    let mut rpc_bound_addrs: Vec<std::net::SocketAddr> = Vec::new();
    let rpc_listener = if cfg.disable_rpc {
        dcroxide_node::logging::info("RPCS", "RPC service is disabled");
        None
    } else {
        let transport = if cfg.disable_tls {
            dcroxide_node::rpcrun::RpcTransport::Plain
        } else {
            // dcrd warns when additional names are asked for but the
            // certificates already exist, because they will not be
            // included (`server.go:3839-3845`).
            if !cfg.alt_dns_names.is_empty()
                && (dcroxide_node::config::file_exists(&cfg.rpc_cert)
                    || dcroxide_node::config::file_exists(&cfg.rpc_key))
            {
                dcroxide_node::logging::warn(
                    "RPCS",
                    "Additional DNS names specified when TLS certificates already exist \
                     will NOT be included:",
                );
                dcroxide_node::logging::warn(
                    "RPCS",
                    &format!(
                        "- In order to create TLS certs that include the additional DNS \
                         names, delete {:?} and {:?} and restart the server",
                        cfg.rpc_key, cfg.rpc_cert
                    ),
                );
            }
            // The certificate's subject alternative names come from
            // --altdnsnames, which is what dcrd passes to genCertPair;
            // --externalip is the P2P advertisement list and has no
            // business in a TLS certificate.
            let config = dcroxide_node::rpcrun::load_or_generate_cert_pair(
                Path::new(&cfg.rpc_cert),
                Path::new(&cfg.rpc_key),
                &cfg.alt_dns_names,
                match dcroxide_node::config::tls_curve(&cfg.tls_curve) {
                    Ok(dcroxide_node::config::TlsCurve::P521) => dcroxide_certgen::Curve::P521,
                    // Validated during configuration, so the error arm
                    // is unreachable; the default is dcrd's default.
                    _ => dcroxide_certgen::Curve::P256,
                },
            )
            .and_then(|(_cert, _key)| {
                // The pair is on disk by now, generated above when it was
                // absent.  From here the paths are what matter, not those
                // bytes: the configuration is rebuilt from the files
                // whenever they change, so a rotated certificate is served
                // without a restart.  dcrd does the same, calling
                // `genCertPair` and then handing `makeReloadableTLSConfig`
                // the three paths (`server.go:3840-3862`).
                //
                // Client certificate authentication demands the CA roots;
                // dcrd reads the file in `newTLSConfig` and fails startup
                // when it is missing or empty, and watches it thereafter.
                let client_cas =
                    if cfg.rpc_auth_type == dcroxide_node::config::AUTH_TYPE_CLIENT_CERT {
                        Some(Path::new(&cfg.rpc_client_cas))
                    } else {
                        None
                    };
                dcroxide_node::rpcrun::reloadable_tls_config(
                    Path::new(&cfg.rpc_cert),
                    Path::new(&cfg.rpc_key),
                    client_cas,
                    dcroxide_node::rpcrun::RPC_TLS_MIN_RELOAD_CHECK_DELAY,
                )
            });
            match config {
                Ok(config) => dcroxide_node::rpcrun::RpcTransport::Tls(config),
                Err(e) => {
                    log_error(&format!("Unable to set up RPC TLS: {e}"));
                    return ExitCode::FAILURE;
                }
            }
        };
        // The index seams over the live indexes (dcrd assigning
        // `s.txIndex` and `s.existsAddrIndex` to the rpcserver
        // config).
        let tx_indexer = indexes
            .as_ref()
            .and_then(|indexes| indexes.tx_index.as_ref().map(|index| (index, indexes)))
            .map(|(index, indexes)| {
                Box::new(dcroxide_node::indexes::NodeRpcTxIndexer::new(
                    Arc::clone(index),
                    Arc::clone(&indexes.queryer),
                )) as Box<dyn dcroxide_rpc::server::RpcTxIndexer + Send + Sync>
            });
        let exists_addresser = indexes
            .as_ref()
            .and_then(|indexes| {
                indexes
                    .exists_addr_index
                    .as_ref()
                    .map(|index| (index, indexes))
            })
            .map(|(index, indexes)| {
                Box::new(dcroxide_node::indexes::NodeRpcExistsAddresser::new(
                    Arc::clone(index),
                    Arc::clone(&indexes.queryer),
                ))
                    as Box<dyn dcroxide_rpc::server::RpcExistsAddresser + Send + Sync>
            });
        // The getwork seam over the running generator (dcrd assigning
        // `s.bg` to the rpcserver config's `BlockTemplater`); `None`
        // when no mining addresses are configured, so getwork errors
        // with dcrd's "no payment addresses" message.
        let block_templater = generator.as_ref().map(|generator| {
            Box::new(dcroxide_node::bgtemplate::NodeRpcBlockTemplater::new(
                generator.current_handle(),
                generator.subscribers_handle(),
                generator.sink(),
                Arc::clone(&chain),
                Arc::clone(&tx_pool),
                cfg.params.params.clone(),
                mining_policy.clone(),
                cfg.mining_time_offset,
            )) as Box<dyn dcroxide_rpc::server::RpcBlockTemplater + Send + Sync>
        });
        // Hand the already-built CPU miner to the RPC server so
        // `generate`/`setgenerate`/`getmininginfo` reach it (dcrd
        // assigning `s.cpuMiner`); the idle stand-in when no mining
        // addresses are configured, so `generate` answers dcrd's "no
        // payment addresses" error.
        let cpu_miner: Box<dyn dcroxide_rpc::server::RpcCpuMiner + Send + Sync> =
            match cpu_miner.take() {
                Some(miner) => Box::new(miner),
                None => Box::new(dcroxide_node::rpcrun::IdleCpuMiner),
            };
        // The `stop` RPC requests the same graceful shutdown as an
        // interrupt.  Only its first request reaches the shutdown
        // listener: dcrd's `newServer` forwards one receive from the
        // server's `requestProcessShutdown` channel to
        // `shutdownRequestChannel`, and `handleStop`'s non-blocking send
        // finds no receiver after that.
        let request_shutdown: Box<dyn Fn() + Send + Sync> = {
            let interrupt = Arc::clone(&interrupt);
            let shutdown_tx = shutdown_tx.clone();
            let forwarded = core::sync::atomic::AtomicBool::new(false);
            Box::new(move || {
                if !forwarded.swap(true, core::sync::atomic::Ordering::SeqCst) {
                    request_process_shutdown(&interrupt, &shutdown_tx);
                }
            })
        };
        let mut rpc_srv = dcroxide_rpc::server::Server::new(rpc_config(
            &cfg,
            Arc::clone(&chain),
            rpc_ntfn_handler,
            connected.clone(),
            Arc::clone(&server.sync_manager),
            Arc::clone(&server.net_totals),
            Arc::clone(&tx_pool),
            server.sync_peers.clone(),
            Arc::clone(&server.recently_advertised),
            rebroadcaster
                .as_ref()
                .expect("the rebroadcaster exists when RPC is enabled")
                .sink(),
            ntfn.clone()
                .expect("the manager exists when RPC is enabled"),
            tx_indexer,
            exists_addresser,
            db.clone(),
            block_templater,
            Arc::clone(&fee_estimator),
            cpu_miner,
            Arc::clone(&addr_manager),
            request_shutdown,
            outbound_channel.control(),
            Arc::clone(&server.mix_pool),
        ));
        // Install the websocket notification manager (dcrd's
        // wsNotificationManager) and start its delivery thread over
        // the server.
        let ntfn = ntfn
            .clone()
            .expect("the manager exists when RPC is enabled");
        rpc_srv.ntfn_mgr = Box::new(ntfn.clone());
        let rpc_server = Arc::new(rpc_srv);
        let ntfn_thread = ntfn.start(Arc::clone(&rpc_server));
        match dcroxide_node::rpcrun::start_rpc_listener(
            &cfg.rpc_listeners,
            rpc_server,
            transport,
            ntfn.clone(),
            cfg.rpc_max_clients.max(0) as usize,
        ) {
            Ok(listener) => {
                // One line per listener, as dcrd's `Run` logs from each
                // listener's serving goroutine.
                for addr in listener.bound_addrs() {
                    dcroxide_node::logging::info(
                        "RPCS",
                        &format!("RPC server listening on {addr}"),
                    );
                }
                rpc_bound_addrs = listener.bound_addrs().to_vec();
                Some((listener, ntfn, ntfn_thread))
            }
            // dcrd fails `newServer` when the listen addresses do not
            // parse or none of them bound, and `dcrdMain` reports that as
            // it reports every other server construction failure.
            Err(e) => {
                log_error(&format!("Unable to start server: {e}"));
                return ExitCode::FAILURE;
            }
        }
    };

    // dcrd cannot start at all with a negative --maxpeers: `newServer`
    // builds its relay queues as `make(chan relayMsg, cfg.MaxPeers)`
    // (`server.go:3931-3932`) and Go panics on a negative capacity, with
    // nothing to recover it.  Refuse here rather than boot with no peer
    // limit, which is what the faithful `uint32` casts below would
    // otherwise produce.  See QK-0014.
    //
    // dcrd reaches its panic just after `initListeners`, so it binds the
    // peer-to-peer listeners and then dies; refusing before binding them
    // is the one ordering difference, and it is not observable beyond a
    // socket that upstream holds for a few microseconds.
    if !dcroxide_node::max_peers_is_startable(cfg.max_peers) {
        // Upstream dies the same way at both ends of the range -- one
        // `panic: makechan: size out of range` -- but which end it was
        // is worth telling apart for whoever reads the log.
        let bound = if cfg.max_peers < 0 {
            String::from("may not be less than 0")
        } else {
            format!(
                "may not be {} or greater, the capacity dcrd's relay queue is refused at",
                dcroxide_node::MAX_PEERS_MAKECHAN_LIMIT
            )
        };
        log_error(&format!(
            "The maxpeers option {bound} -- parsed [{}]",
            cfg.max_peers
        ));
        return ExitCode::FAILURE;
    }

    // The connection manager decision core (dcrd 2.2's connmgr.New in
    // newServer): the policy limits, the CIDR whitelist matcher, and
    // the network default port for address selection.
    let default_port: u16 = cfg.params.params.default_port.parse().unwrap_or(0);
    let whitelists = cfg.whitelists.clone();
    let conn_manager: dcroxide_node::outbound::SharedConnManager = {
        let mut csprng = dcroxide_connmgr::SystemCsprng::default();
        Arc::new(std::sync::Mutex::new(dcroxide_connmgr::ConnManager::new(
            dcroxide_connmgr::ManagerConfig {
                default_port,
                // dcrd casts both straight to uint32 (`server.go:4283-4284`:
                // `MaxNormalConns: uint32(cfg.MaxPeers)`,
                // `MaxConnsPerHost: uint32(cfg.MaxSameIP)`), which truncates
                // rather than clamping.  Neither dcrd nor this port validates
                // the two flags, so a negative reaches here and must read as
                // the huge positive dcrd sees, not as zero.
                max_normal_conns: cfg.max_peers as u32,
                max_conns_per_host: cfg.max_same_ip as u32,
                target_outbound: dcroxide_node::server_target_outbound(cfg.max_peers),
                retry_duration_nanos: DEFAULT_RETRY_DURATION,
                is_whitelisted: Box::new(move |addr| {
                    whitelists.iter().any(|net| net.contains(&addr.ip))
                }),
            },
            &mut csprng,
        )))
    };

    // Bind the peer-to-peer listeners and start serving inbound peers
    // unless listening is disabled (dcrd's server listeners).
    let runtime = if cfg.disable_listen {
        dcroxide_node::logging::info("SRVR", "Listening for peer-to-peer connections is disabled");
        None
    } else {
        match start_listeners(
            &cfg,
            &template,
            connected.clone(),
            Arc::clone(&server),
            Arc::clone(&conn_manager),
        ) {
            // Each listener announces itself as dcrd connmgr's
            // `listenHandler` does, "Server listening on <addr>".
            Ok(runtime) => {
                // The rest of dcrd's `initListeners`: each bound listener
                // is announced to the parent process under
                // --boundaddrevents, then the node's own addresses are
                // registered so the handshake can advertise one and
                // getnetworkinfo can list them -- every --externalip,
                // or else every bound listener.
                let bound: Vec<String> = runtime
                    .bound_addrs()
                    .iter()
                    .map(dcroxide_node::listenaddrs::go_tcp_addr_string)
                    .collect();
                for addr in &bound {
                    pipe_notifier.notify_p2p_address(addr);
                }
                if let Err(e) = dcroxide_node::listenaddrs::add_listener_local_addresses(
                    &addr_manager,
                    &cfg.external_ips,
                    cfg.params.params.default_port,
                    &bound,
                    ServiceFlag::NODE_NETWORK,
                    &*server.lookup,
                    &|| Ok(dcroxide_node::rpcrun::system_interface_addrs()),
                    wall_clock_unix(),
                ) {
                    log_error(&format!("Unable to start server: {e}"));
                    return ExitCode::FAILURE;
                }
                Some(runtime)
            }
            // dcrd's `newServer` failure as `dcrdMain` reports it:
            // nothing bound ("no valid listen address") or a listener
            // that does not parse.
            Err(e) => {
                log_error(&format!("Unable to start server: {e}"));
                return ExitCode::FAILURE;
            }
        }
    };
    // dcrd's `setupRPCListeners` announces each bound RPC listener too,
    // later in `newServer` than `initListeners`, so these follow the
    // peer-to-peer addresses.
    for addr in &rpc_bound_addrs {
        pipe_notifier.notify_rpc_address(&dcroxide_node::listenaddrs::go_tcp_addr_string(addr));
    }

    // Open outbound connections through the connection manager: the
    // permanent `--connect` peers when configured, otherwise automatic
    // dialing from the address manager.  dcrd installs `newAddressFunc`
    // only when there are no `--connect` peers AND the network is neither
    // simnet nor regnet — those networks stay in connect-only mode and
    // never dial discovered peers (dcrd server.go: `!cfg.SimNet &&
    // !cfg.RegNet && len(cfg.ConnectPeers) == 0`).
    let get_new_address = if !cfg.sim_net && !cfg.reg_net && cfg.connect_peers.is_empty() {
        // The address types the automatic dialer may draw (dcrd
        // server.go's `filter` over `GetAddress`): Tor addresses
        // require .onion reachability through a configured proxy.
        let onion_reachable =
            !cfg.no_onion && (!cfg.proxy.is_empty() || !cfg.onion_proxy.is_empty());
        let filter = move |addr_type: dcroxide_addrmgr::NetAddressType| match addr_type {
            dcroxide_addrmgr::NetAddressType::IPv4 | dcroxide_addrmgr::NetAddressType::IPv6 => true,
            dcroxide_addrmgr::NetAddressType::TorV3 => onion_reachable,
            _ => false,
        };
        // dcrd 2.2's newAddressFunc: the manager candidate and its
        // last attempt time; the group spreading, recency, and port
        // preferences live in the connection manager's selection.
        let source_mgr = Arc::clone(&addr_manager);
        Some(Box::new(move || {
            let candidate = source_mgr
                .lock()
                .expect("addrmgr mutex poisoned")
                .get_address(filter);
            let Some(candidate) = candidate else {
                return Err("no valid connect address".to_string());
            };
            let candidate = candidate.lock().expect("known address poisoned");
            Ok((
                candidate.net_address().clone(),
                candidate.last_attempt().unwrap_or_default(),
            ))
        }) as dcroxide_node::outbound::AddressSource)
    } else {
        dcroxide_node::logging::info(
            "SRVR",
            &format!(
                "Connecting to {} permanent peer(s)",
                cfg.connect_peers.len()
            ),
        );
        None
    };
    // Register the persistent peers (dcrd newServer: ConnectPeers,
    // else AddPeers, each resolved through addrStringToNetAddr and
    // added via AddPersistent — any failure fails the start).
    let persistent_targets = if !cfg.connect_peers.is_empty() {
        &cfg.connect_peers
    } else {
        &cfg.add_peers
    };
    let mut persistent = Vec::with_capacity(persistent_targets.len());
    let target_dialer = dcroxide_node::socks::NodeDialer::from_config(&cfg);
    for addr in persistent_targets {
        let added = dcroxide_node::outbound::addr_string_to_connect_target(addr, &target_dialer)
            .and_then(|target| {
                dcroxide_node::outbound::add_persistent_target(
                    &mut conn_manager.lock().expect("connmgr mutex poisoned"),
                    target,
                )
            });
        match added {
            Ok(entry) => persistent.push(entry),
            Err(e) => {
                dcroxide_node::logging::error(
                    "SRVR",
                    &format!("Unable to add persistent peer {addr}: {e}"),
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let connector = start_outbound(
        OutboundConfig {
            template: template.clone(),
            connected: connected.clone(),
            server: Some(Arc::clone(&server)),
            manager: Arc::clone(&conn_manager),
            dial_timeout: Duration::from_nanos(cfg.dial_timeout_nanos as u64),
            // The configured dial routing: direct, or SOCKS5 with the
            // onion rules (dcrd's dcrdDial closures).
            dialer: dcroxide_node::socks::NodeDialer::from_config(&cfg),
            persistent,
            get_new_address,
            // Record dial attempts against the address manager off simnet and
            // regnet, matching where dcrd installs attemptDcrdDial.
            addr_manager: if !cfg.sim_net && !cfg.reg_net {
                Some(Arc::clone(&addr_manager))
            } else {
                None
            },
        },
        outbound_channel,
    );
    // Query the network seeders to bootstrap the address manager (dcrd
    // `Run` launching `querySeeders` when seeding is enabled).
    let seeder_boot = if cfg.disable_seeders {
        dcroxide_node::logging::info("SRVR", "Peer discovery through seeders is disabled");
        None
    } else {
        let seeders: Vec<String> = cfg
            .params
            .params
            .seeders
            .iter()
            .map(|s| s.to_string())
            .collect();
        if seeders.is_empty() {
            None
        } else {
            // No aggregate line here: dcrd emits none — `Querying`
            // appears nowhere in its tree — and reports per seeder
            // instead, naming each one and how many addresses it
            // yielded (`addrmgr/seed.go` 161, 195, 198).  Those lines
            // carry strictly more, and this one was also tagged `SRVR`
            // where dcrd's seeder output is `AMGR`.
            // dcrd routes its seeder HTTP transport through `dcrdDial`,
            // so a proxied daemon queries the seeders over the SOCKS
            // proxy rather than leaking the traffic; without a proxy the
            // battle-tested ureq transport does the direct dial.  The
            // seeder host lookup for the source address is dcrd's
            // `dcrdLookup(seeder)` either way: through Tor under --proxy
            // (unless --noonion), so the names never reach the system
            // resolver (one minute bounds it, like the transport).
            let services = ServiceFlag::NODE_NETWORK.0;
            let lookup_dialer = dcroxide_node::socks::NodeDialer::from_config(&cfg);
            let lookup =
                move |host: &str| lookup_dialer.lookup(host, std::time::Duration::from_secs(60));
            if cfg.dial == dcroxide_node::config::DialSelection::SocksProxy {
                let dialer = dcroxide_node::socks::NodeDialer::from_config(&cfg);
                Some(dcroxide_node::seeding::start_seeding_with_lookup(
                    seeders,
                    Arc::clone(&addr_manager),
                    services,
                    move || dcroxide_node::seeding::ProxySeederTransport::new(dialer.clone()),
                    lookup,
                ))
            } else {
                Some(dcroxide_node::seeding::start_seeding_with_lookup(
                    seeders,
                    Arc::clone(&addr_manager),
                    services,
                    dcroxide_node::seeding::UreqTransport::new,
                    lookup,
                ))
            }
        }
    };

    // Watch for mix session misbehavior at every epoch boundary (dcrd
    // `Server.Run` running `s.mixObserver.Run`).
    let mix_observer =
        dcroxide_node::mixnode::start_mix_epoch_observer(Arc::clone(&server.mix_pool));

    pipe_notifier.notify_startup_complete();
    log_info("Serving peers until a shutdown signal is received.");

    // Idle until a shutdown is requested -- an interrupt, termination
    // or hangup signal, the `stop` RPC, the parent closing `--piperx` or
    // the service control manager -- mirroring dcrd's `svr.Run` blocking
    // on the daemon context.
    let _ = shutdown_rx.recv();
    dcroxide_node::logging::warn("SRVR", "Server shutting down");
    // No block is processed from here on, whoever delivers it.
    stop_block_processing(&server.sync_manager);

    // Stop seeding and dialing, stop the watchdog, disconnect the live
    // peers, and stop accepting new connections (dcrd's server
    // shutdown).
    // Signal the miner to stop hashing so any in-flight solve or
    // `generate` winds down promptly and releases the RPC server before
    // the listener is torn down.
    if let Some(runtime) = &miner_runtime {
        runtime.signal_quit();
    }
    if let Some((rpc_listener, ntfn, ntfn_thread)) = rpc_listener {
        rpc_listener.shutdown();
        ntfn.shutdown();
        if let Some(thread) = ntfn_thread {
            let _ = thread.join();
        }
    }
    if let Some(seeder_boot) = seeder_boot {
        seeder_boot.shutdown();
    }
    mix_observer.shutdown();
    // Stop the peer-to-peer listeners before the connection manager
    // sweep (dcrd Run() closes its listeners first, then removes
    // every connection), so no new inbound admissions race the
    // teardown.
    if let Some(runtime) = runtime {
        runtime.shutdown();
    }
    connector.shutdown();
    stall_timer.shutdown();
    if let Some(rebroadcaster) = rebroadcaster {
        rebroadcaster.shutdown();
    }
    // Stop the miner's background threads before the generator so its
    // workers deregister their template subscriptions first.  A block
    // one of them, or `generate`, submits now is not connected: the sync
    // manager closed at `stop_block_processing` above drops it and
    // reports success, as dcrd's `SyncManager.ProcessBlock` returns nil
    // once shutdown is requested.
    if let Some(runtime) = miner_runtime {
        runtime.shutdown();
    }
    if let Some(generator) = generator {
        generator.shutdown();
    }
    connected.disconnect_all();

    // Stop the periodic dump ticker, then persist the address book so a
    // restart redials its learned peers instead of re-bootstrapping from
    // the seeders every time (dcrd's final `savePeers` when the address
    // handler stops).  save_peers is a no-op when nothing changed and
    // writes atomically.
    address_dump.shutdown();
    if let Err(e) = addr_manager
        .lock()
        .expect("addr manager mutex poisoned")
        .save_peers()
    {
        dcroxide_node::logging::error("AMGR", &format!("Unable to save peers: {e}"));
    }

    // Flush the chain's in-memory UTXO cache and modified block index to
    // the database (dcrd `Run`'s `ShutdownUtxoCache`).  Nothing connects
    // a block past this point: the sync manager has refused every block
    // since `stop_block_processing` above, whether a peer, the RPC server
    // or the miner delivered it, and the miner and the template
    // generator are stopped.  Only an RPC handler abandoned past the
    // server's bounded drain could still move the tip, through
    // invalidateblock or reconsiderblock, and that is recovered the same
    // way as a missing flush.  Every connect persists the best state but
    // holds the UTXO changes in the cache, so a start after an exit
    // without this flush finds the recorded UTXO set state behind the
    // best chain and replays the blocks between them before serving
    // anything (`initialize_utxo_state`, dcrd's `UtxoCache.Initialize`);
    // the flush spares it that replay.  The database itself closes
    // after this, as `run_node` returns (`BlockDbCloser`).
    let flushed = chain
        .lock()
        .expect("chain mutex poisoned")
        .flush(&cfg.params.params);
    if let Err(e) = &flushed {
        // dcrd discards this error (`ShutdownUtxoCache` ignores what
        // `MaybeFlush` returns).  Here it is logged and fails the exit
        // status: the store refused a write, and the storage fault behind
        // that is what a supervisor, an operator and any script reading
        // $? need to hear about.  What is on disk is not damaged by it --
        // the store keeps the last flush that completed, an older
        // consistent state the next start replays forward from.
        log_error(&format!(
            "Unable to flush the block database: {e:?} -- the chain state on disk is \
             the last flush that completed, behind the state this node was running \
             with, and the next start replays forward from it. Investigate the \
             storage fault before restarting."
        ));
    }
    dcroxide_node::logging::info("SRVR", "Server shutdown complete");
    // dcrd defers this event once startup completes, so it fires as
    // `dcrdMain` returns from `svr.Run`: after the server's whole
    // teardown and before the database closes.
    pipe_notifier.notify_shutdown_event(dcroxide_node::ipc::LifetimeAction::P2pServer);

    if flushed.is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Stop the sync manager handling anything more, as dcrd's
/// `SyncManager.Run` closes `quit` once the daemon context is cancelled:
/// every handler then returns at once and `process_block` connects
/// nothing, so no block reaches the chain after the shutdown flush,
/// whether a peer, the RPC server or the miner delivered it.  The flag
/// is set under the manager's lock, so a block being processed as this
/// is called finishes first.
fn stop_block_processing(sync_manager: &Mutex<dcroxide_node::sync::NodeSyncManager>) {
    sync_manager
        .lock()
        .expect("sync manager mutex poisoned")
        .request_shutdown();
}

/// Build the daemon-wide server state: the shared context the peer
/// handlers consult, the connected-peer registry, the peer template,
/// and the armed header-sync watchdog (dcrd `newServer`).
fn build_server(
    cfg: &Config,
    chain: Arc<Mutex<Chain>>,
    addr_manager: Arc<Mutex<AddrManager>>,
    tx_pool: Arc<Mutex<dcroxide_node::txmempool::NodeTxPool>>,
    ntfn: Option<dcroxide_node::websocket::NodeNtfnMgr>,
) -> (
    Arc<ServerContext>,
    ConnectedPeers,
    PeerTemplate,
    dcroxide_node::dispatch::StallTimer,
) {
    let params = &cfg.params.params;
    let template = PeerTemplate::from_config(
        cfg,
        APP_NAME,
        // Advertise the real tip in every `version` (dcrd's
        // `server.NewestBlock`).  Without this the node claims height 0
        // and no peer will ever choose it as a sync source.
        Some({
            let chain = Arc::clone(&chain);
            Arc::new(move || {
                let chain = chain
                    .lock()
                    .map_err(|_| "chain mutex poisoned".to_string())?;
                let best = chain.best_snapshot();
                Ok((best.hash, best.height))
            })
        }),
    );
    // The mixing pool the getdata serve path and the sync manager share
    // (dcrd `newServer` building one `mixpool.Pool`).
    // Building it installs the tx pool's pair-request probe, so the
    // acceptance gauntlet runs dcrd's `NonMixSpendsPairRequest` step.
    let mix_pool =
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);
    // The sync manager shares the chain with the message handlers
    // (dcrd `newServer` building its `netsync.Config`).
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        params,
        cfg.no_mining_state_sync,
        // dcrd's OTHER outbound target -- signed comparison, widened
        // afterwards (`server.go:4132-4142`).  Deliberately not the same
        // computation as the server's; see QK-0014.
        dcroxide_node::netsync_max_outbound_peers(cfg.max_peers),
        cfg.max_orphan_txs as usize,
        Arc::clone(&tx_pool),
        Arc::clone(&mix_pool),
    )));
    // The daemon-wide state the served peers' message handlers consult
    // (dcrd `newServer` deriving `minKnownWork` from the params).
    let server = Arc::new(ServerContext {
        target_outbound: dcroxide_node::server_target_outbound(cfg.max_peers),
        chain,
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: cfg.disable_banning,
        ban_threshold: cfg.ban_threshold,
        whitelists: cfg.whitelists.clone(),
        banned_hosts: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        ban_duration_nanos: cfg.ban_duration_nanos,
        addr_manager,
        sim_or_reg_net: cfg.sim_net || cfg.reg_net,
        // One cache for the process (dcrd's `server.externalAddrCandidates`,
        // built once in `newServer`).
        external_addr_candidates: std::sync::Mutex::new(Default::default()),
        external_addr_facts: dcroxide_node::server::ExternalAddrFacts {
            listeners: cfg.listeners.clone(),
            has_proxy: !cfg.proxy.is_empty() || !cfg.onion_proxy.is_empty(),
            no_discover_ip: cfg.no_discover_ip,
            has_external_ips: !cfg.external_ips.is_empty(),
            // dcrd's condition is `cfg.DisableListen || len(cfg.Listeners) == 0`.
            listen_disabled: cfg.disable_listen || cfg.listeners.is_empty(),
            // Deliberately the ACTIVE PARAMS NAME, not the cfg flags:
            // `considerReportedAddrOutbound` reads `s.chainParams.Name`
            // while the advertise block above it reads `cfg.SimNet` /
            // `cfg.RegNet`.  The two sources are independent upstream and
            // must stay independent here.
            sim_or_reg_net: params.name == "simnet" || params.name == "regnet",
            services: ServiceFlag::NODE_NETWORK,
            // The same `s.targetOutbound` the version handler reads;
            // bounded by 8, so the `target_outbound * 60` majority
            // expression this feeds can never overflow.
            target_outbound: dcroxide_node::server_target_outbound(cfg.max_peers),
        },
        // dcrd's `dcrdLookup`, which routes through the proxy when set.
        lookup: {
            let dialer = dcroxide_node::socks::NodeDialer::from_config(cfg);
            let timeout = std::time::Duration::from_secs(30);
            Box::new(move |host: &str| dialer.lookup(host, timeout))
        },
        stake_validation_height: params.stake_validation_height,
        blocks_only: cfg.blocks_only,
        sync_manager,
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: cfg.disable_listen,
        tx_pool,
        ntfn,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),
        mix_pool,
    });
    // Arm the header-sync stall watchdog around the manager (dcrd's
    // stallHandler timer).
    let stall_timer = dcroxide_node::dispatch::start_stall_timer(
        Arc::clone(&server.sync_manager),
        server.sync_peers.clone(),
        Duration::from_secs(dcroxide_netsync::manager::HEADER_SYNC_STALL_TIMEOUT_SECS),
    );
    (server, ConnectedPeers::new(), template, stall_timer)
}

/// Bind the configured peer-to-peer listeners and start serving inbound
/// peers (dcrd `newServer`'s listener setup plus `inboundPeerConnected`).
fn start_listeners(
    cfg: &Config,
    template: &PeerTemplate,
    connected: ConnectedPeers,
    server: Arc<ServerContext>,
    manager: dcroxide_node::outbound::SharedConnManager,
) -> Result<ListenerRuntime, String> {
    let specs = parse_listeners(&cfg.listeners)?;
    ListenerRuntime::start(
        &specs,
        inbound_peer_handler(template.clone(), connected, Some(server), Some(manager)),
    )
    .map_err(|e| e.to_string())
}

/// How many bytes redb may cache, from `DCROXIDE_DB_CACHE` (MiB).
///
/// An environment variable rather than a command-line option on purpose.
/// dcrd has no counterpart — the setting is a property of redb, which
/// dcrd does not use — and the generated `-h` output is pinned
/// byte-for-byte against dcrd's, so a new flag would break that parity
/// for a knob dcrd cannot have. `DCROXIDE_APPDATA` and
/// `DCROXIDE_ALT_DNSNAMES` already establish the namespace for settings
/// with no dcrd equivalent.
///
/// The default leaves redb's own 1 GiB in place, so an untouched node
/// keeps exactly the resident footprint it had before this was
/// configurable. Leave it there: this is the one storage knob that
/// hurts. Over a full mainnet replay 8192 MiB measured 50% slower —
/// 5125-6294 s against a 3866-3888 s baseline, ranges disjoint — while
/// 256 and 512 MiB are indistinguishable from the default, ranges
/// overlapping it. The probe that motivated the knob (78.6 s at 1 GiB
/// against 16.1 s at 8 GiB, 2,000,000 scattered writes into the
/// 14.48 GiB mainnet metadata store) is superseded: the full chain
/// reverses it, and its 8 GiB arm raised the flush cadence as well, so
/// it never isolated the cache. Cadence is the half that pays, at
/// 11-12%, and dcrd's own `--utxocachemaxsize` already reaches it. The
/// cache is a ceiling filled on demand and bounded by the file size,
/// so a small chain does not pay for a large setting.
///
/// A value that does not parse, or is zero, is ignored with a warning
/// rather than being fatal: it is a tuning hint, and refusing to start
/// over a malformed one would be a worse failure than running with the
/// default.
fn db_cache_bytes() -> usize {
    const VAR: &str = "DCROXIDE_DB_CACHE";
    let Ok(raw) = std::env::var(VAR) else {
        return dcroxide_database::DEFAULT_DB_CACHE_BYTES;
    };
    let trimmed = raw.trim();
    match trimmed.parse::<usize>() {
        Ok(mib) if mib > 0 => match mib.checked_mul(1024 * 1024) {
            Some(bytes) => {
                log_info(&format!("Database page cache set to {mib} MiB by {VAR}"));
                bytes
            }
            None => {
                log_warn(&format!(
                    "{VAR}={trimmed} overflows; using the default cache size"
                ));
                dcroxide_database::DEFAULT_DB_CACHE_BYTES
            }
        },
        _ => {
            log_warn(&format!(
                "{VAR}={trimmed} is not a positive whole number of MiB; using the default cache \
                 size"
            ));
            dcroxide_database::DEFAULT_DB_CACHE_BYTES
        }
    }
}

/// A positive whole number from `var`, or `None` when it is unset,
/// malformed, or zero.
///
/// Shared by the overlay knobs below, which follow `DCROXIDE_DB_CACHE`'s
/// policy: a bad value warns and falls back rather than being fatal,
/// because these are tuning hints and refusing to start over a malformed
/// one would be a worse failure than running with the default.
fn env_tuning_u64(var: &str, unit: &str) -> Option<u64> {
    let raw = std::env::var(var).ok()?;
    let trimmed = raw.trim();
    match trimmed.parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => {
            log_warn(&format!(
                "{var}={trimmed} is not a positive whole number of {unit}; using the default"
            ));
            None
        }
    }
}

/// Apply the metadata overlay's size and time flush triggers from
/// `DCROXIDE_DB_OVERLAY` (MiB) and `DCROXIDE_DB_FLUSH_SECS` (seconds).
///
/// These are the second of the two flush triggers, and until now the
/// unreachable one. Connecting a block flushes the UTXO cache when it
/// fills, and `--utxocachemaxsize` governs that; the overlay has its own
/// independent ceiling (100 MiB) and interval (300 s) that no flag or
/// variable reached, so half the cadence lever was fixed at compile time.
///
/// Cadence is the half that pays. `--utxocachemaxsize` alone measured
/// **12% faster** over a full chain at 1200 MiB and 7% at 600 MiB, three
/// repetitions each with ranges disjoint from the baseline's — the only
/// defensible IBD gain any tuning has produced. What makes the overlay
/// worth reaching is the 2026-08-15 measurement: the node is *fully
/// stalled*, with nothing runnable, for 34.6% of block-sync wall time,
/// and that time is spent in a small number of very large durable
/// commits rather than many small ones. Both triggers force such a
/// commit, so leaving one of them unreachable caps what cadence tuning
/// can be asked to do.
///
/// Environment variables rather than flags, for `DCROXIDE_DB_CACHE`'s
/// reason: dcrd has no counterpart, and the generated `-h` output is
/// pinned byte-for-byte against dcrd's.
///
/// Unset leaves the compiled defaults exactly as they were, so an
/// untouched node behaves identically. Raising either means more work
/// redone after an unclean stop — the flush ordering holds and nothing
/// is corrupted, but more of the recent window replays.
fn apply_overlay_tuning(opts: &mut Options) {
    if let Some(mib) = env_tuning_u64("DCROXIDE_DB_OVERLAY", "MiB") {
        opts.cache_max_size = mib.saturating_mul(1024 * 1024);
        log_info(&format!(
            "Metadata overlay flush size set to {mib} MiB by DCROXIDE_DB_OVERLAY"
        ));
    }
    if let Some(secs) = env_tuning_u64("DCROXIDE_DB_FLUSH_SECS", "seconds") {
        opts.cache_flush_interval_secs = secs;
        log_info(&format!(
            "Metadata overlay flush interval set to {secs} s by DCROXIDE_DB_FLUSH_SECS"
        ));
    }
}

/// Record every metadata flush to the JSONL path in
/// `DCROXIDE_DB_FLUSHLOG`, when one is set.
///
/// Exists to settle what the 2026-08-15 D-state measurement could not.
/// That run found the node fully stalled for 34.6% of block-sync wall
/// time, but the sampler reads kernel wait channels rather than user
/// stacks, so it cannot say whether a stalled thread is inside the
/// metadata commit or writing a block file. The observer knows exactly,
/// and pairing its windows against the sampler's timestamps attributes
/// the stall directly instead of by inference.
///
/// One line per flush: the sequence, the wall-clock instant the flush
/// ENDED, and its duration. The observer fires after the commit, so
/// `end - elapsed` reconstructs the window it occupied. Each of the
/// flush's three phases -- the block-file sync, the insert loop and the
/// commit -- gets its own time and, on Linux, the bytes the flushing
/// thread read from storage and the bytes it dirtied in it. The time
/// and the bytes read are what say whether a stall in the window was
/// waiting on reads: `write_bytes` counts pages when they are dirtied,
/// not when they are written back, so writeback time shows in a phase's
/// `ms` and not in its `write_bytes`, and the block-file sync reads
/// about 0 there however much it flushes.
///
/// Stats sampling is deliberately left off (`flush_stats_every` stays
/// 0). redb's `stats()` walks every branch and leaf page, which on a
/// chain-sized tree cost 442.5 s against the flushes' own 260.9 s in the
/// replay that motivated this — enabling it here would swamp the
/// quantity being measured.
fn flush_log_observer() -> Option<dcroxide_database::FlushObserver> {
    let path = std::env::var("DCROXIDE_DB_FLUSHLOG").ok()?;
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            log_warn(&format!(
                "DCROXIDE_DB_FLUSHLOG={path} is not writable ({e}); not logging"
            ));
            return None;
        }
    };
    log_info(&format!("Logging metadata flushes to {path}"));
    let sink = std::sync::Mutex::new(std::io::BufWriter::new(file));
    Some(std::sync::Arc::new(
        move |obs: &dcroxide_database::FlushObservation| {
            use std::io::Write as _;
            let end = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            // A few hundred bytes per flush, and a full mainnet sync makes
            // only a few hundred of them, so the write is far below the
            // seconds-long commit it describes.
            if let Ok(mut out) = sink.lock() {
                let _ = writeln!(
                    out,
                    "{{\"seq\":{},\"end\":{:.3},\"elapsed_ms\":{:.3},\"entries\":{},\"bytes\":{},\"sync\":{},\"insert\":{},\"commit\":{}}}",
                    obs.sequence,
                    end,
                    obs.elapsed.as_secs_f64() * 1000.0,
                    obs.dirty_entries,
                    obs.dirty_bytes,
                    obs.block_sync.to_json(),
                    obs.insert.to_json(),
                    obs.commit.to_json()
                );
                let _ = out.flush();
            }
        },
    ))
}

/// Open (or create) the block database (dcrd `dcrdMain`'s
/// `loadBlockDB`).  The block database lives at
/// `<datadir>/blocks_<dbtype>`; the same handle backs the chain and
/// the enabled indexes.
///
/// It logs dcrd's two lines around the open (`blockdb.go:139`, `:185`),
/// so "Block database loaded" precedes everything the chain logs while
/// it opens, as it does upstream, where the chain is only built later,
/// in `newServer`.
fn open_block_db(cfg: &Config) -> Result<Database, String> {
    let params = &cfg.params.params;
    let db_path = Path::new(&cfg.data_dir).join(format!("blocks_{}", cfg.db_type));
    log_info(&format!(
        "Loading block database from '{}'",
        db_path.display()
    ));
    let mut opts = Options::new(&db_path, params.net.0);
    opts.db_cache_bytes = db_cache_bytes();
    apply_overlay_tuning(&mut opts);
    opts.flush_observer = flush_log_observer();
    // dcrd's `log.go:88` hands the database driver the BCDB logger
    // (`database.UseLogger(bcdbLog)`): the unclean-shutdown repair, the
    // corruption warning and the ROLLBACK lines.
    opts.log = Some(dcroxide_node::logging::bcdb_log_sink());

    // Open the existing database, creating it when it does not yet
    // exist (dcrd's `database.Open` then `database.Create` fallback).
    let db = match Database::open(&opts) {
        Ok(db) => db,
        Err(e) if e.kind == ErrorKind::DbDoesNotExist => {
            // 0700, matching dcrd's `os.MkdirAll(cfg.DataDir, 0700)`
            // in blockdb.go.  Creating it 0755 here would also make
            // `Database::create`'s own owner-only mkdir a no-op, since
            // that one deliberately leaves an existing directory's mode
            // alone.
            dcroxide_database::create_dir_all_owner_only(&db_path)
                .map_err(|e| format!("unable to create database directory: {e}"))?;
            Database::create(&opts).map_err(|e| format!("unable to create database: {e}"))?
        }
        Err(e) => return Err(format!("unable to open database: {e}")),
    };
    log_info("Block database loaded");
    Ok(db)
}

/// Initialize the chain state over the open block database (the chain
/// construction inside dcrd's `newServer`); a fresh database creates
/// the genesis chain state.  The interrupt is the context dcrd hands
/// `blockchain.New`: a shutdown signal stops the startup UTXO catch-up.
fn open_chain(
    cfg: &Config,
    db: Database,
    interrupt: &dcroxide_indexers::Interrupt,
) -> Result<Chain, String> {
    let params = &cfg.params.params;

    // dcrd `newServer` announces --allowoldforks between the fee
    // estimator and the assume-valid setting.
    if cfg.allow_old_forks {
        dcroxide_node::logging::info("SRVR", "Processing forks deep in history is enabled");
    }

    // Set assume valid when enabled (dcrd `newServer`): exactly "0"
    // disables it, an empty value keeps the network's hard-coded hash,
    // and anything else overrides it.
    let assume_valid = if cfg.assume_valid == "0" {
        dcroxide_node::logging::info("SRVR", "Assume valid is disabled");
        Hash::ZERO
    } else if cfg.assume_valid.is_empty() {
        params.assume_valid
    } else {
        let hash = cfg
            .assume_valid
            .parse::<Hash>()
            .map_err(|e| format!("invalid hex for --assumevalid: {e}"))?;
        dcroxide_node::logging::info("SRVR", &format!("Assume valid set to {hash}"));
        hash
    };

    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut chain = Chain::open_with_config(
        db,
        params,
        OpenConfig {
            assume_valid,
            allow_old_forks: cfg.allow_old_forks,
            created_unix,
            interrupt: Some(Arc::clone(interrupt)),
            // dcrd's `log.go` init hands `internal/blockchain` the CHAN
            // logger (`blockchain.UseLogger(chanLog)`, `log.go:85`), so
            // it is in place before `blockchain.New` runs and the open's
            // own lines -- the block index load, the UTXO cache
            // initialization and catch-up, the chain state -- reach it.
            // The per-subsystem levels are already resolved by the time
            // this runs (`logging::set_levels` in `run`), so
            // `--debuglevel CHAN=` governs these lines as it does
            // upstream.
            log: Some(dcroxide_node::chainntfns::chain_log_sink()),
            // dcrd's --utxocachemaxsize (megabytes) bounds the UTXO cache
            // before a flush evicts it down.  dcrd builds the cache with
            // it ahead of `blockchain.New` (`server.go:4005-4009`), so
            // the open-time catch-up replay already flushes at the
            // configured size and logs it.
            utxo_cache_max_bytes: cfg.utxo_cache_max_size.saturating_mul(1024 * 1024),
        },
    )
    // `newServer` returns `blockchain.New`'s error as is, which `%v`
    // renders as its bare description.
    .map_err(|e| e.to_string())?;
    // dcrd's --sigcachemaxsize bounds the signature verification
    // cache by ENTRY COUNT (server.go passes it to
    // `txscript.NewSigCache`).  The open-time catch-up replay above
    // runs no scripts, so sizing after open is equivalent.
    chain.set_sig_cache_max_entries(usize::try_from(cfg.sig_cache_max_size).unwrap_or(usize::MAX));
    Ok(chain)
}

/// Build the RPC server configuration over the shared chain with the
/// daemon's not-yet-wired subsystem seams as no-ops (dcrd `newRPCServer`;
/// each seam fills in as its subsystem lands).
// Mirrors dcrd's rpcserver config assembly, which takes the same set.
#[allow(clippy::too_many_arguments)]
fn rpc_config(
    cfg: &Config,
    chain: Arc<Mutex<Chain>>,
    ntfn_handler: dcroxide_node::chainntfns::ChainNtfnHandler,
    connected: ConnectedPeers,
    sync_manager: Arc<Mutex<dcroxide_node::sync::NodeSyncManager>>,
    net_totals: Arc<dcroxide_node::transport::NetByteTotals>,
    tx_pool: Arc<Mutex<dcroxide_node::txmempool::NodeTxPool>>,
    sync_peers: dcroxide_node::dispatch::SyncPeers,
    recently_advertised: Arc<
        Mutex<dcroxide_containers::lru::Map<dcroxide_chainhash::Hash, dcroxide_wire::MsgTx>>,
    >,
    rebroadcast: dcroxide_node::rebroadcast::RebroadcastSink,
    ntfn: dcroxide_node::websocket::NodeNtfnMgr,
    tx_indexer: Option<Box<dyn dcroxide_rpc::server::RpcTxIndexer + Send + Sync>>,
    exists_addresser: Option<Box<dyn dcroxide_rpc::server::RpcExistsAddresser + Send + Sync>>,
    db: Database,
    block_templater: Option<Box<dyn dcroxide_rpc::server::RpcBlockTemplater + Send + Sync>>,
    fee_estimator: dcroxide_node::fees::SharedFeeEstimator,
    cpu_miner: Box<dyn dcroxide_rpc::server::RpcCpuMiner + Send + Sync>,
    addr_manager: Arc<Mutex<AddrManager>>,
    request_shutdown: Box<dyn Fn() + Send + Sync>,
    outbound_control: dcroxide_node::outbound::OutboundControl,
    mix_pool: Arc<Mutex<dcroxide_node::mixnode::NodeMixPool>>,
) -> dcroxide_rpc::server::Config<dcroxide_node::rpcrun::NodeRpcChain> {
    let params = cfg.params.params.clone();
    // The version 2 filter source shares the live chain (cloned before it
    // is moved into the chain adapter below); the sanity checker keeps the
    // parameters (cloned before they are moved into the subsidy cache).
    let filterer_v2 = dcroxide_node::rpcrun::NodeRpcFiltererV2::new(Arc::clone(&chain));
    let sanity_checker = dcroxide_node::rpcrun::NodeRpcSanityChecker::new(params.clone());
    dcroxide_rpc::server::Config {
        chain: dcroxide_node::rpcrun::NodeRpcChain::new(chain, params.clone())
            .with_chain_ntfn_handler(ntfn_handler),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(dcroxide_standalone::SubsidyCache::new(params)),
        min_relay_tx_fee: cfg.min_relay_tx_fee_atoms,
        max_protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        // The mixing pool behind sendrawmixmessage (dcrd's
        // `AcceptMixMessage` adaptor over `s.mixMsgPool`).
        sync_mgr: Box::new(
            dcroxide_node::rpcrun::NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))
                .with_mix_pool(Arc::clone(&mix_pool)),
        ),
        conn_mgr: Box::new(
            dcroxide_node::rpcrun::NodeRpcConnManager::new(connected, net_totals)
                .with_relay(
                    sync_peers,
                    recently_advertised,
                    Arc::clone(&tx_pool),
                    rebroadcast,
                    ntfn.clone(),
                )
                .with_outbound(outbound_control)
                // The configured lookup routing, so getaddednodeinfo's
                // DNS detail resolves like dcrd's dcrdLookup.
                .with_dialer(dcroxide_node::socks::NodeDialer::from_config(cfg)),
        ),
        client_cert_auth: cfg.rpc_auth_type == dcroxide_node::config::AUTH_TYPE_CLIENT_CERT,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(tx_pool)),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        // addnode and node dial an interface's first address when the
        // host names one (dcrd `normalizeAddress`).
        interfaces: Box::new(dcroxide_node::rpcrun::SystemInterfaces),
        // The process-wide generator, not a fresh kernel read: dcrd's
        // rpcserver imports `crypto/rand` and calls the package
        // functions for both draws this closure serves -- the ping
        // nonce in `handlePing` (`internal/rpcserver/rpcserver.go:42`,
        // `:4269`) and the auth HMAC key at server construction
        // (`:6234-6235`).  The nonce is drawn per request, so an
        // authenticated client sets its rate, and under
        // `panic = "abort"` a failed read there would be an outage.
        rand_u64: Box::new(dcroxide_crypto::rand::uint64),
        tx_indexer,
        db: Box::new(dcroxide_node::indexes::NodeRpcDb::new(db)),
        filterer_v2: Box::new(filterer_v2),
        exists_addresser,
        log_manager: Box::new(dcroxide_node::rpcrun::NodeRpcLogManager),
        fee_estimator: Box::new(dcroxide_node::fees::NodeRpcFeeEstimator::new(fee_estimator)),
        block_templater,
        sanity_checker: Box::new(sanity_checker),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: cfg.proxy.clone(),
        test_net: cfg.test_net,
        runtime_version: String::new(),
        // The CPU miner built above whenever mining addresses are
        // configured, behind generate, setgenerate, getgenerate,
        // gethashespersec and getmininginfo; without them the idle
        // stand-in, which reports the miner off and refuses to generate.
        cpu_miner,
        // getmixpairrequests and getmixmessage read the same shared pool
        // the peers feed (dcrd's `MixPooler: s.mixMsgPool`).
        mix_pooler: Box::new(dcroxide_node::rpcrun::NodeRpcMixPooler::new(mix_pool)),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(dcroxide_node::rpcrun::NodeRpcAddrManager::new(addr_manager)),
        mining_addrs: cfg.mining_addrs.clone(),
        user_agent_version: version::user_agent_version(),
        // The three per-network reachability descriptions the config's
        // `parse_network_interfaces` already derived from the listeners
        // and proxy settings (dcrd's `cfg.generateNetworkInfo()`).
        net_info: vec![
            cfg.ipv4_net_info.clone(),
            cfg.ipv6_net_info.clone(),
            cfg.onion_net_info.clone(),
        ],
        services: ServiceFlag::NODE_NETWORK.0,
        request_shutdown,
        allow_unsynced_mining: cfg.allow_unsynced_mining,
        rpc_user: cfg.rpc_user.clone(),
        rpc_pass: cfg.rpc_pass.clone(),
        rpc_limit_user: cfg.rpc_limit_user.clone(),
        rpc_limit_pass: cfg.rpc_limit_pass.clone(),
    }
}

/// The median-adjusted time as unix seconds (the sync adapter's
/// `adjusted_time_unix`), for driving the chain handler's deferred
/// maintenance from the generator's drain hook.
fn now_unix() -> i64 {
    dcroxide_node::mediantime::adjusted_time_unix()
}

/// The wall-clock time as unix seconds, for the timestamps dcrd takes
/// from `time.Now()` rather than the median-adjusted clock (the local
/// addresses `initListeners` registers, stamped by
/// `addrmgr.NewNetAddressFromIPPort`).
fn wall_clock_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A package-main log line (dcrd's `dcrdLog`); subsystem-specific
/// lines call [`dcroxide_node::logging`] with their own tags.
fn log_info(msg: &str) {
    dcroxide_node::logging::info("DCRD", msg);
}

/// A package-main warning line (dcrd `dcrdLog.Warnf`).
fn log_warn(msg: &str) {
    dcroxide_node::logging::warn("DCRD", msg);
}

/// A package-main error line (dcrd `dcrdLog.Errorf`).
fn log_error(msg: &str) {
    dcroxide_node::logging::error("DCRD", msg);
}

#[cfg(test)]
mod tests {
    use super::{passwd_home, signal_line, stop_block_processing};
    use std::sync::{Arc, Mutex};

    /// A Windows console close, logoff or shutdown is logged as dcrd's
    /// `shutdownListener` logs the SIGTERM Go's runtime makes of it
    /// (`signal.go:34`, `:47-49`), first and repeat.
    #[test]
    fn a_termination_signal_is_logged_as_dcrd_logs_it() {
        assert_eq!(
            signal_line("terminated", false),
            "Received signal (terminated).  Shutting down..."
        );
        assert_eq!(
            signal_line("terminated", true),
            "Received signal (terminated).  Already shutting down..."
        );
    }

    /// `~` resolves through the account's password-file entry, parsed
    /// with Go's cgo-free rules: the old lookup read `$HOME` alone, so a
    /// unit without one expanded `~` under the working directory.
    #[test]
    fn the_home_comes_from_the_password_file_as_go_reads_it() {
        let passwd = concat!(
            "# comment:x:1000:1000::/commented:/bin/sh\n",
            "+nis:x:1000:1000::/nis:/bin/sh\n",
            "root:x:0:0:root:/root:/bin/bash\n",
            "short:x:1000:1000:/short\n",
            "badgid:x:1000:gid::/badgid:/bin/sh\n",
            "\t node:x:1000:1000:Node,,,:/home/node:/bin/bash \n",
            "other:x:1001:1001::/home/other:/bin/sh\n",
        );
        assert_eq!(passwd_home(passwd, "1000").as_deref(), Some("/home/node"));
        assert_eq!(passwd_home(passwd, "0").as_deref(), Some("/root"));
        assert_eq!(passwd_home(passwd, "1001").as_deref(), Some("/home/other"));
        assert_eq!(passwd_home(passwd, "4242"), None);
    }

    /// The shutdown closes the sync manager's gate as dcrd's closed
    /// `quit` does, so a block handed over after it -- by a peer thread
    /// that was waiting on the manager, the RPC server or the miner --
    /// is dropped rather than connected after the final flush.  Nothing
    /// used to close it: `request_shutdown` had no caller.
    #[test]
    fn stopping_block_processing_closes_the_sync_manager() {
        let params = dcroxide_chaincfg::simnet_params();
        let dir = tempfile::tempdir().expect("database directory");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks_ffldb"), params.net.0);
        dcroxide_database::create_dir_all_owner_only(&opts.path).expect("create the directory");
        let db = dcroxide_database::Database::create(&opts).expect("create the database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open the chain"),
        ));
        let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10_000,
            false,
            false,
        );
        let mix_pool =
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);
        let manager = Mutex::new(dcroxide_node::sync::new_sync_manager(
            chain, &params, false, 8, 100, tx_pool, mix_pool,
        ));

        // The genesis block again: processing it fails, which is what
        // shows whether it was processed at all.
        let block = params.genesis_block.clone();
        assert!(
            manager
                .lock()
                .expect("manager")
                .process_block(&block)
                .is_err(),
            "a running manager processes the block"
        );
        stop_block_processing(&manager);
        let mut manager = manager.lock().expect("manager");
        assert!(
            manager.process_block(&block).is_ok(),
            "a stopped manager drops the block unprocessed"
        );
        assert!(manager.on_block(1, &block).is_empty());
    }
}
