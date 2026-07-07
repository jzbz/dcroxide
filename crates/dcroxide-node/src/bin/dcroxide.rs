// SPDX-License-Identifier: ISC
//! The dcroxide daemon binary — the runtime front-end of dcrd's
//! `dcrd.go` `dcrdMain`: build the configuration environment from the
//! real operating system, parse the command line through the ported
//! configuration pipeline, handle the help, version, and
//! debug-level-show exits with dcrd's exit codes, print the startup
//! banner, and idle on a shutdown-signal listener until interrupted.
//!
//! The block database load, the UTXO database, and the peer-to-peer
//! server (`newServer`/`svr.Run`) arrive with later pieces; this
//! stops after the startup announcements.  The rotating file-logging
//! backend is likewise not yet wired, so startup output goes to
//! standard streams.

use std::process::ExitCode;
use std::sync::mpsc;

use dcroxide_node::{
    Config, ConfigEnv, ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS, ERR_VERSION_REQUESTED,
    app_data_dir, load_config_from_argv, logo, supported_subsystems, version,
};

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
    log_info(
        "The block database and peer-to-peer server are not yet wired; \
         idling until a shutdown signal is received.",
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

    log_info("Shutdown complete");
    ExitCode::SUCCESS
}

/// A minimal startup log line until the rotating logging subsystem is
/// wired.
fn log_info(msg: &str) {
    println!("[INF] DCRD: {msg}");
}
