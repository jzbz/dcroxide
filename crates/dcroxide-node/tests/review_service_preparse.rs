// SPDX-License-Identifier: ISC
//! The Windows service command against dcrd's `loadConfig`.  Only the
//! config-file pre-parse (`newConfigParser(&preCfg, &serviceOpts,
//! flags.None)`) registers `-s/--service`; the help pre-parse is a bare
//! `flags.NewParser(&cfg, helpOpts)` that skips it as an unknown option.
//! The port's help pass took the option on Windows, so a command line
//! the pre-parse stops short of still ran the service command, and
//! `--service -h` swallowed the help flag as its value.
//!
//! Every assertion holds on every platform, since the option is unknown
//! everywhere but Windows; the Windows run is the one that catches the
//! regression.

use dcroxide_node::config::{ConfigEnv, ERR_SERVICE_COMMAND_PREFIX};
use dcroxide_node::{ERR_HELP_REQUESTED, load_config_from_argv};

fn load(args: &[&str]) -> Result<(), String> {
    let home_dir = tempfile::tempdir().expect("home");
    let mut full_args = vec![format!("--appdata={}", home_dir.path().display())];
    full_args.extend(args.iter().map(|a| a.to_string()));
    let env = ConfigEnv {
        default_home_dir: "/dcroxide-nonexistent-default".to_string(),
        lookup_localhost: Box::new(|| Ok(vec!["::1".to_string(), "127.0.0.1".to_string()])),
        interface_by_name: Box::new(|_| None),
        getenv: Box::new(|_| None),
        user_home: Box::new(|_| None),
        rand_bytes: Box::new(|b: &mut [u8]| b.fill(0x42)),
    };
    load_config_from_argv(&full_args, &env).map(|_| ())
}

/// dcrd's pre-parse stops at `--bogus` before it reaches `--service`,
/// so no service command runs and the final parse reports the flag.
#[test]
fn a_service_command_past_a_pre_parse_error_does_not_run() {
    let err = load(&["--bogus", "--service=stop"]).expect_err("an unknown flag");
    assert!(!err.starts_with(ERR_SERVICE_COMMAND_PREFIX), "{err}");
    assert!(err.contains("unknown flag `bogus'"), "{err}");
}

/// dcrd's help parser does not know `--service`, so the `-h` after it
/// is the help flag rather than the option's value.
#[test]
fn help_after_the_service_flag_is_still_help() {
    assert_eq!(
        load(&["--service", "-h"]),
        Err(ERR_HELP_REQUESTED.to_string())
    );
    assert_eq!(load(&["-s", "-h"]), Err(ERR_HELP_REQUESTED.to_string()));
}
