// SPDX-License-Identifier: ISC
//! What dcrd's `loadConfig` says on its way through, and the texts it
//! says it in.
//!
//! - It writes some lines to stderr the moment it reaches them: go-flags'
//!   `PrintErrors` echo of a help pre-parse error, "Error creating a
//!   default config file", and the deprecation notices.  A load that
//!   fails later has printed them already.
//! - It logs the previous-testnet directories it finds and, last, the
//!   missing config file, as Go `*PathError`s (`open <path>: no such
//!   file or directory`, `read <path>: is a directory`).
//! - Its home directory creation is Go's `os.MkdirAll`, which fails on
//!   the empty path an empty `--appdata` leaves, names the component
//!   that failed, and hints at an unmounted symlink target.  That one
//!   error is `errSuppressUsage`, so no usage line follows it.
//! - A config value it would take as raw bytes but a `String` cannot
//!   hold is refused rather than altered, and so is such an environment
//!   variable, which the port read as unset: refused only when dcrd
//!   would have read it, and before the load acts on it.  addblock's
//!   `$HOME` likewise.
//! - The clientcert rule without a CA file applies only when the RPC
//!   server runs.
//! - The help flag ends the help pre-parse where it stands, as go-flags'
//!   `ErrHelp` does, so an error after it is neither reached nor echoed.

#![cfg(unix)]

use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};

use dcroxide_node::ERR_HELP_REQUESTED;
use dcroxide_node::config::{
    Config, ConfigEnv, error_shows_usage, load_config_from_argv_with_notices,
};

/// A load's result: the config and the remaining arguments, or the
/// error.
type Loaded = Result<(Config, Vec<String>), String>;

/// Load over `args` with the default home in `default_home`, returning
/// the result and the stderr notices in the order they were written.
fn load(args: &[String], default_home: &Path) -> (Loaded, Vec<String>) {
    load_with_env(args, default_home, &[])
}

/// [`load`] in an environment where each variable in `not_utf8` is set
/// to bytes that are not UTF-8: its lookup records a refusal, as
/// `flags::getenv_utf8` does, and reads as unset.  Every other variable
/// is unset.
fn load_with_env(args: &[String], default_home: &Path, not_utf8: &[&str]) -> (Loaded, Vec<String>) {
    let env_refused = RefCell::new(None);
    let env = ConfigEnv {
        default_home_dir: default_home.to_string_lossy().into_owned(),
        lookup_localhost: Box::new(|| Ok(vec!["::1".to_string(), "127.0.0.1".to_string()])),
        interface_by_name: Box::new(|_| None),
        getenv: Box::new(|name| {
            if not_utf8.contains(&name) {
                env_refused
                    .borrow_mut()
                    .get_or_insert_with(|| format!("refused {name}"));
            }
            None
        }),
        user_home: Box::new(|_| None),
        rand_bytes: Box::new(|b: &mut [u8]| b.fill(0x42)),
    };
    let mut notices = Vec::new();
    let result = load_config_from_argv_with_notices(
        args,
        &env,
        &mut |line| notices.push(line.to_string()),
        &env_refused,
    );
    (result, notices)
}

/// `bytes` as an environment value: raw, as unix keeps it.
fn raw(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|a| a.to_string()).collect()
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// dcrd prints "Error creating a default config file: <err>" and goes
/// on; the port dropped the error.  Its text is the `*PathError` of the
/// failed `os.OpenFile`, and the config file that is then missing is
/// logged as one too.
#[test]
fn a_failed_default_config_creation_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        // Permissions do not stop root.
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    std::fs::create_dir(&home).expect("home");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let home_str = home.to_string_lossy().into_owned();

    let (result, notices) = load(&[format!("--appdata={home_str}")], dir.path());
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).expect("chmod");

    let conf = format!("{home_str}/dcroxide.conf");
    assert_eq!(
        notices,
        vec![format!(
            "Error creating a default config file: open {conf}: permission denied"
        )]
    );
    let (cfg, _) = result.expect("the load goes on");
    assert_eq!(
        cfg.log_warnings,
        vec![format!("open {conf}: no such file or directory")]
    );
}

/// dcrd logs a warning for each previous-testnet directory in the data
/// directory (`config.go:1328-1335`); the port said it did and did not.
#[test]
fn previous_testnet_data_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_string_lossy().into_owned();
    let data = format!("{home}/data");
    std::fs::create_dir_all(format!("{data}/testnet2")).expect("old testnet");

    let (result, _) = load(
        &[format!("--appdata={home}"), "--simnet".to_string()],
        dir.path(),
    );
    let (cfg, _) = result.expect("load");
    assert_eq!(
        cfg.log_warnings,
        vec![format!(
            "Block chain data from previous testnet found ({data}/testnet2) and can probably \
             be removed."
        )]
    );
}

/// go-flags' ini reader keeps raw bytes, so a Latin-1 `rpcpass` is the
/// secret dcrd compares against.  A `String` cannot hold it, and a
/// replacement character in its place is a different secret; the value
/// is refused as argv is.  A comment carrying such bytes is still fine.
#[test]
fn a_config_value_that_is_not_utf8_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_string_lossy().into_owned();
    let conf = dir.path().join("alt.conf");
    std::fs::write(&conf, b"; latin-1 \xe9\nrpcuser=u\nrpcpass=p\xe4ss\n").expect("write config");
    let conf = conf.to_string_lossy().into_owned();

    let (result, _) = load(
        &[
            format!("--appdata={home}"),
            format!("--configfile={conf}"),
            "--simnet".to_string(),
        ],
        dir.path(),
    );
    assert_eq!(
        result.err(),
        Some(format!(
            "Error parsing config file: {conf}:3: the value of option rpcpass is not valid UTF-8"
        ))
    );

    std::fs::write(dir.path().join("alt.conf"), b"; latin-1 \xe9\nrpcuser=u\n").expect("write");
    let (result, _) = load(
        &[
            format!("--appdata={home}"),
            format!("--configfile={conf}"),
            "--simnet".to_string(),
        ],
        dir.path(),
    );
    assert_eq!(result.expect("a comment is skipped").0.rpc_user, "u");
}

/// An environment variable is raw bytes to dcrd, and the port read one
/// that is not UTF-8 as unset: a `DCROXIDE_APPDATA` so set ran on the
/// default home, writing a default config file there.  The load now
/// fails with the refusal before the home directory or that file, as it
/// does after a `$VAR` expansion of a path; a variable dcrd would not
/// have read is never refused.
#[test]
fn an_environment_value_that_is_not_utf8_is_refused_before_it_is_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let default_home = dir.path().join("default");

    // On mainnet the load would write the default config file in the
    // default home.
    let (result, _) = load_with_env(&[], &default_home, &["DCROXIDE_APPDATA"]);
    assert_eq!(result.err(), Some("refused DCROXIDE_APPDATA".to_string()));
    assert!(!default_home.exists(), "the default home was left alone");

    // Beside `--appdata`, go-flags never looks the variable up.
    let app = dir.path().join("app").to_string_lossy().into_owned();
    let (result, _) = load_with_env(
        &[format!("--appdata={app}"), "--simnet".to_string()],
        &default_home,
        &["DCROXIDE_APPDATA"],
    );
    assert!(result.is_ok(), "{:?}", result.err());

    // A `$VAR` in a path is `os.ExpandEnv`'s lookup.
    let (result, _) = load_with_env(
        &[
            format!("--appdata={app}"),
            "--simnet".to_string(),
            "--datadir=$DATA/chain".to_string(),
        ],
        &default_home,
        &["DATA"],
    );
    assert_eq!(result.err(), Some("refused DATA".to_string()));
}

/// The daemon refuses such a variable as it refuses such an argument,
/// usage line and all.  A `$HOME` so set had run it on the current
/// directory, a `DCROXIDE_APPDATA` on the default home.  A variable dcrd
/// does not read is no reason to refuse: `DCROXIDE_APPDATA` beside
/// `--appdata`, or before `-V` exits.
#[test]
fn the_daemon_refuses_an_environment_value_that_is_not_utf8() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();
    let home = format!("{root}/home");
    let run = |vars: &[(&str, &OsStr)], args: &[String]| {
        let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
            .env_clear()
            .envs(vars.iter().copied())
            .current_dir(dir.path())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run dcroxide");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    // Fails any load that gets past the refusal, so a regression exits
    // rather than starting a node.
    let invalid = "--maxorphantx=-1".to_string();
    let bad_appdata = [
        ("HOME", OsStr::new(&home)),
        ("DCROXIDE_APPDATA", raw(b"/srv/d\xe9")),
    ];

    let (ok, _, stderr) = run(&bad_appdata, std::slice::from_ref(&invalid));
    assert!(!ok);
    assert_eq!(
        stderr,
        "invalid UTF-8 in environment variable DCROXIDE_APPDATA: /srv/d\u{FFFD}\n\
         Use dcroxide -h to show usage\n"
    );
    assert!(
        !Path::new(&home).exists(),
        "the default home was left alone"
    );

    let (ok, _, stderr) = run(
        &[("HOME", raw(b"/home/j\xf6rg"))],
        std::slice::from_ref(&invalid),
    );
    assert!(!ok);
    assert_eq!(
        stderr,
        "invalid UTF-8 in environment variable HOME: /home/j\u{FFFD}rg\n\
         Use dcroxide -h to show usage\n"
    );
    assert!(
        !dir.path().join("dcroxide.conf").exists(),
        "nothing was written to the current directory"
    );

    let (ok, _, stderr) = run(
        &bad_appdata,
        &[
            format!("--appdata={root}/app"),
            "--simnet".to_string(),
            invalid.clone(),
        ],
    );
    assert!(!ok);
    assert_eq!(
        stderr,
        "loadConfig: the maxorphantx option may not be less than 0 -- parsed [-1]\n\
         Use dcroxide -h to show usage\n"
    );

    let (ok, stdout, stderr) = run(&bad_appdata, &["-V".to_string()]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("dcroxide version "), "{stdout}");
}

/// addblock's default data directory is under dcrd's `AppDataDir`, whose
/// `$HOME` the port read as unset when it was not UTF-8, importing into
/// `./data` instead.  It is refused before anything is opened.
#[test]
fn addblock_refuses_a_home_that_is_not_utf8() {
    let dir = tempfile::tempdir().expect("tempdir");
    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");
    let out = Command::new(env!("CARGO_BIN_EXE_addblock"))
        .env_clear()
        .env("HOME", raw(b"/home/j\xf6rg"))
        .current_dir(dir.path())
        .args(["--simnet", "--infile", infile.to_str().expect("utf8 path")])
        .stdin(Stdio::null())
        .output()
        .expect("run addblock");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{combined}");
    assert!(
        combined.contains("invalid UTF-8 in environment variable HOME: /home/j\u{FFFD}rg"),
        "{combined}"
    );
    assert!(
        !dir.path().join("data").exists(),
        "nothing was opened under ./data"
    );
}

/// The config file warning is the `*PathError` go-flags returns, with
/// its operation: `open` for a missing file, `read` for a directory.
#[test]
fn config_file_errors_are_go_path_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_string_lossy().into_owned();
    for (configfile, want) in [
        (
            format!("{home}/missing.conf"),
            format!("open {home}/missing.conf: no such file or directory"),
        ),
        (home.clone(), format!("read {home}: is a directory")),
    ] {
        let (result, _) = load(
            &[
                format!("--appdata={home}"),
                format!("--configfile={configfile}"),
                "--simnet".to_string(),
            ],
            dir.path(),
        );
        assert_eq!(result.expect("load").0.log_warnings, vec![want]);
    }
}

/// Go's `os.MkdirAll("")` fails, so dcrd exits on an empty `--appdata`;
/// `create_dir_all("")` succeeds, and the port ran on the default paths.
#[test]
fn an_empty_appdata_fails_as_go_mkdirall_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (result, _) = load(&args(&["--appdata=", "--simnet"]), dir.path());
    let err = result.err().expect("an empty home is refused");
    assert_eq!(
        err,
        "loadConfig: failed to create home directory: mkdir : no such file or directory"
    );
    assert!(!error_shows_usage(&err), "dcrd's errSuppressUsage");
}

/// The home directory error names the path component Go's `MkdirAll`
/// failed on, in Go's words, and a dangling symlink gets dcrd's hint.
#[test]
fn home_directory_errors_read_as_dcrd_writes_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();

    let file = format!("{root}/file");
    std::fs::write(&file, b"").expect("file");
    let (result, notices) = load(
        &[format!("--appdata={file}/home"), "--simnet".to_string()],
        dir.path(),
    );
    let err = result.err().expect("a file in the way");
    assert_eq!(
        err,
        format!("loadConfig: failed to create home directory: mkdir {file}: not a directory")
    );
    assert!(!error_shows_usage(&err));
    assert!(notices.is_empty(), "simnet creates no default config");

    let link = format!("{root}/link");
    std::os::unix::fs::symlink(format!("{root}/unmounted/target"), &link).expect("symlink");
    let (result, _) = load(
        &[format!("--appdata={link}"), "--simnet".to_string()],
        dir.path(),
    );
    assert_eq!(
        result.err(),
        Some(format!(
            "loadConfig: failed to create home directory: is symlink {link} -> \
             {root}/unmounted/target mounted?"
        ))
    );

    // Every other loadConfig error keeps the usage line.
    assert!(error_shows_usage(
        "loadConfig: the maxorphantx option may not be less than 0 -- parsed [-1]"
    ));
}

/// The clientcert rule without a CA file guards the RPC endpoint dcrd
/// would serve unauthenticated; with `--norpc` there is none, and dcrd
/// starts.
#[test]
fn clientcert_without_a_ca_file_is_refused_only_with_rpc_enabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_string_lossy().into_owned();
    let base = [
        format!("--appdata={home}"),
        "--simnet".to_string(),
        "--authtype=clientcert".to_string(),
        "--clientcafile=".to_string(),
    ];

    let (result, _) = load(&base, dir.path());
    assert_eq!(
        result.err(),
        Some("loadConfig: --authtype=clientcert requires --clientcafile".to_string())
    );

    let mut norpc = base.to_vec();
    norpc.push("--norpc".to_string());
    let (result, _) = load(&norpc, dir.path());
    assert!(result.expect("dcrd starts").0.disable_rpc);
}

/// dcrd's help pre-parse is built with `flags.PrintErrors`, so go-flags
/// echoes its error to stderr before the final parse reports it again;
/// behind `--` only the echo remains and dcrd runs.  A notice written
/// before a later failure stays written.
#[test]
fn parse_time_notices_are_written_as_dcrd_writes_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().to_string_lossy().into_owned();
    let appdata = format!("--appdata={home}");

    let (result, notices) = load(
        &[appdata.clone(), "--simnet".into(), "--maxpeers=abc".into()],
        dir.path(),
    );
    let err = result.err().expect("the final parse fails");
    assert!(err.contains("maxpeers"), "{err}");
    assert_eq!(notices, vec![err], "go-flags echoed it first");

    let (result, notices) = load(
        &[
            appdata.clone(),
            "--simnet".into(),
            "--".into(),
            "--maxpeers=abc".into(),
        ],
        dir.path(),
    );
    let (_, remaining) = result.expect("the final parse passes it through");
    assert_eq!(remaining, vec!["--maxpeers=abc".to_string()]);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].contains("maxpeers"), "{notices:?}");

    // The help flag ends go-flags' scan with `ErrHelp` where it
    // stands, so an error after it is never reached, let alone echoed.
    let (result, notices) = load(
        &[appdata.clone(), "-h".into(), "--maxpeers=abc".into()],
        dir.path(),
    );
    assert_eq!(result.err(), Some(ERR_HELP_REQUESTED.to_string()));
    assert!(notices.is_empty(), "{notices:?}");

    let (result, notices) = load(
        &[
            appdata,
            "--simnet".into(),
            "--nodnsseed".into(),
            "--maxorphantx=-1".into(),
        ],
        dir.path(),
    );
    assert!(result.is_err());
    assert_eq!(
        notices,
        vec!["The --nodnsseed option is deprecated: use --noseeders".to_string()]
    );
}

/// The daemon prints those notices even when the load then fails, and
/// leaves the usage line off the home directory error.
#[test]
fn the_daemon_prints_notices_and_suppresses_usage_as_dcrd_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();
    let run = |extra: &[String]| {
        let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
            .args(extra)
            .arg("--simnet")
            .output()
            .expect("run dcroxide");
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    let stderr = run(&[
        format!("--appdata={root}"),
        "--nodnsseed".to_string(),
        "--maxorphantx=-1".to_string(),
    ]);
    assert_eq!(
        stderr,
        "The --nodnsseed option is deprecated: use --noseeders\n\
         loadConfig: the maxorphantx option may not be less than 0 -- parsed [-1]\n\
         Use dcroxide -h to show usage\n"
    );

    let file = format!("{root}/file");
    std::fs::write(&file, b"").expect("file");
    let stderr = run(&[format!("--appdata={file}/home")]);
    assert_eq!(
        stderr,
        format!("loadConfig: failed to create home directory: mkdir {file}: not a directory\n")
    );
}
