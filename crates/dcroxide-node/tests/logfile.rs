// SPDX-License-Identifier: ISC
//! The daemon's log file, against dcrd's (`log.go:124-144`,
//! `config.go:866-907`, `dcrd.go:54-64`).  `--logdir`, `--logsize` and
//! `--nofilelogging` were parsed and validated, but standard output was
//! the only sink.  Now:
//!
//! - the file is `dcroxide.log` where dcrd's is `dcrd.log`, in the log
//!   directory with the network's name appended, which is `logs` under
//!   the home directory unless `--logdir` names another;
//! - every log line standard output carries is written to it, in the
//!   same order, through `Shutdown complete`, and a restart appends;
//! - the directories it creates are owner-only;
//! - under `--nofilelogging` there is none, and the log directory is
//!   neither namespaced nor created;
//! - the file is opened where dcrd's is, as soon as `--logsize` parses,
//!   so `--debuglevel=show` and a configuration refused later leave it
//!   behind, empty;
//! - a log directory that cannot be made, or a log file that cannot be
//!   opened, fails the start there with dcrd's line on standard error,
//!   status 1 and nothing on standard output, ahead of
//!   `--debuglevel=show` and every later refusal.
//!
//! The rotation itself is pinned by the tests of the `logrotate`
//! module.

use std::path::Path;

use dcroxide_node::config::{Config, ConfigEnv, load_config_from_argv};

/// Load a configuration over `args` with the default home `home`.
fn load(home: &Path, args: &[&str]) -> Result<Config, String> {
    let env = ConfigEnv {
        default_home_dir: home.to_string_lossy().into_owned(),
        lookup_localhost: Box::new(|| Ok(vec!["::1".to_string(), "127.0.0.1".to_string()])),
        interface_by_name: Box::new(|_| None),
        getenv: Box::new(|_: &str| None),
        user_home: Box::new(|_| None),
        rand_bytes: Box::new(|b: &mut [u8]| b.fill(0x42)),
    };
    let args: Vec<String> = args.iter().map(ToString::to_string).collect();
    load_config_from_argv(&args, &env).map(|(cfg, _)| cfg)
}

/// The log file is `dcroxide.log` in `<home>/logs/<network>`, follows
/// `--appdata` unless `--logdir` is given, and takes the network's name
/// under `--logdir` too.
#[test]
fn the_log_file_is_in_the_networks_log_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let root = dir.path().to_string_lossy().into_owned();
    let home_str = home.to_string_lossy().into_owned();

    for (flag, network) in [
        (None, "mainnet"),
        (Some("--testnet"), "testnet3"),
        (Some("--simnet"), "simnet"),
        (Some("--regnet"), "regnet"),
    ] {
        let cfg = load(&home, flag.as_slice()).expect("load");
        assert_eq!(
            cfg.log_file(),
            format!("{home_str}/logs/{network}/dcroxide.log"),
            "{network}"
        );
    }

    let appdata = format!("--appdata={root}/app");
    let cfg = load(&home, &["--simnet", &appdata]).expect("load");
    assert_eq!(
        cfg.log_file(),
        format!("{root}/app/logs/simnet/dcroxide.log")
    );

    let logdir = format!("--logdir={root}/elsewhere/");
    let cfg = load(&home, &["--simnet", &appdata, &logdir]).expect("load");
    assert_eq!(
        cfg.log_file(),
        format!("{root}/elsewhere/simnet/dcroxide.log")
    );
}

/// `--nofilelogging` skips the log directory's namespacing and the
/// `--logsize` parse, as dcrd's `loadConfig` does, so a size that would
/// be refused is not.
#[test]
fn nofilelogging_leaves_the_log_options_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let home_str = home.to_string_lossy().into_owned();

    let cfg = load(&home, &["--simnet", "--nofilelogging", "--logsize=10"]).expect("load");
    assert!(cfg.no_file_logging);
    assert_eq!(cfg.log_dir, format!("{home_str}/logs"));

    assert_eq!(
        load(&home, &["--simnet", "--logsize=10"]).err().as_deref(),
        Some("loadConfig: Invalid logsize: 10 ")
    );
}

/// Runs of the daemon itself.  Each exits by itself, without a signal
/// or a deadline: the network's block database path is a regular file,
/// so the start fails at the block database, having logged its first
/// lines, and logs `Shutdown complete`.
#[cfg(unix)]
mod daemon {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    /// A home directory and a data directory whose simnet block
    /// database cannot be created.
    struct Dirs {
        _root: tempfile::TempDir,
        root: PathBuf,
        appdata: PathBuf,
        datadir: PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().to_path_buf();
        let appdata = path.join("app");
        let datadir = path.join("data");
        std::fs::create_dir(&datadir).expect("datadir");
        std::fs::write(datadir.join("simnet"), b"").expect("blocker");
        Dirs {
            _root: root,
            root: path,
            appdata,
            datadir,
        }
    }

    /// Run the daemon on simnet in `dirs` to its exit.
    fn run(dirs: &Dirs, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dcroxide"))
            .arg("--simnet")
            .arg(format!("--appdata={}", dirs.appdata.display()))
            .arg(format!("--datadir={}", dirs.datadir.display()))
            .args(["--norpc", "--nolisten", "--noseeders"])
            .args(args)
            .env_remove("DCROXIDE_APPDATA")
            .stdin(Stdio::null())
            .output()
            .expect("run dcroxide")
    }

    /// The log lines of standard output: everything but the banner and
    /// the blank line after it, which are not log lines in this port
    /// and have no counterpart in dcrd.
    fn log_lines(stdout: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(stdout)
            .lines()
            .filter(|line| line.get(23..25) == Some(" ["))
            .map(str::to_string)
            .collect()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// Every log line goes to `<home>/logs/simnet/dcroxide.log` as well,
    /// in standard output's order and with nothing else; the directories
    /// are made owner-only; and a second start appends its lines.
    #[test]
    fn every_log_line_reaches_the_log_file() {
        let dirs = dirs();
        let out = run(&dirs, &[]);
        assert_eq!(out.status.code(), Some(1));
        let first = log_lines(&out.stdout);
        assert!(
            first
                .last()
                .is_some_and(|l| l.ends_with("[INF] DCRD: Shutdown complete")),
            "{first:?}"
        );
        assert!(
            first
                .iter()
                .any(|l| l.contains("[ERR] DCRD: Unable to load block database")),
            "{first:?}"
        );

        let logs = dirs.appdata.join("logs");
        let file = logs.join("simnet").join("dcroxide.log");
        let content = std::fs::read_to_string(&file).expect("log file");
        assert_eq!(content, format!("{}\n", first.join("\n")));
        assert_eq!(mode(&logs), 0o700);
        assert_eq!(mode(&logs.join("simnet")), 0o700);
        assert_eq!(mode(&file) & !0o644, 0, "the log file is created 0644");

        let out = run(&dirs, &[]);
        let second = log_lines(&out.stdout);
        let both: Vec<String> = first.iter().chain(&second).cloned().collect();
        assert_eq!(
            std::fs::read_to_string(&file).expect("log file"),
            format!("{}\n", both.join("\n"))
        );
    }

    /// `--logdir` moves the file, with the network's name appended.
    #[test]
    fn logdir_moves_the_log_file() {
        let dirs = dirs();
        let elsewhere = dirs.root.join("elsewhere");
        let out = run(&dirs, &[&format!("--logdir={}", elsewhere.display())]);
        let lines = log_lines(&out.stdout);
        let content = std::fs::read_to_string(elsewhere.join("simnet").join("dcroxide.log"))
            .expect("log file");
        assert_eq!(content, format!("{}\n", lines.join("\n")));
        assert!(!dirs.appdata.join("logs").exists());
    }

    /// Under `--nofilelogging` the daemon says so and writes no file,
    /// nor any log directory.
    #[test]
    fn nofilelogging_writes_no_file() {
        let dirs = dirs();
        let out = run(&dirs, &["--nofilelogging"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            log_lines(&out.stdout)
                .iter()
                .any(|l| l.ends_with("[INF] DCRD: File logging disabled")),
        );
        assert!(!dirs.appdata.join("logs").exists());
    }

    /// A log directory that cannot be made ends the start as dcrd's
    /// `initLogRotator` does: the `*PathError` of `os.MkdirAll` on
    /// standard error, no usage line, nothing on standard output, and
    /// status 1.
    #[test]
    fn a_log_directory_that_cannot_be_made_fails_the_start() {
        let dirs = dirs();
        let blocker = dirs.root.join("blocker");
        std::fs::write(&blocker, b"").expect("blocker");
        let out = run(&dirs, &[&format!("--logdir={}", blocker.display())]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!(
                "failed to create log directory: mkdir {}: not a directory\n",
                blocker.display()
            )
        );
        assert!(out.stdout.is_empty());
    }

    /// A log file that cannot be opened ends the start the same way,
    /// with the `*PathError` of `rotator.New`'s open.
    #[test]
    fn a_log_file_that_cannot_be_opened_fails_the_start() {
        let dirs = dirs();
        let logs = dirs.root.join("logs");
        let file = logs.join("simnet").join("dcroxide.log");
        std::fs::create_dir_all(&file).expect("a directory where the file goes");
        let out = run(&dirs, &[&format!("--logdir={}", logs.display())]);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!(
                "failed to create file rotator: open {}: is a directory\n",
                file.display()
            )
        );
        assert!(out.stdout.is_empty());
    }

    /// The file is opened where dcrd opens it, straight after the
    /// `--logsize` parse: a log directory that cannot be made fails the
    /// start ahead of the `--debuglevel=show` exit and of a configuration
    /// refused later, and a good one is left behind by both, with the
    /// file in it empty.
    #[test]
    fn the_log_file_is_opened_where_dcrds_is() {
        let dirs = dirs();
        let blocker = dirs.root.join("blocker");
        std::fs::write(&blocker, b"").expect("blocker");
        let bad = format!("--logdir={}", blocker.display());
        let refusal = format!(
            "failed to create log directory: mkdir {}: not a directory\n",
            blocker.display()
        );
        for later in ["--debuglevel=show", "--dbtype=bogus"] {
            let out = run(&dirs, &[&bad, later]);
            assert_eq!(out.status.code(), Some(1), "{later}");
            assert_eq!(String::from_utf8_lossy(&out.stderr), refusal, "{later}");
            assert!(out.stdout.is_empty(), "{later}");
        }

        let file = dirs
            .appdata
            .join("logs")
            .join("simnet")
            .join("dcroxide.log");
        let out = run(&dirs, &["--debuglevel=show"]);
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("Supported subsystems "));
        assert_eq!(std::fs::read(&file).expect("log file"), b"");
        std::fs::remove_file(&file).expect("remove");

        let out = run(&dirs, &["--dbtype=bogus"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .starts_with("loadConfig: the specified database type [bogus] is invalid"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(&file).expect("log file"), b"");
    }
}
