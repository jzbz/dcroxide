// SPDX-License-Identifier: ISC
//! A `$HOME` that is not UTF-8 is refused only when the default home is
//! the home.  dcrd reads `$HOME` for its default home at package init
//! (`dcrutil.AppDataDir`), but with `--appdata` or `DCRD_APPDATA` set
//! `loadConfig` replaces everything derived from it (`config.go:692-727`)
//! and starts; the port refused it whatever the command line said.  The
//! same held for addblock beside `--datadir`.  A path given beside the
//! named home must not be taken for a default the refused `$HOME` would
//! have produced, and a `~` that meets the bad `$HOME` again is refused.

#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};

/// Run the daemon with `HOME` set to bytes that are not UTF-8 and every
/// other variable in `vars`, returning its stderr.  `--maxorphantx=-1`
/// fails any load that gets past the environment checks, so the run
/// exits rather than starting a node.
fn run_with_bad_home(dir: &std::path::Path, vars: &[(&str, &str)], args: &[String]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .env_clear()
        .env("HOME", OsStr::from_bytes(b"/home/j\xf6rg"))
        .envs(vars.iter().copied())
        .current_dir(dir)
        .args(args)
        .arg("--maxorphantx=-1")
        .stdin(Stdio::null())
        .output()
        .expect("run dcroxide");
    assert!(!out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const PAST_THE_ENVIRONMENT: &str = "loadConfig: the maxorphantx option may not be less than 0 \
     -- parsed [-1]\nUse dcroxide -h to show usage\n";

#[test]
fn a_bad_home_beside_appdata_is_not_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();

    let stderr = run_with_bad_home(
        dir.path(),
        &[],
        &[format!("--appdata={root}/app"), "--simnet".to_string()],
    );
    assert_eq!(stderr, PAST_THE_ENVIRONMENT);

    let appdata = format!("{root}/env-app");
    let stderr = run_with_bad_home(
        dir.path(),
        &[("DCROXIDE_APPDATA", &appdata)],
        &["--simnet".to_string()],
    );
    assert_eq!(stderr, PAST_THE_ENVIRONMENT);

    // Without either, the default home is the home, and it is refused
    // before anything is written under it.
    let stderr = run_with_bad_home(dir.path(), &[], &["--simnet".to_string()]);
    assert_eq!(
        stderr,
        "invalid UTF-8 in environment variable HOME: /home/j\u{FFFD}rg\n\
         Use dcroxide -h to show usage\n"
    );
    assert!(
        !dir.path().join("dcroxide.conf").exists() && !dir.path().join("data").exists(),
        "nothing was written to the current directory"
    );
}

/// No path given on the command line is taken for a default the refused
/// `$HOME` would have produced.  dcrd's defaults hold that variable's
/// raw bytes, which no argument can spell, so `--appdata=.` names a home
/// and `--configfile=dcroxide.conf` names a file of its own.  The "."
/// the port's lookup fell back to matched both: the first was refused as
/// the default home, and the second was moved into the named home, with
/// a default config file created there.
#[test]
fn a_path_beside_a_bad_home_is_not_taken_for_a_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();

    let stderr = run_with_bad_home(
        dir.path(),
        &[],
        &["--appdata=.".to_string(), "--simnet".to_string()],
    );
    assert_eq!(stderr, PAST_THE_ENVIRONMENT);

    // Off simnet, dcrd creates a config file only for the default one.
    let stderr = run_with_bad_home(
        dir.path(),
        &[],
        &[
            format!("--appdata={root}/app"),
            "--configfile=dcroxide.conf".to_string(),
        ],
    );
    assert_eq!(stderr, PAST_THE_ENVIRONMENT);
    assert!(
        !dir.path().join("app").join("dcroxide.conf").exists(),
        "the named config file stayed where it was named"
    );
    assert!(
        !dir.path().join("dcroxide.conf").exists(),
        "no default config file was created for a named one"
    );
}

/// On Apple platforms std's lookup for a leading `~` takes `$HOME` before
/// the directory service Go asks, so a `~` beside `--appdata` meets the
/// bad `$HOME` again.  It is refused, as on the other unixes, rather than
/// read as no home and `~/d` run on `./d`.
#[cfg(target_vendor = "apple")]
#[test]
fn a_tilde_beside_appdata_refuses_a_bad_home_on_apple() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();
    let stderr = run_with_bad_home(
        dir.path(),
        &[],
        &[
            format!("--appdata={root}/app"),
            "--datadir=~/d".to_string(),
            "--simnet".to_string(),
        ],
    );
    assert_eq!(
        stderr,
        "invalid UTF-8 in environment variable HOME: /home/j\u{FFFD}rg\n\
         Use dcroxide -h to show usage\n"
    );
}

/// addblock likewise: dcrd's `cmd/addblock` reads `$HOME` for its default
/// data directory at package init, and a `--datadir` of its own leaves
/// that unused, so the import runs.  Without one the default is the data
/// directory, and the port refuses the `$HOME` it came from.
#[test]
fn addblock_takes_a_bad_home_beside_datadir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let infile = dir.path().join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");
    let run = |extra: &[String]| {
        let out = Command::new(env!("CARGO_BIN_EXE_addblock"))
            .env_clear()
            .env("HOME", OsStr::from_bytes(b"/home/j\xf6rg"))
            .current_dir(dir.path())
            .args(["--simnet", "--infile", infile.to_str().expect("utf8 path")])
            .args(extra)
            .stdin(Stdio::null())
            .output()
            .expect("run addblock");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), combined)
    };
    let refusal = "invalid UTF-8 in environment variable HOME";

    let datadir = dir.path().join("own");
    let (ok, combined) = run(&[format!("--datadir={}", datadir.display())]);
    assert!(ok, "{combined}");
    assert!(!combined.contains(refusal), "{combined}");
    assert!(
        datadir.join("simnet").exists(),
        "the import ran: {combined}"
    );

    // A `--datadir` spelling the "." default the port's lookup fell back
    // to is still one of its own: dcrd's default holds the bad bytes.
    let (ok, combined) = run(&["--datadir=./data".to_string()]);
    assert!(ok, "{combined}");
    assert!(!combined.contains(refusal), "{combined}");
    assert!(
        dir.path().join("data").join("simnet").exists(),
        "the import ran: {combined}"
    );

    let (ok, combined) = run(&[]);
    assert!(!ok, "{combined}");
    assert!(combined.contains(refusal), "{combined}");
}
