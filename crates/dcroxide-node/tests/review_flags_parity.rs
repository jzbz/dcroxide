// SPDX-License-Identifier: ISC
//! The go-flags and Go standard library behaviours `loadConfig`
//! observes, end to end through the configuration pipeline, with the
//! outcomes and texts a go-flags v1.6.1 / Go 1.27 run over dcrd's config
//! struct gives:
//!
//! - The help option ends the help pre-parse with `ErrHelp` where it
//!   stands, so no argument after it, nor the rest of a short cluster,
//!   can turn the help into an error.
//! - An INI line with an empty key matches the first option through the
//!   empty `ini-name` tag, `ShowVersion`.
//! - The INI file is read whole for syntax first, and its values are
//!   then looked up and converted in order, so the first bad line of
//!   that walk is the one reported.
//! - Numbers, durations and quoted values convert, and fail, as Go's
//!   `strconv` and `time` do, and addresses split and join as `net`
//!   does.

use std::path::Path;

use dcroxide_node::ERR_HELP_REQUESTED;
use dcroxide_node::config::{Config, ConfigEnv, load_config_from_argv, normalize_addresses};

/// A load's result: the config and the remaining arguments, or the
/// error.
type Loaded = Result<(Config, Vec<String>), String>;

/// Load `args` (after an `--appdata` naming `home`) with `conf` as the
/// config file, named with `--configfile` as a file other than the
/// default so that simnet reads it too.
fn load(home: &Path, conf: &str, args: &[&str]) -> Loaded {
    std::fs::write(conf_path(home), conf).expect("write config");
    let env = ConfigEnv {
        default_home_dir: home.to_string_lossy().into_owned(),
        lookup_localhost: Box::new(|| Ok(vec!["::1".to_string(), "127.0.0.1".to_string()])),
        interface_by_name: Box::new(|_| None),
        getenv: Box::new(|_| None),
        user_home: Box::new(|_| None),
        rand_bytes: Box::new(|b: &mut [u8]| b.fill(0x42)),
    };
    let mut argv = vec![
        format!("--appdata={}", home.display()),
        format!("--configfile={}", conf_path(home)),
    ];
    argv.extend(args.iter().map(|a| a.to_string()));
    load_config_from_argv(&argv, &env)
}

/// The path of the config file [`load`] writes, as errors name it.
fn conf_path(home: &Path) -> String {
    home.join("test.conf").to_string_lossy().into_owned()
}

#[test]
fn help_wins_over_everything_after_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    for args in [
        &["-h", "--maxpeers=abc"][..],
        &["-h", "--nolisten=1"],
        &["-h", "--maxpeers"],
        // 'u' is never reached, so its missing argument is no error.
        &["-hu"],
        &["-hV=1"],
    ] {
        assert_eq!(
            load(dir.path(), "", args).err().as_deref(),
            Some(ERR_HELP_REQUESTED),
            "{args:?}"
        );
    }
    // An error before it still wins.
    let err = load(dir.path(), "", &["--maxpeers=abc", "-h"])
        .err()
        .expect("an error");
    assert_ne!(err, ERR_HELP_REQUESTED);
    assert!(err.contains("maxpeers"), "{err}");
}

#[test]
fn an_empty_ini_key_is_the_version_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    for conf in ["=\n", "= 1\n", "=true\n"] {
        let (cfg, _) = load(dir.path(), conf, &["--simnet"]).expect("dcrd starts");
        // The final config's flag, which dcrd never reads.
        assert!(cfg.show_version, "{conf:?}");
    }
    assert_eq!(
        load(dir.path(), "=foo\n", &["--simnet"]).err(),
        Some(format!(
            "Error parsing config file: {}:1: strconv.ParseBool: parsing \"foo\": invalid syntax",
            conf_path(dir.path())
        ))
    );
}

#[test]
fn ini_errors_come_in_go_flags_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = conf_path(dir.path());
    for (conf, want) in [
        // A conversion error ahead of a later unknown option.
        (
            "a=\n;\nmaxpeers=abc\n\n\n\nbogus=1\n",
            format!("{path}:3: strconv.ParseInt: parsing \"abc\": invalid syntax"),
        ),
        // An unknown option ahead of a later conversion error.
        (
            "bogus=1\nmaxpeers=abc\n",
            format!("{path}:1: unknown option: bogus"),
        ),
        // A syntax error anywhere ahead of an unknown section before it.
        (
            "[Bogus]\nx=1\n[Application Options]\nnokey\n",
            format!("{path}:4: malformed key=value (nokey)"),
        ),
        // A quoted value Unquote refuses is a syntax error too.
        (
            "maxpeers=abc\nrpcuser=\"a\\x+1\"\n",
            format!("{path}:2: invalid syntax"),
        ),
        // An unknown section with nothing else wrong.
        (
            "maxpeers=5\n[Bogus]\n",
            "could not find option group `Bogus'".to_string(),
        ),
        // A section named again continues its values.
        (
            "[Application Options]\nmaxpeers=5\n[application options]\nmaxpeers=abc\n",
            format!("{path}:4: strconv.ParseInt: parsing \"abc\": invalid syntax"),
        ),
    ] {
        assert_eq!(
            load(dir.path(), conf, &["--simnet"]).err(),
            Some(format!("Error parsing config file: {want}")),
            "{conf:?}"
        );
    }
}

#[test]
fn conversions_fail_and_succeed_as_go_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = |args: &[&str]| {
        load(dir.path(), "", args)
            .err()
            .expect("dcrd refuses to start")
    };

    // ParseInt / ParseUint report the overflow before the bad byte.
    let e = err(&["--simnet", "--maxpeers=99999999999999999999x"]);
    assert!(
        e.ends_with("strconv.ParseInt: parsing \"99999999999999999999x\": value out of range"),
        "{e}"
    );
    let e = err(&["--simnet", "--blockmaxsize=4294967296x"]);
    assert!(
        e.ends_with("strconv.ParseUint: parsing \"4294967296x\": value out of range"),
        "{e}"
    );

    // ParseFloat takes underscores and hex floats and refuses overflow.
    for (value, want) in [("0.000_1", 0.0001), ("0x1p-14", 6.103515625e-05)] {
        let arg = format!("--minrelaytxfee={value}");
        let (cfg, _) = load(dir.path(), "", &["--simnet", &arg]).expect("dcrd starts");
        assert_eq!(cfg.min_relay_tx_fee, want, "{value}");
    }
    let e = err(&["--simnet", "--limitfreerelay=1e400"]);
    assert!(
        e.ends_with("strconv.ParseFloat: parsing \"1e400\": value out of range"),
        "{e}"
    );

    // ParseDuration quotes with the time package's quote.
    let e = err(&["--simnet", "--banduration=1\u{b5}"]);
    assert!(
        e.ends_with(r#"time: unknown unit "\xc2\xb5" in duration "1\xc2\xb5""#),
        "{e}"
    );

    // Unquote: `\U` and UTF-8 byte escapes are taken, `\x+1` is not.
    let (cfg, _) = load(
        dir.path(),
        "rpcpass=\"p\\xc3\\xa9\"\nrpcuser=\"\\U0001F600\"\n",
        &["--simnet"],
    )
    .expect("dcrd starts");
    assert_eq!(cfg.rpc_pass, "p\u{e9}");
    assert_eq!(cfg.rpc_user, "\u{1f600}");
    let e = err(&["--simnet", "--rpcuser=\"a\\x+1\""]);
    assert!(e.ends_with("(expected string): invalid syntax"), "{e}");

    // SplitHostPort refuses a stray bracket after the port.
    let e = err(&["--simnet", "--proxy=[::1]:9050]"]);
    assert!(
        e.ends_with(
            "proxy address '[::1]:9050]' is invalid: address [::1]:9050]: unexpected ']' in address"
        ),
        "{e}"
    );
}

#[test]
fn addresses_normalize_as_go_net_does() {
    let none = |_: &str| None;
    // JoinHostPort brackets for a colon only.
    assert_eq!(
        normalize_addresses(&["host%zone".to_string()], "9108", 0, &none),
        vec!["host%zone:9108".to_string()]
    );
    // SplitHostPort refuses the stray '[', so the whole value is the
    // host.
    assert_eq!(
        normalize_addresses(&["[a[b]:80".to_string()], "9108", 0, &none),
        vec!["[[a[b]:80]:9108".to_string()]
    );
}
