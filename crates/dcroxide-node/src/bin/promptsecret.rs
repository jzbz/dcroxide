// SPDX-License-Identifier: ISC
//! The `promptsecret` tool (dcrd `cmd/promptsecret`): prompt for a
//! secret on the terminal with echo disabled and write it to stdout,
//! `-n` times.  The prompt and errors go to stderr so the secret on
//! stdout can be piped; the buffer is zeroed after the write.
//!
//! dcrd reads the secret through `golang.org/x/term.ReadPassword`,
//! which flips the terminal's echo flag in-process.  The workspace
//! forbids unsafe code, so the port flips the same termios bit
//! through `stty` on unix — a non-terminal stdin fails exactly like
//! Go's `ReadPassword` on a pipe — and reports echo control as
//! unsupported on windows (where the console API requires unsafe
//! calls; the Windows service wrapper is likewise not ported).
//! Go's `flag` package drives the tiny command line, so its exit
//! codes and error texts are kept: parse errors print the message
//! and usage and exit 2, `-h` prints the usage and exits 0.

// The argument walk mirrors Go's arithmetic over bounded indexes.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};

/// Go `flag` package usage text for the one option.
const USAGE: &str = "Usage of promptsecret:\n  -n int\n    \tprompt n times (default 1)\n";

/// How the command line parse ended.
enum ParsedArgs {
    Run(i64),
    Help,
    Error(String),
}

/// Parse the command line like Go's `flag` package over the single
/// `-n` int flag: `-n=5`, `-n 5`, and the double-dash forms are
/// accepted, parsing stops at the first non-flag argument, and `-h`
/// or `--help` requests the usage.
fn parse_args(args: &[String]) -> ParsedArgs {
    let mut n: i64 = 1;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // Go flag: a non-flag argument, a bare "-", or "--" terminates
        // flag parsing.
        if !arg.starts_with('-') || arg == "-" || arg == "--" {
            break;
        }
        // Go flag strips one or two dashes; a remaining name that is
        // empty or starts with '-' or '=' is a syntax error.
        let name_val = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .expect("checked above");
        if name_val.is_empty() || name_val.starts_with('-') || name_val.starts_with('=') {
            return ParsedArgs::Error(format!("bad flag syntax: {arg}"));
        }
        let (name, inline) = match name_val.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (name_val, None),
        };
        match name {
            "n" => {
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                return ParsedArgs::Error("flag needs an argument: -n".to_string());
                            }
                        }
                    }
                };
                // Go flag normalizes strconv failures to "parse error"
                // and range failures to "value out of range".
                match parse_go_flag_int(&value) {
                    Ok(v) => n = v,
                    Err(e) => {
                        return ParsedArgs::Error(format!(
                            "invalid value \"{value}\" for flag -n: {e}"
                        ));
                    }
                }
            }
            "h" | "help" => return ParsedArgs::Help,
            other => {
                return ParsedArgs::Error(format!("flag provided but not defined: -{other}"));
            }
        }
        i += 1;
    }
    ParsedArgs::Run(n)
}

/// Go `strconv.ParseInt(s, 0, 64)` as the `flag` package surfaces it:
/// one leading sign, base prefixes, Go's underscore placement rules
/// (between digits, or between the base prefix and a digit), and
/// `parse error` / `value out of range` as the normalized messages.
fn parse_go_flag_int(s: &str) -> Result<i64, &'static str> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    // Go's underscoreOK runs over the unsigned remainder before the
    // prefix is stripped, so the prefix counts as digits.
    if !underscore_ok(rest) {
        return Err("parse error");
    }
    let (radix, digits) =
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, hex)
        } else if let Some(bin) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
            (2, bin)
        } else if let Some(oct) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
            (8, oct)
        } else if rest.len() > 1 && rest.starts_with('0') {
            (8, &rest[1..])
        } else {
            (10, rest)
        };
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    // Go's ParseUint over the remainder rejects any interior sign
    // (from_str_radix would accept one), and requires digits.
    if cleaned.is_empty() || cleaned.starts_with('-') || cleaned.starts_with('+') {
        return Err("parse error");
    }
    // Parse with the sign attached so i64::MIN round-trips exactly.
    let signed = if neg { format!("-{cleaned}") } else { cleaned };
    match i64::from_str_radix(&signed, radix) {
        Ok(v) => Ok(v),
        Err(e) => match e.kind() {
            std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => {
                Err("value out of range")
            }
            _ => Err("parse error"),
        },
    }
}

/// Go `strconv`'s `underscoreOK` over an unsigned numeric literal:
/// underscores may only sit between digits, counting a base prefix's
/// characters as digits (so `0x_1` and `0_1` are fine while `_1`,
/// `1_`, and `1__2` are not).
fn underscore_ok(s: &str) -> bool {
    // saw tracks the previous character class: '^' start, '0' digit
    // (or prefix), '_' underscore, '!' anything else.
    let mut saw = '^';
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut hex = false;
    if bytes.len() >= 2
        && bytes[0] == b'0'
        && matches!(bytes[1].to_ascii_lowercase(), b'b' | b'o' | b'x')
    {
        saw = '0';
        hex = bytes[1].eq_ignore_ascii_case(&b'x');
        i = 2;
    }
    while i < bytes.len() {
        let c = bytes[i];
        let digit = c.is_ascii_digit() || (hex && c.to_ascii_lowercase().is_ascii_hexdigit());
        if digit {
            saw = '0';
        } else if c == b'_' {
            if saw != '0' {
                return false;
            }
            saw = '_';
        } else {
            if saw == '_' {
                return false;
            }
            saw = '!';
        }
        i += 1;
    }
    saw != '_'
}

/// Snapshot the terminal state and enter the password-reading mode
/// via `stty` (the unsafe-free stand-in for x/term's in-process
/// termios calls): the saved `stty -g` form restores the ORIGINAL
/// state afterward exactly as x/term restores its snapshot, and the
/// entered mode is x/term's — echo off with canonical mode, signals,
/// and CR-to-NL mapping forced on.  `stty` reads the terminal from
/// its inherited stdin, so a piped stdin fails with the same
/// inappropriate-ioctl condition Go's `ReadPassword` surfaces.
#[cfg(unix)]
fn enter_password_mode() -> Result<String, String> {
    let saved = std::process::Command::new("stty")
        .arg("-g")
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !saved.status.success() {
        // The message Go's syscall error renders for a non-terminal
        // stdin, the overwhelmingly common failure here.
        return Err("inappropriate ioctl for device".to_string());
    }
    let saved = String::from_utf8_lossy(&saved.stdout).trim().to_string();

    let status = std::process::Command::new("stty")
        .args(["-echo", "icanon", "isig", "icrnl"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("inappropriate ioctl for device".to_string());
    }
    Ok(saved)
}

#[cfg(unix)]
fn restore_terminal(saved: &str) {
    let _ = std::process::Command::new("stty")
        .arg(saved)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn enter_password_mode() -> Result<String, String> {
    Err("terminal echo control is not supported on this platform".to_string())
}

#[cfg(not(unix))]
fn restore_terminal(_saved: &str) {}

/// Read a secret from stdin with terminal echo disabled (Go
/// `term.ReadPassword` over x/term's `readPasswordLine`): the line up
/// to the newline, with backspaces applied destructively and carriage
/// returns skipped.  A read that ends at EOF with bytes in hand
/// returns them; an immediate EOF is an error, like Go's.
fn read_password() -> Result<Vec<u8>, String> {
    let saved = enter_password_mode()?;

    let mut secret = Vec::new();
    let mut byte = [0u8; 1];
    let result = loop {
        match std::io::stdin().read(&mut byte) {
            Ok(0) => {
                if secret.is_empty() {
                    break Err("EOF".to_string());
                }
                break Ok(());
            }
            Ok(_) => match byte[0] {
                b'\x08' => {
                    // x/term treats a raw backspace destructively.
                    secret.pop();
                }
                b'\n' => break Ok(()),
                // x/term skips carriage returns on unix (the enter
                // key arrives as newline through the ICRNL mapping).
                b'\r' => {}
                other => secret.push(other),
            },
            Err(e) => break Err(e.to_string()),
        }
    };

    // Always restore the original terminal state.
    restore_terminal(&saved);

    match result {
        Ok(()) => Ok(secret),
        Err(e) => {
            zero(&mut secret);
            Err(e)
        }
    }
}

/// Zero the secret buffer (dcrd's `zero`); the `black_box` keeps the
/// stores from being optimized away as writes to a dead buffer.
fn zero(b: &mut [u8]) {
    b.fill(0);
    std::hint::black_box(&*b);
}

/// One prompt round (dcrd `prompt`): the prompt and the closing
/// newline go to stderr, the secret and its newline to stdout, and
/// either failure exits 1 after zeroing.
fn prompt() {
    eprint!("Secret: ");
    let secret = read_password();
    eprintln!();
    let mut secret = match secret {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("unable to read secret: {e}");
            std::process::exit(1);
        }
    };

    let written = std::io::stdout().write_all(&secret);
    zero(&mut secret);
    if let Err(e) = written {
        eprintln!("unable to write to stdout: {e}");
        std::process::exit(1);
    }
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let n = match parse_args(&args) {
        ParsedArgs::Run(n) => n,
        ParsedArgs::Help => {
            // Go flag prints the usage and exits 0 for -h.
            eprint!("{USAGE}");
            std::process::exit(0);
        }
        ParsedArgs::Error(msg) => {
            // Go flag prints the error, then the usage, and exits 2.
            eprintln!("{msg}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };

    for _ in 0..n {
        prompt();
    }
}
