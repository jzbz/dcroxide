// SPDX-License-Identifier: ISC
//! The `gencerts` tool (dcrd `cmd/gencerts`): generate a self-signed
//! certificate authority — or a certificate issued by one — over the
//! ported certificate machinery, with dcrd's go-flags command line
//! and exit codes (help exits 0, parse and fatal errors exit 1, a
//! wrong argument count prints the help to stderr and exits 2).

use std::io::Write;

use dcroxide_certgen::gentool::{
    GenEnv, create_issued_cert, generate_authority, generate_key, load_ca_pair, pem_private_key,
};
use dcroxide_node::flags::{OptKind, OptSpec, ScanMode};

/// The gencerts option registry (the go-flags struct tags of dcrd's
/// `config`, plus the help option go-flags registers itself).
const GENCERTS_OPTIONS: [OptSpec; 10] = [
    OptSpec {
        long: "",
        short: Some('C'),
        field: "CA",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "",
        short: Some('K'),
        field: "CAKey",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "",
        short: Some('H'),
        field: "Hosts",
        kind: OptKind::StrSlice,
    },
    OptSpec {
        long: "",
        short: Some('L'),
        field: "Local",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "",
        short: Some('S'),
        field: "Signs",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "",
        short: Some('o'),
        field: "Org",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "",
        short: Some('a'),
        field: "Algo",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "",
        short: Some('y'),
        field: "Years",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "",
        short: Some('f'),
        field: "Force",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "help",
        short: Some('h'),
        field: "Help",
        kind: OptKind::Bool,
    },
];

/// The help text (go-flags `WriteHelp` renders this from the struct
/// tags; hand-written like the daemon's not-yet-generated help).
const GENCERTS_HELP: &str = "\
Usage:
  gencerts [OPTIONS] cert key

Application Options:
  -C=  sign generated certificate using CA cert (requires -K)
  -K=  key of CA certificate
  -H=  hostname or IP certificate is valid for; may be specified multiple times
  -L   append localhost, 127.0.0.1, and ::1 to hosts if not already specified
  -S   allow certificate to sign leaf certificates
  -o=  organization
  -a=  key algorithm (one of: P-256, P-384, P-521, Ed25519, RSA4096)
  -y=  years certificate is valid for
  -f   overwrite existing certs/keys

Help Options:
  -h, --help  Show this help message
";

/// dcrd's `fatalf`: the message to stderr and exit 1.
fn fatalf(msg: &str) -> ! {
    eprint!("{msg}");
    std::process::exit(1);
}

/// dcrd's `usage`: the help to stderr and exit 2.
fn usage() -> ! {
    eprint!("{GENCERTS_HELP}");
    std::process::exit(2);
}

/// The parsed configuration with dcrd's defaults.
struct Config {
    ca: String,
    ca_key: String,
    hosts: Vec<String>,
    local: bool,
    signs: bool,
    org: String,
    algo: String,
    years: i64,
    force: bool,
}

/// The real clock and randomness (Go `time.Now` and dcrd
/// `crypto/rand`).
struct OsEnv;

impl GenEnv for OsEnv {
    fn now_unix(&mut self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn serial_bytes(&mut self) -> Vec<u8> {
        // A uniform value below 2^128 (dcrd `rand.BigInt` over
        // `serialNumberLimit`).
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("system randomness");
        bytes.to_vec()
    }
}

/// Write a file with the given unix permission bits (Go
/// `os.WriteFile`'s mode; no-op permissions off unix).
fn write_file(name: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = open.open(name)?;
    f.write_all(data)
}

fn main() {
    let mut cfg = Config {
        ca: String::new(),
        ca_key: String::new(),
        hosts: Vec::new(),
        local: false,
        signs: false,
        org: "gencerts".to_string(),
        algo: "P-256".to_string(),
        years: 10,
        force: false,
    };
    let mut help = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (state, err) = dcroxide_node::flags::scan_args_in(
        &GENCERTS_OPTIONS,
        &mut |spec, value| {
            let val = value.unwrap_or("");
            match spec.field {
                "CA" => cfg.ca = val.to_string(),
                "CAKey" => cfg.ca_key = val.to_string(),
                "Hosts" => cfg.hosts.push(val.to_string()),
                "Local" => cfg.local = true,
                "Signs" => cfg.signs = true,
                "Org" => cfg.org = val.to_string(),
                "Algo" => cfg.algo = val.to_string(),
                "Force" => cfg.force = true,
                "Years" => cfg.years = dcroxide_node::go_parse_int(val, 64)?,
                "Help" => help = true,
                _ => {}
            }
            Ok(())
        },
        &args,
        ScanMode::PassDoubleDash,
    );
    // go-flags help exits 0 here (unlike addblock, gencerts' main
    // special-cases ErrHelp before the generic exit-1).
    if help {
        print!("{GENCERTS_HELP}");
        std::process::exit(0);
    }
    if let Some(err) = err {
        // go-flags' PrintErrors writes the message; main exits 1.
        eprintln!("{}", err.message());
        std::process::exit(1);
    }
    if state.retargs.len() != 2 {
        usage();
    }
    let certname = state.retargs[0].clone();
    let keyname = state.retargs[1].clone();

    // The algorithm selection precedes every other check (dcrd's
    // keygen switch with its %q-quoted unknown-algorithm error).
    if !matches!(
        cfg.algo.as_str(),
        "P-256" | "P-384" | "P-521" | "Ed25519" | "RSA4096"
    ) {
        eprintln!("unknown algorithm \"{}\"", cfg.algo);
        usage();
    }

    if (cfg.ca.is_empty()) != (cfg.ca_key.is_empty()) {
        fatalf("-C and -K must be used together\n");
    }

    if cfg.local {
        let mut localhost = false;
        let mut v4 = false;
        let mut v6 = false;
        for h in &cfg.hosts {
            match h.as_str() {
                "localhost" => localhost = true,
                "127.0.0.1" => v4 = true,
                "::1" => v6 = true,
                _ => {}
            }
        }
        if !localhost {
            cfg.hosts.push("localhost".to_string());
        }
        if !v4 {
            cfg.hosts.push("127.0.0.1".to_string());
        }
        if !v6 {
            cfg.hosts.push("::1".to_string());
        }
    }

    let key = generate_key(&cfg.algo).expect("validated above");
    let key_der = match key.marshal_pkcs8() {
        Ok(der) => der,
        Err(e) => fatalf(&format!("{e}\n")),
    };
    let key_block = pem_private_key(&key_der);

    let mut env = OsEnv;
    let cert = if cfg.ca.is_empty() {
        match generate_authority(&mut env, &key, &cfg.hosts, &cfg.org, cfg.years, cfg.signs) {
            Ok(cert) => cert,
            Err(e) => fatalf(&format!("generate certificate authority: {e}\n")),
        }
    } else {
        let ca_pem = match std::fs::read(&cfg.ca) {
            Ok(pem) => pem,
            Err(e) => fatalf(&format!("open CA keypair: {e}\n")),
        };
        let ca_key_pem = match std::fs::read(&cfg.ca_key) {
            Ok(pem) => pem,
            Err(e) => fatalf(&format!("open CA keypair: {e}\n")),
        };
        let (ca, ca_key) = match load_ca_pair(&ca_pem, &ca_key_pem) {
            Ok(pair) => pair,
            Err(e) => fatalf(&format!("open CA keypair: {e}\n")),
        };
        match create_issued_cert(
            &mut env, &key, &ca, &ca_key, &cfg.hosts, &cfg.org, cfg.years, cfg.signs,
        ) {
            Ok(cert) => cert,
            Err(e) => fatalf(&format!("issue certificate: {e}\n")),
        }
    };

    // Go's fileExists treats any stat error other than not-found as
    // existing.
    let file_exists = |name: &str| match std::fs::metadata(name) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    };
    if !cfg.force && file_exists(&certname) {
        fatalf(&format!("certificate file \"{certname}\" already exists\n"));
    }
    if !cfg.force && file_exists(&keyname) {
        fatalf(&format!("key file \"{keyname}\" already exists\n"));
    }

    if let Err(e) = write_file(&certname, &cert.pem, 0o644) {
        fatalf(&format!("cannot write cert: {e}\n"));
    }
    if let Err(e) = write_file(&keyname, &key_block, 0o600) {
        let _ = std::fs::remove_file(&certname);
        fatalf(&format!("cannot write key: {e}\n"));
    }
}
