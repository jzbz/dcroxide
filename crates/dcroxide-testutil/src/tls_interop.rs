// SPDX-License-Identifier: ISC
//! The TLS interop tests' harness: the oracle's TLS commands
//! (`tools/oracle/tls.go`) run under dcrd's `GODEBUG`, and what the two
//! matrices, `dcroxide-tlscrypto`'s `tests/go_interop.rs` and
//! `dcroxide-node`'s `tests/tls_interop.rs`, share: certificates from
//! `tls_pki`, Go's report of what a connection negotiated, and the
//! client-certificate cells with each one's verdict today, so that Go's
//! client-certificate set (ADR-0015, T4) changes them in one place.  None
//! of it touches rustls: each matrix drives its own TLS ends.

use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::time::Instant;

use serde_json::{Value, json};

use crate::{Oracle, REFERENCE_GO, hex, oracle_or_skip_with_env, require_reference_go, unhex};

/// The `GODEBUG` the TLS interop tests run the oracle under: dcrd's
/// settings at the parity pin, whose `debug.go` sets `//go:debug
/// default=go1.26`, for the four crypto, `crypto/tls` and `crypto/x509`
/// settings among the eight whose defaults differ from those of the oracle
/// module's `go 1.24.0` line (Go 1.26.2's `internal/godebugs/table.go:32`,
/// `:69`, `:70`, `:80`; the other four, `:31`, `:34`, `:72` and `:74`, are
/// the runtime's and `net/url`'s).  With `tlssecpmlkem=1` Go's default key
/// exchanges are dcrd's, the three hybrids first
/// (`crypto/tls/defaults.go:29-33`), and a configured hybrid other than
/// X25519MLKEM768 is kept at all (`common.go:1270-1286`); `tlssha1=0` drops
/// SHA-1 from Go's TLS 1.2 signature schemes; `x509sha256skid=1` and
/// `cryptocustomrand=0` are how dcrd makes certificates and draws
/// randomness for them.  The other oracle tests keep the module's
/// defaults.  The oracle's own TLS tests set the same string
/// (`tools/oracle/tls_test.go`'s `tlsGODEBUG`), and a test here holds the
/// two equal.
pub const DCRD_TLS_GODEBUG: &str = "tlssecpmlkem=1,tlssha1=0,x509sha256skid=1,cryptocustomrand=0";

/// How long any of Go's connections may take, its accept, handshake,
/// request and response, as the oracle's `timeout_ms`.
pub const TIMEOUT_MS: u64 = 10_000;

/// The oracle for the TLS interop tests: [`oracle_or_skip_with_env`] under
/// [`DCRD_TLS_GODEBUG`], with the same skip-or-fail policy for an oracle
/// whose Go builds none of its TLS commands, which need Go 1.26 or later
/// (`tools/oracle/tls.go`, and `tls_old.go` under an older Go).
fn tls_oracle_or_skip() -> Option<Oracle> {
    let mut oracle = oracle_or_skip_with_env(&[("GODEBUG", DCRD_TLS_GODEBUG)])?;
    let response = oracle.call("build_info", b"");
    let go_version = response["go_version"].as_str().unwrap_or_default();
    if go_builds_tls_commands(go_version) {
        return Some(oracle);
    }
    let why = format!("the oracle runs {go_version}, and its TLS commands need Go 1.26 or later");
    assert!(
        env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none(),
        "DCROXIDE_REQUIRE_ORACLE is set but {why}"
    );
    eprintln!("skipping: {why} (set DCROXIDE_REQUIRE_ORACLE to make this an error)");
    None
}

/// Whether the Go that `runtime.Version()` names as `go_version` builds
/// the oracle's TLS commands: a release from go1.26 on, or a version that
/// names no release, such as a development build's, which is taken to be
/// newer.
fn go_builds_tls_commands(go_version: &str) -> bool {
    let Some(release) = go_version.strip_prefix("go") else {
        return true;
    };
    let mut numbers = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|n| n.parse::<u32>().ok());
    match (numbers.next().flatten(), numbers.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= (1, 26),
        _ => true,
    }
}

/// The oracle under dcrd's `GODEBUG` as a matrix runs it: the Go that
/// answers, and the handshakes the matrix has made, each connection
/// counted once, as Go's client made it or, when its client is the code
/// under test, as Go's server served it.
pub struct TlsOracle {
    oracle: Oracle,
    go_version: String,
    handshakes: usize,
    /// Go's servers whose results are not taken yet, by id, and whether
    /// Go's own client dialed each, which counted the connection already.
    listening: HashMap<String, (String, bool)>,
    started: Instant,
}

impl TlsOracle {
    /// The oracle, or `None` where the tests skip: no oracle, or one whose
    /// Go is older than 1.26, unless `DCROXIDE_REQUIRE_ORACLE` is set.
    pub fn start() -> Option<TlsOracle> {
        Some(TlsOracle {
            oracle: tls_oracle_or_skip()?,
            go_version: String::new(),
            handshakes: 0,
            listening: HashMap::new(),
            started: Instant::now(),
        })
    }

    /// The oracle's answer to `cmd` with `request`, which must be no error,
    /// from the reference Go under `DCROXIDE_REQUIRE_ORACLE`.
    pub fn call(&mut self, cmd: &str, request: &Value) -> Value {
        let response = self.oracle.call(cmd, request.to_string().as_bytes());
        assert!(
            response.get("error").is_none(),
            "{cmd}: the oracle answered {response}"
        );
        let go_version = response["go_version"].as_str().unwrap_or_default();
        require_reference_go(go_version);
        go_version.clone_into(&mut self.go_version);
        response
    }

    /// The Go that answered last, as `runtime.Version()` names it.
    pub fn go_version(&self) -> &str {
        &self.go_version
    }

    /// The handshakes made so far.
    pub fn handshakes(&self) -> usize {
        self.handshakes
    }

    /// The certificates `specs` describe ([`spec`]), from `tls_pki`, by
    /// name.
    pub fn pki(&mut self, specs: &[Value]) -> HashMap<String, Issued> {
        let response = self.call("tls_pki", &json!({ "certs": specs }));
        specs
            .iter()
            .map(|spec| {
                let name = spec["name"].as_str().expect("a name");
                let made = &response["detail"][name];
                let text = |field: &str| made[field].as_str().expect("tls_pki's answer");
                let issued = Issued {
                    cert: unhex(text("cert")),
                    key_pkcs8: unhex(text("key_pkcs8")),
                    cert_pem: text("cert_pem").as_bytes().to_vec(),
                    key_pem: text("key_pem").as_bytes().to_vec(),
                };
                (name.to_owned(), issued)
            })
            .collect()
    }

    /// Go's client making one connection with `dial`'s fields, the
    /// timeout added: the `tls_dial` detail.
    pub fn dial(&mut self, mut dial: Value) -> Value {
        dial["timeout_ms"] = json!(TIMEOUT_MS);
        let addr = dial["addr"].as_str().unwrap_or_default();
        for (listening, dialed) in self.listening.values_mut() {
            *dialed |= listening == addr;
        }
        self.handshakes = self.handshakes.saturating_add(1);
        self.call("tls_dial", &dial)["detail"].clone()
    }

    /// Go's server listening with `listen`'s fields, the timeout added:
    /// its address and its id.
    pub fn listen(&mut self, mut listen: Value) -> (String, Value) {
        listen["timeout_ms"] = json!(TIMEOUT_MS);
        let response = self.call("tls_listen", &listen);
        let addr = response["result"].as_str().expect("an address").to_owned();
        let id = response["detail"]["id"].clone();
        self.listening.insert(id.to_string(), (addr.clone(), false));
        (addr, id)
    }

    /// The `tls_listen_result` detail of the server `id` names, once it is
    /// done.
    pub fn served(&mut self, id: &Value) -> Value {
        if let Some((_, false)) = self.listening.remove(&id.to_string()) {
            self.handshakes = self.handshakes.saturating_add(1);
        }
        self.call("tls_listen_result", &json!({ "id": id }))["detail"].clone()
    }

    /// Assert that `detail`, Go's client's or server's answer, is a
    /// refusal, and, when the oracle runs the reference Go, that Go's error
    /// is `error`.  Another Go words its errors as it does, and these tests
    /// compare its verdicts with the code under test's, not its words
    /// (design 18.4), so a Go other than the reference is held to the
    /// refusal alone.
    pub fn assert_refused(&self, what: &str, detail: &Value, error: &str) {
        assert_refused_under(&self.go_version, what, detail, error);
    }

    /// Print what the matrix ran, its handshakes, its wall time and the Go
    /// that answered, straight to the process's standard error, which the
    /// test harness does not capture, so that the line reaches CI's log
    /// when the test passes too.
    pub fn report(&self, matrix: &str) {
        let line = format!(
            "{matrix}: {} handshakes in {:.1?} against {}\n",
            self.handshakes,
            self.started.elapsed(),
            self.go_version
        );
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

/// [`TlsOracle::assert_refused`] for the Go that `go_version` names.
fn assert_refused_under(go_version: &str, what: &str, detail: &Value, error: &str) {
    assert_eq!(detail["ok"], false, "{what}: Go's end {detail}");
    if go_version == REFERENCE_GO {
        assert_eq!(detail["error"], error, "{what}: Go's end");
    }
}

/// A certificate `tls_pki` made, with its key, in DER and in PEM.
#[derive(Clone, Debug)]
pub struct Issued {
    /// The certificate, DER.
    pub cert: Vec<u8>,
    /// Its key, PKCS#8.
    pub key_pkcs8: Vec<u8>,
    /// The certificate, PEM.
    pub cert_pem: Vec<u8>,
    /// Its key, PKCS#8 in PEM.
    pub key_pem: Vec<u8>,
}

impl Issued {
    /// The certificate and key as the oracle's `client_cert` and
    /// `tls_listen` take them, with `chain` after the certificate.
    pub fn identity(&self, chain: &[&Issued]) -> Value {
        let mut certs = vec![hex(&self.cert)];
        certs.extend(chain.iter().map(|issued| hex(&issued.cert)));
        json!({ "chain": certs, "key_pkcs8": hex(&self.key_pkcs8) })
    }
}

/// A `tls_pki` certificate: `name`, on `key`, a curve's name or an RSA key
/// of the test-key fixture by its name there ([`crate::rsa_test_key`]),
/// issued by `issuer` with `sig_alg` or self-signed, for `usage`:
/// `"server"` names localhost and the loopback address, `"client"` names
/// nobody, `"ca"` is an authority.
pub fn spec(name: &str, key: &str, issuer: Option<(&str, &str)>, usage: &str) -> Value {
    let mut spec = json!({ "name": name });
    if key.starts_with("rsa") {
        spec["rsa"] = crate::rsa_test_key(key).oracle_json();
    } else {
        spec["key"] = json!(key);
    }
    if let Some((issuer, sig_alg)) = issuer {
        spec["issuer"] = json!(issuer);
        spec["sig_alg"] = json!(sig_alg);
    }
    match usage {
        "server" => {
            spec["eku"] = json!(["server_auth"]);
            spec["dns"] = json!(["localhost"]);
            spec["ip"] = json!(["127.0.0.1"]);
        }
        "client" => spec["eku"] = json!(["client_auth"]),
        "ca" => spec["ca"] = json!(true),
        _ => panic!("no usage {usage}"),
    }
    spec
}

/// What a connection negotiated, by Go's names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The version, as `tls.VersionName` names it.
    pub version: String,
    /// The cipher suite, as `tls.CipherSuiteName` names it.
    pub suite: String,
    /// The key exchange, as `tls.CurveID`'s String names it.
    pub group: String,
    /// Whether the server asked for another key share.
    pub hello_retry_request: bool,
}

impl Negotiated {
    /// A connection that negotiated these.
    pub fn new(version: &str, suite: &str, group: &str, hello_retry_request: bool) -> Negotiated {
        Negotiated {
            version: version.to_owned(),
            suite: suite.to_owned(),
            group: group.to_owned(),
            hello_retry_request,
        }
    }

    /// What Go reports in a `tls_dial` or `tls_listen_result` detail, once
    /// its handshake is done.
    pub fn of_go(detail: &Value) -> Option<Negotiated> {
        let text = |field: &str| detail[field].as_str().unwrap_or_default();
        let version = text("version");
        (!version.is_empty()).then(|| {
            Negotiated::new(
                version,
                text("cipher_suite"),
                text("curve_id"),
                detail["hello_retry_request"] == true,
            )
        })
    }
}

/// Why a server on ring's verification set, the provider's today and with
/// it the node's, refuses a client certificate Go's server accepts: no
/// P-521 or SHA-512 ECDSA and no RSA key under 2048 bits until Go's
/// client-certificate set (ADR-0015, T4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientCertRefusal {
    /// A P-521 client key.
    P521Key,
    /// A leaf its issuer signed with ECDSA-SHA512.
    Sha512Issuer,
    /// An RSA-1024 client key.
    Rsa1024Key,
}

impl ClientCertRefusal {
    /// The error Go's client reports for the refusal in `version`, `"TLS
    /// 1.3"` or `"TLS 1.2"`, under the reference Go.  In TLS 1.3 Go's
    /// client sends no certificate it cannot sign with under a scheme the
    /// CertificateRequest lists (`crypto/tls/handshake_client.go:1264-1278`),
    /// and a P-521 key signs with ecdsa_secp521r1_sha512 alone
    /// (`auth.go:203-209`), which ring's set lacks, so the server finds no
    /// certificate and says it requires one; every other refusal is of a
    /// certificate or signature the server cannot verify, a decrypt_error
    /// alert in rustls (`rustls-0.23.46/src/error.rs:647-651`).
    pub fn go_error(self, version: &str) -> &'static str {
        match (self, version) {
            (ClientCertRefusal::P521Key, "TLS 1.3") => "remote error: tls: certificate required",
            _ => "remote error: tls: error decrypting message",
        }
    }
}

/// The client-certificate cells both matrices run: client keys P-256,
/// P-384, Ed25519 and RSA-2048, each a self-signed leaf the server trusts
/// and a leaf under each kind of authority, and the three refused today
/// ([`ClientCertRefusal`]), each to be presented in each version.
pub struct ClientCerts {
    /// What the server trusts: the authorities, which are P-256, P-384,
    /// RSA-4096 twice, Ed25519, and P-384 again for the leaf it signs with
    /// ECDSA-SHA512, then the leaves that stand alone.
    pub trusted: Vec<Issued>,
    /// Each cell: its name, the client's certificate, and why the server
    /// refuses it today, if it does.
    pub cells: Vec<(String, Issued, Option<ClientCertRefusal>)>,
}

impl ClientCerts {
    /// The authorities, each a name, its key and the algorithm it signs
    /// its leaves with.
    pub const CAS: [(&'static str, &'static str, &'static str); 5] = [
        ("ca-p256", "P-256", "ECDSA-SHA256"),
        ("ca-p384", "P-384", "ECDSA-SHA384"),
        ("ca-rsa4096-pkcs1", "rsa4096", "SHA256-RSA"),
        ("ca-rsa4096-pss", "rsa4096", "SHA256-RSAPSS"),
        ("ca-ed25519", "Ed25519", "Ed25519"),
    ];

    /// The client keys of the cells accepted today.
    pub const KEYS: [&'static str; 4] = ["P-256", "P-384", "Ed25519", "rsa2048"];

    /// The cells refused today, each a name, the client's key, its issuer,
    /// the issuer's signature algorithm and why.
    pub const REFUSED: [(
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        ClientCertRefusal,
    ); 3] = [
        (
            "client P-521 under ca-p256",
            "P-521",
            "ca-p256",
            "ECDSA-SHA256",
            ClientCertRefusal::P521Key,
        ),
        (
            "client P-256 under ca-p384 signing ECDSA-SHA512",
            "P-256",
            "ca-p384-sha512",
            "ECDSA-SHA512",
            ClientCertRefusal::Sha512Issuer,
        ),
        (
            "client rsa1024 under ca-p256",
            "rsa1024",
            "ca-p256",
            "ECDSA-SHA256",
            ClientCertRefusal::Rsa1024Key,
        ),
    ];

    /// The authority that signs the ECDSA-SHA512 leaf.
    const SHA512_CA: &'static str = "ca-p384-sha512";

    /// What [`ClientCerts::make`] asks `tls_pki` for, and the cells, each a
    /// name and why it is refused today, if it is.
    fn specs() -> (Vec<Value>, Vec<(String, Option<ClientCertRefusal>)>) {
        let mut specs: Vec<Value> = Self::CAS
            .iter()
            .map(|(name, key, _)| spec(name, key, None, "ca"))
            .collect();
        specs.push(spec(Self::SHA512_CA, "P-384", None, "ca"));
        let mut cells = Vec::new();
        for key in Self::KEYS {
            let name = format!("client {key} alone");
            specs.push(spec(&name, key, None, "client"));
            cells.push((name, None));
            for (ca, _, sig_alg) in Self::CAS {
                let name = format!("client {key} under {ca}");
                specs.push(spec(&name, key, Some((ca, sig_alg)), "client"));
                cells.push((name, None));
            }
        }
        for (name, key, ca, sig_alg, refusal) in Self::REFUSED {
            specs.push(spec(name, key, Some((ca, sig_alg)), "client"));
            cells.push((name.to_owned(), Some(refusal)));
        }
        (specs, cells)
    }

    /// Made by `go`'s `tls_pki`.
    pub fn make(go: &mut TlsOracle) -> ClientCerts {
        let (specs, cells) = Self::specs();
        let pki = go.pki(&specs);
        let trusted = Self::CAS
            .iter()
            .map(|(name, ..)| (*name).to_owned())
            .chain([Self::SHA512_CA.to_owned()])
            .chain(
                cells
                    .iter()
                    .map(|(name, _)| name.clone())
                    .filter(|name| name.ends_with(" alone")),
            )
            .map(|name| pki[&name].clone())
            .collect();
        let cells = cells
            .into_iter()
            .map(|(name, refusal)| {
                let issued = pki[&name].clone();
                (name, issued, refusal)
            })
            .collect();
        ClientCerts { trusted, cells }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oracle runs with the environment it is given and this process's
    /// besides: under [`DCRD_TLS_GODEBUG`], as [`TlsOracle::start`] starts
    /// it and as [`Oracle::spawn_with_env`] is given it, a Go server and
    /// client both cut to SecP256r1MLKEM768 negotiate it, and under the
    /// oracle module's own defaults, an empty `GODEBUG`, Go drops it from
    /// both and the client has no key exchange to offer.  The empty one
    /// alone would hold were the environment dropped, since Go reads it as
    /// an unset one.
    #[test]
    fn the_oracle_runs_with_the_environment_it_is_given() {
        let Some(mut dcrd) = TlsOracle::start() else {
            return;
        };
        let spawned = |godebug: &str| TlsOracle {
            oracle: Oracle::spawn_with_env(&[("GODEBUG", godebug)]),
            go_version: String::new(),
            handshakes: 0,
            listening: HashMap::new(),
            started: Instant::now(),
        };
        let server = dcrd.pki(&[spec("server", "P-256", None, "server")])["server"].clone();
        let hybrid = json!(["SecP256r1MLKEM768"]);
        for (mut go, want) in [
            (dcrd, "SecP256r1MLKEM768"),
            (spawned(DCRD_TLS_GODEBUG), "SecP256r1MLKEM768"),
            (spawned(""), ""),
        ] {
            let mut listen = server.identity(&[]);
            listen["curve_preferences"] = hybrid.clone();
            let (addr, id) = go.listen(listen);
            let dial = go.dial(json!({
                "addr": addr, "server_name": "localhost", "roots": [hex(&server.cert)],
                "curve_preferences": hybrid,
            }));
            let served = go.served(&id);
            if want.is_empty() {
                go.assert_refused(
                    "the module's defaults",
                    &dial,
                    "tls: no supported elliptic curves for ECDHE",
                );
                assert_eq!(served["ok"], false, "{served}");
            } else {
                assert_eq!(dial["ok"], true, "{dial}");
                assert_eq!(dial["curve_id"], want, "{dial}");
                assert_eq!(served["curve_id"], want, "{served}");
            }
            assert_eq!(go.handshakes(), 1, "one connection, counted once");
        }
    }

    /// A refusal is held to the reference Go's words for it, and under
    /// another Go to its being a refusal alone.
    #[test]
    fn a_refusal_is_held_to_the_reference_gos_words() {
        let refused = json!({ "ok": false, "error": "remote error: tls: handshake failure" });
        let holds = |go_version: &str, detail: &Value, error: &str| {
            std::panic::catch_unwind(|| assert_refused_under(go_version, "a cell", detail, error))
                .is_ok()
        };
        let words = "remote error: tls: handshake failure";
        assert!(holds(REFERENCE_GO, &refused, words));
        assert!(!holds(REFERENCE_GO, &refused, "EOF"), "other words");
        assert!(holds("go1.27.0", &refused, "EOF"), "another Go's words");
        let completed = json!({ "ok": true, "error": "" });
        assert!(
            !holds(REFERENCE_GO, &completed, ""),
            "a completed connection"
        );
        assert!(
            !holds("go1.27.0", &completed, ""),
            "a completed connection, another Go"
        );
    }

    /// The oracle's TLS commands are built by Go 1.26 and later releases,
    /// and by a Go that names no release.
    #[test]
    fn the_tls_commands_need_go_1_26() {
        for (go_version, builds) in [
            ("go1.24.13", false),
            ("go1.25.14", false),
            ("go1.26rc1", true),
            ("go1.26.0", true),
            (REFERENCE_GO, true),
            ("go1.27.2", true),
            ("devel go1.27-abcdef", true),
        ] {
            assert_eq!(go_builds_tls_commands(go_version), builds, "{go_version}");
        }
    }

    /// The oracle's own TLS tests run under [`DCRD_TLS_GODEBUG`]: the
    /// `tlsGODEBUG` constant of `tools/oracle/tls_test.go` is the same
    /// string, so a change to dcrd's settings at the pin reaches both.
    #[test]
    fn the_oracle_tests_run_under_the_same_godebug() {
        let path = crate::repo_root()
            .join("tools")
            .join("oracle")
            .join("tls_test.go");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let consts: Vec<&str> = source
            .lines()
            .filter_map(|line| line.strip_prefix("const tlsGODEBUG = "))
            .collect();
        assert_eq!(
            consts,
            [format!("\"{DCRD_TLS_GODEBUG}\"")],
            "{}'s tlsGODEBUG",
            path.display()
        );
    }

    /// The client-certificate cells: four keys alone and under five
    /// authorities, accepted today, and the three refused, each named
    /// once; the server trusts the six authorities and the four leaves
    /// that stand alone; and each refused cell's Go error is the decrypt
    /// error but for the P-521 key in TLS 1.3.
    #[test]
    fn the_client_certificate_cells() {
        let (specs, cells) = ClientCerts::specs();
        assert_eq!(specs.len(), 6 + cells.len());
        let accepted = cells.iter().filter(|(_, refusal)| refusal.is_none());
        assert_eq!(
            accepted.count(),
            4 * 6,
            "four keys, alone and under five authorities"
        );
        let refused: Vec<_> = cells.iter().filter_map(|(_, refusal)| *refusal).collect();
        assert_eq!(
            refused,
            [
                ClientCertRefusal::P521Key,
                ClientCertRefusal::Sha512Issuer,
                ClientCertRefusal::Rsa1024Key,
            ]
        );
        let names: std::collections::BTreeSet<&str> = specs
            .iter()
            .filter_map(|spec| spec["name"].as_str())
            .collect();
        assert_eq!(names.len(), specs.len(), "every name once");
        let alone = cells.iter().filter(|(name, _)| name.ends_with(" alone"));
        assert_eq!(alone.count(), 4);
        let decrypt = "remote error: tls: error decrypting message";
        for refusal in refused {
            assert_eq!(refusal.go_error("TLS 1.2"), decrypt, "{refusal:?}");
            let tls13 = refusal.go_error("TLS 1.3");
            assert_eq!(
                tls13 == decrypt,
                refusal != ClientCertRefusal::P521Key,
                "{refusal:?}"
            );
        }
    }
}
