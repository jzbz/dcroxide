// SPDX-License-Identifier: ISC
//! The daemon's TXMP and MINR lines below info, over a running node.
//!
//! dcrd installs its `TXMP` logger as the mempool's package logger and
//! its `MINR` logger as the mining and CPU miner packages'
//! (`log.go:91-94`), so `--debuglevel=TXMP=debug,MINR=debug` shows every
//! transaction the pool accepts and every template the background
//! generator builds.  The port's pool and template generation had no
//! logger, so those levels showed nothing from either.
//!
//! The three template lines asserted are the ones dcrd 2.1.7 logs for
//! the same steps on a fresh simnet node paying a pay-to-pubkey-hash
//! mining address: the startup template for height 1, then the
//! templates for heights 2 and 3 as `generate 2` connects each block.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_chainhash::Hash;
use dcroxide_wire::{MsgTx, OutPoint, TX_TREE_REGULAR, TxIn, TxOut};

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until the collected stdout from byte `from` on contains
/// `needle`, returning all of it.
fn wait_for(collected: &Mutex<String>, from: usize, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let out = collected.lock().expect("sink").clone();
        if out[from..].contains(needle) {
            return out;
        }
        assert!(Instant::now() < deadline, "no {needle:?} in: {out}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One JSON-RPC call over plain HTTP as user:pass; the response body.
fn rpc_call(addr: &str, method: &str, params: &str) -> String {
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send the request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response).into_owned();
    match response.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => response,
    }
}

/// A regular transaction spending an unknown output that expired at
/// height 1, told apart by its output value.
fn expired_tx(value: i64) -> MsgTx {
    let mut pk_script = vec![0x76, 0xa9, 0x14];
    pk_script.extend_from_slice(&[0x5a; 20]);
    pk_script.extend_from_slice(&[0x88, 0xac]);
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([0x11; 32]),
                index: 0,
                tree: TX_TREE_REGULAR,
            },
            sequence: 0xffff_ffff,
            value_in: 1_000_000,
            block_height: 0,
            block_index: 0,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value,
            version: 0,
            pk_script,
        }],
        expiry: 1,
        ..MsgTx::default()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The template line dcrd logs at debug once a template is built, for a
/// simnet template at the proof-of-work limit and the minimum ticket
/// price.
fn created(txns: u32, stxns: u32, sigops: u32, bytes: u32) -> String {
    format!(
        "[DBG] MINR: Created new block template ({txns} transactions, {stxns} stake \
         transactions, 0 treasury transactions, 0 in fees, {sigops} signature operations, \
         {bytes} bytes, target difficulty \
         7fffff0000000000000000000000000000000000000000000000000000000000, stake difficulty \
         0.0002)\n"
    )
}

#[test]
fn txmp_and_minr_lines_show_at_their_levels() {
    let params = dcroxide_chaincfg::simnet_params();
    let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x5a; 20],
        &params,
    )
    .expect("mining address");
    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--nofilelogging",
            "--debuglevel=MINR=debug",
        ])
        .arg(format!("--miningaddr={}", mining_addr.encode()))
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let mut out = child.stdout.take().expect("stdout pipe");
    let mut daemon = Daemon(child);
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .expect("sink")
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let listening = wait_for(&collected, 0, "RPC server listening on ");
    let addr = listening
        .split("RPC server listening on ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .expect("the listener address")
        .trim()
        .to_string();

    // The startup template, then one per block `generate` connects.
    wait_for(&collected, 0, &created(1, 0, 3, 378));
    let mined = rpc_call(&addr, "generate", "[2]");
    assert!(mined.contains(r#""error":null"#), "{mined}");
    let out = wait_for(
        &collected,
        0,
        "[INF] MINR: Block submitted via CPU miner accepted (hash ",
    );
    let height_two = out
        .find(&created(1, 1, 1, 323))
        .expect("height 2's template");
    let after_two = height_two + created(1, 1, 1, 323).len();
    wait_for(&collected, after_two, &created(1, 1, 1, 323));
    let out = collected.lock().expect("sink").clone();
    assert_eq!(
        out.matches("[DBG] MINR: Considering 0 transactions for inclusion to new block\n")
            .count(),
        out.matches("[DBG] MINR: Created new block template (")
            .count(),
        "each template is announced as it is considered: {out}"
    );
    assert!(!out.contains("TXMP:"), "TXMP stays at info: {out}");

    // TXMP at debug: a refused transaction's trace line stays hidden.
    let set = rpc_call(&addr, "debuglevel", r#"["MINR=info,TXMP=debug"]"#);
    assert!(set.contains(r#""error":null"#), "{set}");
    let mark = collected.lock().expect("sink").len();
    let tx = expired_tx(1000);
    let refused = rpc_call(
        &addr,
        "sendrawtransaction",
        &format!(r#"["{}"]"#, hex(&tx.serialize())),
    );
    assert!(refused.contains("expired at height 1"), "{refused}");

    // At trace it shows, with dcrd's text: the transaction and the
    // refusal's description.
    let set = rpc_call(&addr, "debuglevel", r#"["TXMP=trace"]"#);
    assert!(set.contains(r#""error":null"#), "{set}");
    let tx = expired_tx(2000);
    let tx_hash = tx.tx_hash();
    let refused = rpc_call(
        &addr,
        "sendrawtransaction",
        &format!(r#"["{}"]"#, hex(&tx.serialize())),
    );
    assert!(refused.contains("expired at height 1"), "{refused}");
    let out = wait_for(
        &collected,
        mark,
        &format!(
            "[TRC] TXMP: Failed to process transaction {tx_hash}: transaction {tx_hash} expired \
             at height 1\n"
        ),
    );
    assert_eq!(
        out[mark..].matches("TXMP:").count(),
        1,
        "the first refusal logged nothing at debug: {}",
        &out[mark..]
    );

    // MINR back at info: a block's templates log nothing below it.  The
    // template for height 4 is built after block 3 connects, on the
    // generator's thread, and block 4 is mined from it, so the output up
    // to block 4's acceptance holds that whole build.
    for height in [3, 4] {
        let mined = rpc_call(&addr, "generate", "[1]");
        assert!(mined.contains(r#""error":null"#), "{mined}");
        let hash = mined
            .split('"')
            .find(|field| field.len() == 64 && field.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("a block hash in {mined}"))
            .to_string();
        wait_for(
            &collected,
            mark,
            &format!(
                "[INF] MINR: Block submitted via CPU miner accepted (hash {hash}, height {height}"
            ),
        );
    }
    let out = collected.lock().expect("sink").clone();
    assert!(
        !out[mark..].contains("[DBG] MINR"),
        "MINR at info: {}",
        &out[mark..]
    );

    let _ = rpc_call(&addr, "stop", "[]");
    let deadline = Instant::now() + Duration::from_secs(60);
    while daemon.0.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "the daemon never stopped");
        std::thread::sleep(Duration::from_millis(50));
    }
}
