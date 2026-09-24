// SPDX-License-Identifier: ISC
//! The mixing RPCs over the running daemon's own RPC configuration.
//!
//! The daemon built a live mixing pool for its peers but gave the RPC
//! server `mix_pooler: ()` and a sync manager without the pool, so
//! `sendrawmixmessage` failed every message with "RPC server seam
//! accept_mix_message is not wired in this build" and
//! `getmixpairrequests` answered `[]` whatever the pool held.  dcrd
//! wires `MixPooler: s.mixMsgPool` and accepts into the same pool
//! (`rpcSyncMgr.AcceptMixMessage`).  `review_mix_rpc.rs` covers the
//! adapters; this drives the daemon binary, so it fails if `rpc_config`
//! stops handing them the pool.

// The pipe descriptor is re-opened through /proc/self/fd.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded buffers, heights and a deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_chainhash::Hash;
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{SCRIPT_CLASS_P2PKH_V0, Secp256k1KeyPair, sign_message};
use dcroxide_txscript::stdaddr;
use dcroxide_wire::{Message, MixPairReqUTXO, MsgBlock, MsgMixPairReq, OutPoint};

/// The text every trait default reports (`server.rs` `unwired_seam`).
const UNWIRED: &str = "is not wired in this build";

fn key(tag: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[0] = tag;
    bytes[31] = 1;
    PrivateKey::from_bytes(&bytes).expect("private key")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The payload of the first `rpclistenaddr` pipe message in the stream
/// (dcrd `ipc.go` framing).
fn rpc_listen_addr(bytes: &[u8]) -> Option<String> {
    const KIND: &[u8] = b"rpclistenaddr";
    let at = bytes
        .windows(2 + KIND.len())
        .position(|w| w[0] == 1 && w[1] as usize == KIND.len() && &w[2..] == KIND)?;
    let len_at = at + 2 + KIND.len();
    let len = u32::from_le_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
    let payload = bytes.get(len_at + 4..len_at + 4 + len)?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

/// One JSON-RPC request over plain HTTP with basic credentials; the
/// response body.
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

/// The string result of a JSON-RPC response.
fn string_result(response: &str) -> String {
    let rest = response
        .split_once(r#""result":""#)
        .unwrap_or_else(|| panic!("no string result: {response}"))
        .1;
    rest[..rest.find('"').expect("closing quote")].to_string()
}

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_daemon_rpc_server_reaches_its_mixing_pool() {
    let params = dcroxide_chaincfg::simnet_params();
    let owner = key(0x31);
    let owner_pub = owner.public_key().serialize_compressed();
    let owner_addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &stdaddr::hash160(&owner_pub),
        &params,
    )
    .expect("mining address");
    let (_, owner_script) = owner_addr.payment_script();

    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--listen=127.0.0.1:0",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            // The bound RPC address arrives over the pipe.
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--miningaddr={}", owner_addr.encode()))
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let _daemon = Daemon(child);
    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("sink").extend_from_slice(&buf[..n]);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let addr = loop {
        if let Some(addr) = rpc_listen_addr(&collected.lock().expect("sink")) {
            break addr;
        }
        assert!(
            Instant::now() < deadline,
            "the RPC listener never announced its address"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    // Mine past the premine so block 2's coinbase pays the owner.
    let mined = rpc_call(&addr, "generate", "[2]");
    assert!(mined.contains(r#""error":null"#), "{mined}");
    let hash = string_result(&rpc_call(&addr, "getblockhash", "[2]"));
    let block_hex = string_result(&rpc_call(
        &addr,
        "getblock",
        &format!(r#"["{hash}",false]"#),
    ));
    let (block, _) = MsgBlock::from_bytes(&unhex(&block_hex)).expect("block");
    let coinbase = &block.transactions[0];
    let (index, output) = coinbase
        .tx_out
        .iter()
        .enumerate()
        .find(|(_, out)| out.pk_script == owner_script)
        .expect("the coinbase pays the mining address");

    // A pair request over that output, with a proof of its ownership
    // and a fee the pool's policy takes.
    let expiry = 2 + 10;
    let proof = Secp256k1KeyPair {
        pub_key: owner_pub.to_vec(),
        priv_key: owner.clone(),
    }
    .sign_utxo_proof(expiry)
    .expect("utxo proof");
    let identity = key(0x32);
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: identity.public_key().serialize_compressed(),
        expiry,
        mix_amount: output.value - 100_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: output.value,
        utxos: vec![MixPairReqUTXO {
            out_point: OutPoint {
                hash: coinbase.tx_hash(),
                index: index as u32,
                tree: 0,
            },
            script: Vec::new(),
            pub_key: owner_pub.to_vec(),
            signature: proof,
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    sign_message(&mut pr, &identity).expect("sign pair request");
    let pr_hex = hex(&Message::MixPairReq(pr)
        .encode_payload(dcroxide_wire::MIX_VERSION)
        .expect("encode"));

    let before = rpc_call(&addr, "getmixpairrequests", "[]");
    assert!(before.contains(r#""result":[]"#), "{before}");

    let sent = rpc_call(
        &addr,
        "sendrawmixmessage",
        &format!(r#"["mixpairreq","{pr_hex}"]"#),
    );
    assert!(!sent.contains(UNWIRED), "{sent}");
    assert!(sent.contains(r#""error":null"#), "{sent}");

    let listed = rpc_call(&addr, "getmixpairrequests", "[]");
    assert!(
        listed.contains(&format!(r#""result":["{pr_hex}"]"#)),
        "{listed}"
    );

    // Unknown messages are reported by the pool, not by a missing seam.
    let missing = rpc_call(
        &addr,
        "getmixmessage",
        &format!(r#"["{}"]"#, Hash([7u8; 32])),
    );
    assert!(!missing.contains(UNWIRED), "{missing}");
}
