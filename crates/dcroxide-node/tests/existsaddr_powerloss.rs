// SPDX-License-Identifier: ISC
//! The exists address index across a real power cut of the whole
//! process: block files and metadata store together.
//!
//! A simnet daemon runs under `tools/powerloss`, the `LD_PRELOAD` shim
//! that records what every write destroys until its file is synced, with
//! the metadata flushing every second and a tiny memtable target, so its
//! flushes journal, merge and collect the journal all the time.  It mines
//! blocks over RPC, each carrying a transaction that pays fresh addresses
//! first seen in the mempool, until a SIGKILL lands at a random moment
//! after the first of those transactions.  The undo log is replayed,
//! which leaves every file as of its last sync, as a power cut would, and
//! the daemon restarts without the shim and catches its index up.  Every
//! address the run ever used, and every address of the restarted chain,
//! must then answer `existsaddresses` exactly as the blocks at or below
//! the restarted tip say: present if one of them pays it, absent
//! otherwise -- the mempool of a killed process is gone, as dcrd's is.
//! Four cuts in a row.
//!
//! A mined block is flushed as it connects, so most cuts land between
//! flushes and some inside one; the database's and the index's
//! `PowerLossBackend` sweeps place a cut at every storage operation, and
//! this checks the whole process -- block files, metadata store, journal
//! reload and catch-up -- after a real kill.
//!
//! Linux only, and skipped where `cc` or `python3` is missing unless
//! `DCROXIDE_REQUIRE_FAULT_INJECTION` is set, as CI sets it.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over small counts and amounts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_chainhash::Hash;
use dcroxide_indexers::{ADDR_KEY_SIZE, addr_to_key};
use dcroxide_testutil::{SplitMix64, unhex};
use dcroxide_txscript::SIG_HASH_ALL;
use dcroxide_txscript::sign::{SignatureType, signature_script};
use dcroxide_txscript::stdaddr::{
    Address, hash160, new_address_pub_key_hash_ecdsa_secp256k1_v0,
    new_address_pub_key_hash_ed25519_v0, new_address_pub_key_hash_schnorr_secp256k1_v0,
    new_address_script_hash_v0_from_hash,
};
use dcroxide_txscript::stdscript;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// Turns a skip into a failure, as for the shim's own test.
const REQUIRE: &str = "DCROXIDE_REQUIRE_FAULT_INJECTION";

/// The miner's private key; its pubkey-hash address takes the coinbases.
const KEY: [u8; 32] = [0x2a; 32];

/// How many cuts in a row: the module comment's four.
const ROUNDS: i64 = 4;

/// The blocks mined before the first round, enough to mature the first
/// coinbases.
const FIRST_BLOCKS: i64 = 18;

/// The height the run stops at: short of the stake validation height,
/// past which a block needs votes this miner cannot cast.
const HEIGHT_LIMIT: i64 = 130;

/// The heights kept back for each round still to come: enough for a
/// coinbase to mature and a few blocks to carry transactions.
const RESERVE: i64 = 10;

type Key = [u8; ADDR_KEY_SIZE];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Kills a daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

/// Why an RPC call gave no result.
#[derive(Debug)]
enum Fail {
    /// No complete response: the daemon is gone, killed mid-call.
    Gone(String),
    /// The daemon answered with an error.
    Refused(String),
}

/// One JSON-RPC call; the response body.
fn rpc(addr: &str, method: &str, params: &str) -> Result<String, Fail> {
    let gone = |e: std::io::Error| Fail::Gone(e.to_string());
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
    let mut stream = TcpStream::connect(addr).map_err(gone)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(gone)?;
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(gone)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(gone)?;
    let response = String::from_utf8_lossy(&response).into_owned();
    match response.split_once("\r\n\r\n") {
        Some((_, body)) if body.contains(r#""error":null"#) => Ok(body.to_string()),
        Some((_, body)) if body.contains(r#""error":{"#) => Err(Fail::Refused(body.to_string())),
        _ => Err(Fail::Gone(format!("an incomplete response: {response}"))),
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

/// The numeric result of a JSON-RPC response.
fn number_result(response: &str) -> i64 {
    let rest = response
        .split_once(r#""result":"#)
        .unwrap_or_else(|| panic!("no result: {response}"))
        .1;
    rest[..rest.find([',', '}']).expect("end")]
        .parse()
        .expect("number")
}

/// A running daemon and its RPC address.
struct Daemon {
    child: KillOnDrop,
    addr: String,
}

/// Start the simnet daemon over `appdata`, under the shim when `shim` is
/// `(library, undo log)`.
fn start(appdata: &Path, mining: &str, shim: Option<(&Path, &Path)>) -> Daemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcroxide"));
    command
        .arg("--simnet")
        .arg(format!("--appdata={}", appdata.display()))
        .args([
            "--noseeders",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--notls",
            "--rpcuser=user",
            "--rpcpass=pass",
            "--pipetx=2",
            "--boundaddrevents",
        ])
        .arg(format!("--miningaddr={mining}"))
        .env_remove("DCRD_APPDATA")
        // Flush every second, and merge the memtable at four keys, so the
        // cuts land in flushes that journal, merge and collect.
        .env("DCROXIDE_DB_FLUSH_SECS", "1")
        .env("DCROXIDE_EXISTSADDR_MEMTABLE_KEYS", "4")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some((lib, log)) = shim {
        command
            .env("LD_PRELOAD", lib)
            .env("POWERLOSS_DIR", appdata.join("data"))
            .env("POWERLOSS_LOG", log);
    }
    let mut child = command.spawn().expect("spawn dcroxide");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let child = KillOnDrop(child);
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
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(addr) = rpc_listen_addr(&collected.lock().expect("sink")) {
            return Daemon { child, addr };
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never announced its RPC address"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Every key a block gives the index, as the index extracts them.
fn block_keys(block: &MsgBlock) -> HashSet<Key> {
    let params = dcroxide_chaincfg::simnet_params();
    let mut keys = HashSet::new();
    for tx in block.transactions.iter().chain(&block.stransactions) {
        let is_sstx = dcroxide_stake::is_sstx(tx);
        for out in &tx.tx_out {
            let (script_type, mut addrs) =
                stdscript::extract_addrs(out.version, &out.pk_script, &params);
            if is_sstx
                && script_type == stdscript::ScriptType::NullData
                && let Ok(addr) =
                    dcroxide_stake::addr_from_sstx_pk_scr_commitment(&out.pk_script, &params)
            {
                addrs.push(addr);
            }
            keys.extend(addrs.iter().filter_map(|a| addr_to_key(a).ok()));
        }
    }
    keys
}

fn address_of(key: &Key) -> String {
    let params = dcroxide_chaincfg::simnet_params();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&key[1..]);
    let addr = match key[0] {
        0 => new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, &params),
        1 => new_address_pub_key_hash_ed25519_v0(&hash, &params),
        2 => new_address_pub_key_hash_schnorr_secp256k1_v0(&hash, &params),
        _ => new_address_script_hash_v0_from_hash(&hash, &params),
    };
    addr.expect("address").encode()
}

fn block_at(addr: &str, height: i64) -> Result<MsgBlock, Fail> {
    let hash = string_result(&rpc(addr, "getblockhash", &format!("[{height}]"))?);
    let raw = string_result(&rpc(addr, "getblock", &format!(r#"["{hash}",false]"#))?);
    Ok(MsgBlock::from_bytes(&unhex(&raw)).expect("block").0)
}

/// A spendable output of the miner's.
#[derive(Clone, Copy)]
struct Coin {
    outpoint: OutPoint,
    value: i64,
    height: u32,
    index: u32,
}

/// Mine and spend until the daemon is gone, which the killer thread
/// makes happen at a random moment, or until the chain reaches
/// `height_cap`, adding every key the run puts in a transaction, mined
/// or not, to `used`.  A coinbase once spent, in a block or only in the
/// mempool, is never offered again.  Returns whether it stopped at the
/// cap, the daemon still running.
///
/// `cue` tells the killer thread where the round is: one message when
/// the round's first transaction is in the mempool, which starts the
/// countdown to the cut, and its drop when this returns.  Until that
/// first transaction the round only reads the chain back, every block
/// from the first, and may have to mine a block or two for a coinbase
/// to mature; a cut during that puts no fresh address at risk.
fn mine_until_killed(
    daemon: &Daemon,
    mine: &Address,
    rng: &mut SplitMix64,
    used: &mut BTreeSet<Key>,
    spent: &mut HashSet<(Hash, u32)>,
    height_cap: i64,
    cue: std::sync::mpsc::Sender<()>,
) -> bool {
    let call = |method: &str, params: &str| match rpc(&daemon.addr, method, params) {
        Ok(body) => Some(body),
        Err(Fail::Gone(why)) => {
            println!("the daemon went during {method}: {why}");
            None
        }
        Err(Fail::Refused(body)) => panic!("the daemon refused {method}: {body}"),
    };
    let (_, mine_script) = mine.payment_script();
    let mut coins: Vec<Coin> = Vec::new();
    let mut seen_height = 0i64;
    let mut cued = false;
    loop {
        // Collect the coinbases of new blocks.
        let Some(tip) = call("getblockcount", "[]") else {
            return false;
        };
        let tip = number_result(&tip);
        while seen_height < tip {
            seen_height += 1;
            let block = match block_at(&daemon.addr, seen_height) {
                Ok(block) => block,
                Err(Fail::Gone(_)) => return false,
                Err(Fail::Refused(body)) => panic!("getblock: {body}"),
            };
            let coinbase = &block.transactions[0];
            for (i, out) in coinbase.tx_out.iter().enumerate() {
                if out.pk_script == mine_script && !spent.contains(&(coinbase.tx_hash(), i as u32))
                {
                    coins.push(Coin {
                        outpoint: OutPoint {
                            hash: coinbase.tx_hash(),
                            index: i as u32,
                            tree: 0,
                        },
                        value: out.value,
                        height: block.header.height,
                        index: 0,
                    });
                }
            }
        }
        if tip >= height_cap {
            // This round's heights are used up.
            return true;
        }
        // Spend a mature coinbase to fresh addresses, which the mempool
        // records first.
        if let Some(at) = coins.iter().position(|c| tip - i64::from(c.height) >= 16) {
            let coin = coins.remove(at);
            spent.insert((coin.outpoint.hash, coin.outpoint.index));
            let mut outs = Vec::new();
            let mut paid = 0;
            for _ in 0..3 {
                let mut hash = [0u8; 20];
                for b in &mut hash {
                    *b = rng.next_u64() as u8;
                }
                let addr = new_address_pub_key_hash_ecdsa_secp256k1_v0(
                    &hash,
                    &dcroxide_chaincfg::simnet_params(),
                )
                .expect("address");
                used.insert(addr_to_key(&addr).expect("key"));
                let (version, pk_script) = addr.payment_script();
                outs.push(TxOut {
                    value: 1_000_000,
                    version,
                    pk_script,
                });
                paid += 1_000_000;
            }
            let (version, pk_script) = mine.payment_script();
            outs.push(TxOut {
                value: coin.value - paid - 100_000,
                version,
                pk_script,
            });
            let mut tx = MsgTx {
                ser_type: TxSerializeType::Full,
                version: 1,
                tx_in: vec![TxIn {
                    previous_out_point: coin.outpoint,
                    sequence: u32::MAX,
                    value_in: coin.value,
                    block_height: coin.height,
                    block_index: coin.index,
                    signature_script: Vec::new(),
                }],
                tx_out: outs,
                lock_time: 0,
                expiry: 0,
            };
            tx.tx_in[0].signature_script = signature_script(
                &tx,
                0,
                &mine_script,
                SIG_HASH_ALL,
                &KEY,
                SignatureType::EcdsaSecp256k1,
                true,
            )
            .expect("sign");
            let hex: String = tx.serialize().iter().map(|b| format!("{b:02x}")).collect();
            if call("sendrawtransaction", &format!(r#"["{hex}"]"#)).is_none() {
                return false;
            }
            if !cued {
                cued = true;
                let _ = cue.send(());
            }
        }
        if call("generate", "[1]").is_none() {
            return false;
        }
    }
}

/// Every address the run used and every address of the restarted chain
/// must answer as the restarted chain's blocks say.  Returns the tip and
/// how many of the used addresses answered present.
fn check_index(daemon: &Daemon, used: &BTreeSet<Key>) -> (i64, usize) {
    let tip = number_result(&rpc(&daemon.addr, "getblockcount", "[]").expect("tip"));
    let mut chain_keys = HashSet::new();
    for height in 1..=tip {
        chain_keys.extend(block_keys(&block_at(&daemon.addr, height).expect("block")));
    }
    let mut keys: Vec<Key> = used.iter().copied().collect();
    keys.extend(chain_keys.iter().copied());
    keys.sort_unstable();
    keys.dedup();
    let present = used.iter().filter(|k| chain_keys.contains(*k)).count();
    for batch in keys.chunks(64) {
        let list: Vec<String> = batch
            .iter()
            .map(|k| format!("\"{}\"", address_of(k)))
            .collect();
        let response = rpc(
            &daemon.addr,
            "existsaddresses",
            &format!("[[{}]]", list.join(",")),
        )
        .expect("existsaddresses");
        let bits = unhex(&string_result(&response));
        for (i, key) in batch.iter().enumerate() {
            let got = bits[i / 8] >> (i % 8) & 1 == 1;
            assert_eq!(
                got,
                chain_keys.contains(key),
                "{} at restarted tip {tip}",
                address_of(key)
            );
        }
    }
    (tip, present)
}

#[test]
fn the_index_answers_from_the_blocks_that_survived_a_power_cut() {
    if !available("cc") || !available("python3") {
        if std::env::var_os(REQUIRE).is_some() {
            panic!("{REQUIRE} is set but this test needs cc and python3");
        }
        eprintln!("SKIP: needs cc and python3 (set {REQUIRE} to make this a failure)");
        return;
    }
    let work = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("existsaddr_powerloss-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("work dir");
    let lib = work.join("libpowerloss.so");
    let built = Command::new("cc")
        .args(["-shared", "-O2", "-Wall", "-Wextra", "-fPIC", "-o"])
        .arg(&lib)
        .arg(repo_root().join("tools/powerloss/shim.c"))
        .arg("-ldl")
        .output()
        .expect("run cc");
    assert!(
        built.status.success(),
        "building the shim: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let params = dcroxide_chaincfg::simnet_params();
    let pubkey = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&KEY)
        .expect("key")
        .public_key()
        .serialize_compressed();
    let mine = new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash160(&pubkey), &params)
        .expect("mining address");
    let appdata = work.join("home");
    let mut rng = SplitMix64::from_entropy("the_index_answers_from_the_blocks_that_survived");
    let mut used = BTreeSet::new();
    used.insert(addr_to_key(&mine).expect("key"));
    let mut spent = HashSet::new();
    let mut last_tip = 0;
    for round in 0..ROUNDS {
        let log = work.join(format!("undo-{round}.log"));
        let daemon = start(&appdata, &mine.encode(), Some((&lib, &log)));
        if round == 0 {
            rpc(&daemon.addr, "generate", &format!("[{FIRST_BLOCKS}]"))
                .expect("mature the first coinbases");
        }
        // The cut: a SIGKILL a random delay after the round's first
        // transaction, so that no round is cut before it has put a
        // fresh address in play, however slow the machine.  It lands
        // at once if the mining ends first.  The thread hands back
        // whether it waited the delay out, which is what tells a cut
        // from a daemon that went on its own.
        let pid = daemon.child.0.id();
        let delay = Duration::from_millis(200 + rng.below(800));
        let (cue_tx, cue_rx) = std::sync::mpsc::channel::<()>();
        let killer = std::thread::spawn(move || {
            let waited = cue_rx.recv().is_ok()
                && matches!(
                    cue_rx.recv_timeout(delay),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                );
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            waited
        });
        // Every round still to come keeps `RESERVE` heights short of
        // the limit, so that no round starts with none left to mine.
        let height_cap = HEIGHT_LIMIT - (ROUNDS - 1 - round) * RESERVE;
        let before = used.len();
        let capped = mine_until_killed(
            &daemon, &mine, &mut rng, &mut used, &mut spent, height_cap, cue_tx,
        );
        let waited = killer.join().expect("killer");
        assert!(
            waited || capped,
            "round {round}: the daemon went before the cut"
        );
        assert!(used.len() > before, "round {round} sent no transaction");
        if capped {
            println!("round {round}: its heights ran out, so the cut landed on an idle daemon");
        }
        let Daemon { mut child, .. } = daemon;
        let _ = child.0.wait();
        assert!(
            std::fs::metadata(&log).is_ok_and(|m| m.len() > 0),
            "the shim logged nothing"
        );
        let replay = Command::new("python3")
            .arg(repo_root().join("tools/powerloss/replay.py"))
            .arg(&log)
            .output()
            .expect("run replay.py");
        assert!(
            replay.status.success(),
            "replay.py: {}",
            String::from_utf8_lossy(&replay.stderr)
        );

        let daemon = start(&appdata, &mine.encode(), None);
        let (tip, present) = check_index(&daemon, &used);
        println!(
            "round {round}: restarted at tip {tip}, {present} of {} addresses used so far \
             survived ({})",
            used.len(),
            String::from_utf8_lossy(&replay.stdout).trim()
        );
        // A clean stop ended the last round, so its tip is durable.
        assert!(tip >= last_tip, "round {round}: tip {tip} below {last_tip}");
        last_tip = tip;
        let _ = rpc(&daemon.addr, "stop", "[]");
        let Daemon { mut child, .. } = daemon;
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.0.try_wait().expect("wait").is_none() {
            assert!(Instant::now() < deadline, "the daemon never stopped");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let _ = std::fs::remove_dir_all(&work);
}
