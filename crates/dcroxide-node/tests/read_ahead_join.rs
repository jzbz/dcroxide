// SPDX-License-Identifier: ISC
//! No reader thread outlives its connection.
//!
//! A connection that is read ahead has a `peer-reader` thread
//! (`dcroxide_node::readahead`), which dcrd does not have.  When the
//! connection ends, that thread is joined before the connection returns,
//! like the output and timer threads, whatever it was doing: here it is
//! in the middle of checking, decoding and hashing large blocks when the
//! handler drops the peer.
//!
//! The thread is looked for by name among this process's own threads, so
//! the test is alone in its file: no other connection of the process has
//! a reader thread.
//!
//! A joined thread can still be listed for an instant.  The join returns
//! when the kernel clears the thread's id, which it does on the thread's
//! way out and before the thread's entry is gone.  A thread found as the
//! connection returns is therefore looked for once more a few
//! milliseconds later.  A thread that was not joined is still at work on
//! a large block then, which takes an unoptimized build far longer.

// Threads are listed through /proc.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use dcroxide_chainhash::Hash;
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{
    DisconnectReason, OutboundQueue, ServeHooks, ServeSignal, StallConfig,
    run_peer_connection_with_stall,
};
use dcroxide_node::transport::{Teardown, WireTransport};
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer, PeerGlobals};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, Message, MsgBlock, MsgTx, OutPoint, ServiceFlag, TxIn, TxOut,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

fn config(user_agent_name: &str) -> Config {
    Config {
        net: NET,
        services: ServiceFlag(1),
        user_agent_name: user_agent_name.to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    }
}

/// A block told apart by its header's nonce, with `txs` transactions.
fn block(nonce: u32, txs: u32) -> MsgBlock {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.nonce = nonce;
    let tx = |seed: u32| MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([seed as u8; 32]),
                index: seed,
                tree: 0,
            },
            sequence: u32::MAX,
            ..TxIn::default()
        }],
        tx_out: vec![TxOut {
            value: i64::from(seed),
            version: 0,
            pk_script: vec![0x51],
        }],
        ..MsgTx::default()
    };
    MsgBlock {
        header,
        transactions: (0..txs).map(tx).collect(),
        stransactions: Vec::new(),
    }
}

/// How long a joined thread is given to leave the kernel's list.
const GONE_WITHIN: Duration = Duration::from_millis(5);

/// How many threads of this process are reader threads.
fn reader_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("this process's threads")
        .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path().join("comm")).ok())
        .filter(|name| name.trim() == "peer-reader")
        .count()
}

/// How many reader threads are left once a thread that has just been
/// joined has had the moment it needs to go.
fn reader_threads_left() -> usize {
    match reader_threads() {
        0 => 0,
        _ => {
            thread::sleep(GONE_WITHIN);
            reader_threads()
        }
    }
}

/// Hooks that ask for read-ahead and drop the peer a moment into the
/// block with nonce 1.
struct DropAtSecondBlock;

impl ServeHooks for DropAtSecondBlock {
    fn on_message(
        &mut self,
        _peer: &Mutex<Peer>,
        msg: Message,
        _mix_hash: Option<Hash>,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        match msg {
            Message::Block(block) if block.header.nonce == 1 => {
                // Long enough for the large blocks behind this one to
                // have arrived, so that the reader thread is at work on
                // them and not waiting for the socket.
                thread::sleep(Duration::from_millis(15));
                ServeSignal::Disconnect("dropped by the handler".into())
            }
            _ => ServeSignal::Continue,
        }
    }

    fn read_ahead_wanted(&mut self) -> bool {
        true
    }
}

#[test]
fn the_reader_thread_is_joined_before_the_connection_returns() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let (ended_tx, ended) = mpsc::channel();
    thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);
        let reason = run_peer_connection_with_stall(
            Teardown::new(stream),
            peer,
            MAX_PROTOCOL_VERSION,
            NET,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            None,
            DropAtSecondBlock,
            StallConfig {
                tick: Duration::from_millis(50),
                response_timeout: Duration::from_secs(3600),
            },
        );
        // The moment the connection has returned.
        let _ = ended_tx.send((reason, reader_threads_left()));
    });

    let stream = TcpStream::connect(addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, NET);
    let mut peer =
        Peer::new_outbound(config("dcroxide-out"), &addr.to_string()).expect("outbound peer");
    peer.negotiate_outbound_protocol(
        &mut transport,
        &mut NodePeerEnv::new(),
        &PeerGlobals::new(),
        None,
    )
    .expect("outbound negotiation");
    assert_eq!(reader_threads(), 0, "no connection has been read ahead yet");

    // A block to start reading ahead behind, the block that gets the
    // peer dropped, and three large blocks for the reader to be busy
    // with meanwhile.
    let mut stream: Vec<u8> = Vec::new();
    for msg in [
        Message::Block(block(0, 1)),
        Message::Block(block(1, 1)),
        Message::Block(block(2, 12_000)),
        Message::Block(block(3, 12_000)),
        Message::Block(block(4, 12_000)),
    ] {
        stream
            .extend(dcroxide_wire::write_message(&msg, MAX_PROTOCOL_VERSION, NET).expect("frame"));
    }
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");
    // The node may close before it has taken everything.
    let _ = sender.write_all(&stream);

    let (reason, readers) = ended
        .recv_timeout(Duration::from_secs(60))
        .expect("the connection ends");
    assert!(
        matches!(&reason, DisconnectReason::Protocol(r) if r == "dropped by the handler"),
        "{reason:?}"
    );
    assert_eq!(
        readers, 0,
        "a reader thread was still running when its connection returned"
    );
}
