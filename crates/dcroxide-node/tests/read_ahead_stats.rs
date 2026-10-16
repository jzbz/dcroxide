// SPDX-License-Identifier: ISC
//! The figures of the line the daemon logs about reading ahead as it
//! shuts down (`dcroxide_node::readahead::shutdown_line`).
//!
//! A sync is judged by that line: how many blocks the reader threads
//! read and how many bytes they were, how long the checksums, the
//! decoding and the hashing took off the block thread, how long each
//! side waited for the other, and how full the queue got.  One
//! connection is driven here through a stream whose figures are known,
//! with hooks that time themselves:
//!
//! - a first block, which the input thread reads for itself and behind
//!   which the connection is read ahead;
//! - a block whose handler is slow, with five more behind it, so that
//!   the reader fills its queue and waits for the handler;
//! - after a pause, a ping whose handler is slow too.  The handler's
//!   wait for the ping is not a wait for a block, and the reader's wait
//!   while the ping is handled is not a wait on a full queue: it reads
//!   in turn behind a message that is not a block.  Neither is counted;
//! - after another pause, a large block, which the handler waits for;
//! - and, once the server has said reading ahead is no longer wanted,
//!   one more block after one more pause.  The reader thread reads it in
//!   turn, and the handler's wait for it is not counted: that wait is
//!   every connection's between blocks once the sync is done.
//!
//! The counters are sums over the whole process, so the test is alone in
//! its file.

// Test-harness arithmetic over small counts and fixed waits.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_chainhash::Hash;
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{
    DisconnectReason, OutboundQueue, ServeHooks, ServeSignal, StallConfig,
    run_peer_connection_with_stall,
};
use dcroxide_node::transport::{Teardown, WireTransport};
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, Message, MsgBlock, MsgPing, MsgTx, OutPoint, ServiceFlag, TxIn, TxOut,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// How long the slow handlers take, and how long the peer pauses before
/// the ping and before the last block.
const SLOW: Duration = Duration::from_millis(400);

/// How far a wait the line reports may be from the same wait as the
/// hooks timed it.  A wait that should not have been counted is
/// [`SLOW`] long, twice this.
const TOLERANCE: Duration = Duration::from_millis(200);

/// The bound on every wait for something that must happen.
const PATIENCE: Duration = Duration::from_secs(30);

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

/// The bytes of a block as the peer frames it.
fn framed(block: &MsgBlock) -> Vec<u8> {
    dcroxide_wire::write_message(&Message::Block(block.clone()), MAX_PROTOCOL_VERSION, NET)
        .expect("frame the block")
}

/// What the hooks handled, and when the handler began and ended.
#[derive(Clone, Copy, Debug)]
struct Handled {
    /// The nonce of the block, or `None` for the ping.
    block: Option<u32>,
    began: Instant,
    ended: Instant,
}

/// The nonce of the block from which reading ahead is no longer wanted.
const LAST_WANTED: u32 = 7;

/// Hooks that ask for read-ahead until they have handled the block with
/// nonce [`LAST_WANTED`], take [`SLOW`] over the block with nonce 1 and
/// over a ping, and report every block and ping they handle with the
/// time the handler began and ended.
struct TimedHooks {
    handled: mpsc::Sender<Handled>,
    /// Whether reading ahead is still wanted.
    wanted: bool,
}

impl ServeHooks for TimedHooks {
    fn on_message(
        &mut self,
        _peer: &Mutex<Peer>,
        msg: Message,
        _mix_hash: Option<Hash>,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        let began = Instant::now();
        let block = match &msg {
            Message::Block(block) => Some(block.header.nonce),
            Message::Ping(_) => None,
            _ => return ServeSignal::Continue,
        };
        if block.is_none_or(|nonce| nonce == 1) {
            thread::sleep(SLOW);
        }
        if block.is_some_and(|nonce| nonce >= LAST_WANTED) {
            self.wanted = false;
        }
        let _ = self.handled.send(Handled {
            block,
            began,
            ended: Instant::now(),
        });
        ServeSignal::Continue
    }

    fn read_ahead_wanted(&mut self) -> bool {
        self.wanted
    }
}

/// The text of the line between two of its fixed parts.
fn between<'a>(line: &'a str, before: &str, after: &str) -> &'a str {
    let rest = line
        .split_once(before)
        .unwrap_or_else(|| panic!("{before:?} is missing from: {line}"))
        .1;
    rest.split_once(after)
        .unwrap_or_else(|| panic!("{after:?} is missing from: {line}"))
        .0
}

/// A count of the line.
fn count(line: &str, before: &str, after: &str) -> u64 {
    between(line, before, after)
        .parse()
        .unwrap_or_else(|_| panic!("a count between {before:?} and {after:?}: {line}"))
}

/// A time of the line, which is in seconds to the millisecond.
fn time(line: &str, before: &str, after: &str) -> Duration {
    let text = between(line, before, after);
    let (seconds, millis) = text
        .split_once('.')
        .unwrap_or_else(|| panic!("a time between {before:?} and {after:?}: {line}"));
    assert_eq!(millis.len(), 3, "milliseconds in {text:?}: {line}");
    let seconds: u64 = seconds.parse().expect("seconds");
    let millis: u64 = millis.parse().expect("milliseconds");
    Duration::from_millis(seconds * 1000 + millis)
}

/// The next thing the hooks handled, which must be what is expected.
#[track_caller]
fn expect_handled(handled: &mpsc::Receiver<Handled>, block: Option<u32>) -> Handled {
    let next = handled
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|_| panic!("{block:?} was never handled"));
    assert_eq!(next.block, block, "handled out of order");
    next
}

#[test]
fn the_shutdown_line_reports_the_figures_of_a_known_stream() {
    assert_eq!(
        dcroxide_node::readahead::shutdown_line(0),
        None,
        "nothing has been read ahead in this process yet"
    );

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let (handled_tx, handled) = mpsc::channel();
    let (reason_tx, reason_rx) = mpsc::channel();
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
            TimedHooks {
                handled: handled_tx,
                wanted: true,
            },
            StallConfig {
                tick: Duration::from_millis(50),
                response_timeout: Duration::from_secs(3600),
            },
        );
        let _ = reason_tx.send(reason);
    });

    let stream = TcpStream::connect(addr).expect("dial the listener");
    stream
        .set_read_timeout(Some(PATIENCE))
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
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");

    // The first block, the slow one and the five behind it, at once.
    let small: Vec<Vec<u8>> = (0..=6).map(|nonce| framed(&block(nonce, 1))).collect();
    sender.write_all(&small.concat()).expect("send the blocks");
    let first = expect_handled(&handled, Some(0));
    let slow = expect_handled(&handled, Some(1));
    for nonce in 2..=6 {
        expect_handled(&handled, Some(nonce));
    }

    // A pause, in which the handler waits for a frame that turns out
    // not to be a block, and the ping, whose handler is slow.
    thread::sleep(SLOW);
    transport
        .write_message(&Message::Ping(MsgPing { nonce: 1 }))
        .expect("send ping");
    let ping = expect_handled(&handled, None);

    // Another pause, and a large block: the handler waits for it.
    thread::sleep(SLOW);
    let large = framed(&block(LAST_WANTED, 12_000));
    sender.write_all(&large).expect("send the large block");
    let last = expect_handled(&handled, Some(LAST_WANTED));

    // Reading ahead is no longer wanted.  One more pause and one more
    // block, which the handler waits for as it does after a sync.
    thread::sleep(SLOW);
    let after = framed(&block(LAST_WANTED + 1, 1));
    sender.write_all(&after).expect("send the block after");
    expect_handled(&handled, Some(LAST_WANTED + 1));

    drop(sender);
    drop(transport);
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("closing the connection ends it");
    assert!(
        matches!(reason, DisconnectReason::ReadError(_)),
        "{reason:?}"
    );

    // No database runs here: the count of records one wrote as they
    // were handed to it is the caller's to give, and the line repeats it.
    let line = dcroxide_node::readahead::shutdown_line(3).expect("a reader thread read blocks");
    // Every block but the first was read by the reader thread, on the
    // one connection there was.
    assert_eq!(count(&line, "Read-ahead: ", " blocks ("), 8, "{line}");
    let bytes: usize = small[1..].iter().map(Vec::len).sum::<usize>() + large.len() + after.len();
    assert_eq!(
        count(&line, " blocks (", " bytes) on "),
        bytes as u64,
        "{line}"
    );
    assert_eq!(count(&line, " bytes) on ", " connections; "), 1, "{line}");
    // The four blocks behind the slow one filled the queue.
    assert_eq!(count(&line, "; at most ", " items queued; "), 4, "{line}");

    // The work that left the input thread was timed.  The large block
    // alone takes milliseconds to check and decode, and to hash.
    let decode = time(&line, "; checksum and decode ", " s and hashing ");
    let hashing = time(&line, " s and hashing ", " s done off the block thread; ");
    assert!(decode >= Duration::from_millis(1), "{line}");
    assert!(hashing >= Duration::from_millis(1), "{line}");

    // The reader waited for the handler while the queue was full, which
    // was while the slow block was handled, and at no other time: not
    // while the ping was handled.
    let reader_waited = time(
        &line,
        "; the reader waited ",
        " s for the block thread; the block thread waited ",
    );
    let queue_full = slow.ended.duration_since(slow.began);
    assert!(
        reader_waited.abs_diff(queue_full) <= TOLERANCE,
        "the queue was full for {queue_full:?}: {line}"
    );

    // The handler waited for the reader each time it came back for a
    // block that had not been read yet while reading ahead was wanted:
    // for the block behind the first, and for the large one.  Its wait
    // for the ping is not counted, and neither are its wait for the
    // block that came when reading ahead was no longer wanted and its
    // wait for the end of the stream.
    let handler_waited = time(
        &line,
        " s for the block thread; the block thread waited ",
        " s for the reader; ",
    );
    let for_blocks = slow.began.duration_since(first.ended) + last.began.duration_since(ping.ended);
    assert!(
        handler_waited.abs_diff(for_blocks) <= TOLERANCE,
        "the handler waited {for_blocks:?} for blocks: {line}"
    );

    // No index thread runs here.
    assert_eq!(
        time(
            &line,
            "; index queue full for ",
            " s; block-file records laid out for "
        ),
        Duration::ZERO,
        "{line}"
    );

    // Every block the reader thread read went to the handler with its
    // payload laid out as its block-file record, which took the reader
    // time: the large block's comparison and checksum alone are over
    // hundreds of kilobytes.
    assert_eq!(
        count(&line, "; block-file records laid out for ", " blocks in "),
        8,
        "{line}"
    );
    let laid_out = time(&line, " blocks in ", " s, 3 written as laid out");
    assert!(laid_out < PATIENCE, "{line}");
    assert!(line.ends_with(" s, 3 written as laid out"), "{line}");
}
