// SPDX-License-Identifier: ISC
//! Reading ahead of the block handler, over real loopback connections.
//!
//! A served connection whose server asks for it gets a `peer-reader`
//! thread that reads the socket up to sixteen frames ahead of the input
//! thread (`dcroxide_node::readahead`), which dcrd does not have: its
//! `inHandler` reads a message only when its listener has returned from
//! the one before (`peer/peer.go:1535-1599`).  These tests pin what must
//! not change with it.  The server sees the same calls, with the same
//! contents, in the same order; the peer sees the same replies; the
//! connection ends the same way; the stall detector and the peer's
//! receive counters learn of a message when it is handled, not when it
//! is read; the idle timer runs from when the handler went idle; and
//! nothing read ahead is acted on once the connection is being torn
//! down.
//!
//! The hooks here are the server's stand-in.  They ask for read-ahead
//! after every block, where the daemon asks only for its sync peer
//! during the initial chain sync (`tests/dispatch.rs`).

// Test-harness arithmetic over small counts and fixed waits.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_blockchain::{BlockTxHashes, HashedBlock};
use dcroxide_chainhash::Hash;
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{
    DisconnectReason, OutboundQueue, ServeHooks, ServeSignal, StallConfig,
    run_peer_connection_with_stall,
};
use dcroxide_node::transport::{READ_POLL_INTERVAL, Teardown, WireTransport};
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, MESSAGE_HEADER_SIZE, Message, MsgAddrV2, MsgBlock,
    MsgFeeFilter, MsgGetData, MsgHeaders, MsgInv, MsgMixSlotReserve, MsgPing, MsgPong, MsgTx,
    OutPoint, ServiceFlag, TxIn, TxOut,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// Long enough that the timer it is given to never fires in a test.
const NEVER: Duration = Duration::from_secs(3600);

/// The bound on every wait for something that must happen.
const PATIENCE: Duration = Duration::from_secs(20);

/// Stall timings under which the detector never ends a connection.
const NO_STALL: StallConfig = StallConfig {
    tick: Duration::from_millis(50),
    response_timeout: NEVER,
};

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

/// Serve one inbound connection with the hooks `make_hooks` builds from
/// a second handle on the connection, which shares its teardown flag as
/// the server's registry handle does.  The reason the connection ended
/// is published on the returned channel once every thread of the
/// connection has been joined.
fn serve<H, F>(
    idle_timeout: Duration,
    stall: StallConfig,
    make_hooks: F,
) -> (SocketAddr, mpsc::Receiver<DisconnectReason>)
where
    H: ServeHooks + 'static,
    F: FnOnce(Teardown) -> H + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let (reason_tx, reason_rx) = mpsc::channel();
    thread::spawn(move || {
        let (stream, remote_addr) = listener.accept().expect("accept connection");
        let mut peer = Peer::new_inbound(config("dcroxide-in"));
        let na = net_address_v2_from_socket(remote_addr, ServiceFlag(0)).expect("net address");
        peer.associate(&remote_addr.to_string(), na, 0);
        let conn = Teardown::new(stream);
        let hooks = make_hooks(conn.try_clone().expect("a second handle"));
        let reason = run_peer_connection_with_stall(
            conn,
            peer,
            MAX_PROTOCOL_VERSION,
            NET,
            idle_timeout,
            NEVER,
            None,
            hooks,
            stall,
        );
        let _ = reason_tx.send(reason);
    });
    (addr, reason_rx)
}

/// Connect to the served peer and complete the version handshake.
fn dial(addr: SocketAddr) -> WireTransport<TcpStream> {
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
    transport
}

/// The bytes of a message as the peer frames it.
fn framed(msg: &Message) -> Vec<u8> {
    dcroxide_wire::write_message(msg, MAX_PROTOCOL_VERSION, NET).expect("frame the message")
}

/// A transaction that differs with `seed`.
fn tx(seed: u32) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([seed as u8; 32]),
                index: seed,
                tree: 0,
            },
            sequence: u32::MAX,
            signature_script: vec![0x51; (seed % 40) as usize],
            ..TxIn::default()
        }],
        tx_out: vec![TxOut {
            value: i64::from(seed),
            version: 0,
            pk_script: vec![0x51],
        }],
        ..MsgTx::default()
    }
}

/// A header that differs with `nonce`.
fn header(nonce: u32) -> BlockHeader {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.nonce = nonce;
    header.height = nonce;
    header
}

/// A block that differs with `nonce`, with `txs` transactions in each
/// tree.
fn block(nonce: u32, txs: u32) -> MsgBlock {
    MsgBlock {
        header: header(nonce),
        transactions: (0..txs).map(|i| tx(nonce.wrapping_add(i))).collect(),
        stransactions: (0..txs)
            .map(|i| tx(nonce.wrapping_mul(7).wrapping_add(i)))
            .collect(),
    }
}

/// The inventory of a block.
fn block_inv(block: &MsgBlock) -> InvVect {
    InvVect {
        inv_type: InvType::BLOCK,
        hash: block.header.block_hash(),
    }
}

/// A small deterministic generator.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One of the kinds of message a peer sends, chosen by the generator.
fn any_message(rng: &mut Lcg, serial: u32) -> Message {
    match rng.below(16) {
        // Blocks are the most common, as during a sync.
        0..=6 => Message::Block(block(serial, rng.below(3) as u32)),
        7 => Message::Ping(MsgPing {
            nonce: u64::from(serial),
        }),
        8 => Message::Pong(MsgPong {
            nonce: u64::from(serial),
        }),
        9 => Message::Inv(MsgInv {
            inv_list: (0..1 + rng.below(3))
                .map(|i| InvVect {
                    inv_type: InvType::TX,
                    hash: Hash([(serial as u8).wrapping_add(i as u8); 32]),
                })
                .collect(),
        }),
        10 => Message::Headers(MsgHeaders {
            headers: (0..1 + rng.below(3) as u32)
                .map(|i| header(serial.wrapping_add(i)))
                .collect(),
        }),
        11 => Message::GetData(MsgGetData {
            inv_list: vec![InvVect {
                inv_type: InvType::BLOCK,
                hash: Hash([serial as u8; 32]),
            }],
        }),
        12 => Message::Tx(tx(serial)),
        13 => Message::AddrV2(MsgAddrV2 {
            addr_list: (0..1 + rng.below(3) as u16)
                .map(|i| {
                    let addr = SocketAddr::from(([10, 0, serial as u8, 1], 9108 + i));
                    net_address_v2_from_socket(addr, ServiceFlag(1)).expect("net address")
                })
                .collect(),
        }),
        14 => Message::FeeFilter(MsgFeeFilter {
            min_fee: i64::from(serial),
        }),
        // A mixing message, which is hashed as it is read.
        _ => Message::MixSlotReserve(MsgMixSlotReserve {
            signature: [0; 64],
            identity: [0; 33],
            session_id: [serial as u8; 32],
            run: serial,
            dc_mix: vec![vec![vec![1; 32]]],
            seen_ciphertexts: Vec::new(),
        }),
    }
}

/// How a generated stream ends.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// The peer closes its side.
    Close,
    /// A whole frame whose checksum is wrong.
    BadChecksum,
    /// A header naming a command that does not exist.
    UnknownCommand,
    /// An inventory message with a byte left over after its payload.
    TrailingByte,
}

/// The bytes of the frame a stream ends with, if it ends with one.
fn ending_frame(ending: Ending) -> Vec<u8> {
    const PAYLOAD_LEN_AT: usize = 16;
    const CHECKSUM_AT: usize = 20;
    match ending {
        Ending::Close => Vec::new(),
        Ending::BadChecksum => {
            let mut frame = framed(&Message::Ping(MsgPing { nonce: 99 }));
            frame[CHECKSUM_AT] ^= 0xff;
            frame
        }
        Ending::UnknownCommand => {
            let mut frame = framed(&Message::VerAck);
            frame[4..16].copy_from_slice(b"notacommand\0");
            frame
        }
        Ending::TrailingByte => {
            let mut frame = framed(&Message::Inv(MsgInv {
                inv_list: vec![InvVect {
                    inv_type: InvType::TX,
                    hash: Hash([9; 32]),
                }],
            }));
            frame.push(0);
            let payload_len = (frame.len() - MESSAGE_HEADER_SIZE) as u32;
            frame[PAYLOAD_LEN_AT..PAYLOAD_LEN_AT + 4].copy_from_slice(&payload_len.to_le_bytes());
            let checksum = dcroxide_chainhash::hash_b(&frame[MESSAGE_HEADER_SIZE..]);
            frame[CHECKSUM_AT..CHECKSUM_AT + 4].copy_from_slice(&checksum[..4]);
            frame
        }
    }
}

/// When the recording hooks say reading ahead is wanted.
#[derive(Clone, Copy, Debug)]
enum Wanted {
    /// Never: every read is the input thread's own.
    Never,
    /// After every block.
    Always,
    /// After every block until this many have been handled.
    Until(usize),
    /// After a block or not, by a generator seeded with this.
    Random(u64),
}

/// What the recording hooks do besides recording.
#[derive(Clone, Copy, Debug)]
struct Behaviour {
    wanted: Wanted,
    /// Answer this message, counted from zero, with a disconnect.
    disconnect_at: Option<usize>,
    /// Tear the connection down from inside this message's handler, as
    /// a sync-manager disconnect action does, and keep serving.
    tear_down_at: Option<usize>,
    /// Whether a wire violation is answered with a ban that disconnects.
    ban_violations: bool,
    /// Sleep this long in every block's handler, so that frames behind
    /// the block are read while it is handled.
    block_delay: Duration,
}

/// One call the server's stand-in received.
// A transcript entry is a whole message or next to nothing, and boxing
// the message would only obscure the comparisons.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
enum Call {
    Connected,
    /// A message, the mixing hash it arrived with, and the bytes the
    /// peer's receive counter had gained since the handshake when the
    /// handler was called.
    Message {
        msg: Message,
        mix_hash: Option<Hash>,
        received: u64,
    },
    /// The input loop asked whether reading ahead is wanted.
    AskedReadAhead,
    WireViolation(String),
    Disconnected,
    /// A block arrived with hashes that are not its own.
    WrongHashes(Hash),
    /// A block the reader thread read arrived without the payload it
    /// was read in laid out as its block-file record, or with a record
    /// of other bytes than its serialization.
    WrongRecord(Hash),
}

/// Hooks that record every call and behave as told.
///
/// A block is recorded as the message it arrived as, whether the input
/// thread read it and it came through `on_message`, or the reader thread
/// read it ahead and it came through `on_block` with its hashes: the two
/// transcripts are then the same exactly when the server was handed the
/// same blocks at the same positions.
struct Recorder {
    calls: Arc<Mutex<Vec<Call>>>,
    behaviour: Behaviour,
    killer: Teardown,
    /// The peer's receive counter as the connection was handed over.
    received_base: u64,
    messages: usize,
    blocks: usize,
    wanted_rng: Lcg,
    /// How many blocks arrived with their hashes.
    hashed_blocks: Arc<AtomicUsize>,
}

impl Recorder {
    fn record(&self, call: Call) {
        self.calls.lock().expect("calls").push(call);
    }

    /// Record a message and do with it what the script says.
    fn handle(&mut self, peer: &Mutex<Peer>, msg: Message, mix_hash: Option<Hash>) -> ServeSignal {
        let received = peer
            .lock()
            .expect("peer")
            .stats_snapshot()
            .bytes_recv
            .wrapping_sub(self.received_base);
        let is_block = matches!(msg, Message::Block(_));
        self.record(Call::Message {
            msg,
            mix_hash,
            received,
        });
        let index = self.messages;
        self.messages += 1;
        if is_block {
            self.blocks += 1;
            if !self.behaviour.block_delay.is_zero() {
                thread::sleep(self.behaviour.block_delay);
            }
        }
        if self.behaviour.tear_down_at == Some(index) {
            self.killer.disconnect();
        }
        if self.behaviour.disconnect_at == Some(index) {
            return ServeSignal::Disconnect("the script says so".into());
        }
        ServeSignal::Continue
    }
}

impl ServeHooks for Recorder {
    fn on_connected(
        &mut self,
        peer: &Arc<Mutex<Peer>>,
        _outbound: &OutboundQueue,
        _remote_disable_relay_tx: bool,
    ) {
        self.received_base = peer.lock().expect("peer").stats_snapshot().bytes_recv;
        self.record(Call::Connected);
    }

    fn on_message(
        &mut self,
        peer: &Mutex<Peer>,
        msg: Message,
        mix_hash: Option<Hash>,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        self.handle(peer, msg, mix_hash)
    }

    fn on_block(
        &mut self,
        peer: &Mutex<Peer>,
        block: HashedBlock,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        self.hashed_blocks.fetch_add(1, Ordering::SeqCst);
        // The hashes are the block's own.
        if *block.hash() != block.block().header.block_hash()
            || **block.tx_hashes() != BlockTxHashes::compute(block.block())
        {
            self.record(Call::WrongHashes(*block.hash()));
        }
        // And so is the record: the payload the block arrived in, which
        // is its serialization, under its own header's hash.
        if block.record().is_none_or(|record| {
            record.block() != block.block().serialize() || record.hash() != block.hash()
        }) {
            self.record(Call::WrongRecord(*block.hash()));
        }
        let block = Arc::unwrap_or_clone(block.into_block());
        self.handle(peer, Message::Block(block), None)
    }

    fn on_wire_violation(&mut self, err: &str) -> ServeSignal {
        self.record(Call::WireViolation(err.to_string()));
        if self.behaviour.ban_violations {
            ServeSignal::Disconnect("banned by the script".into())
        } else {
            ServeSignal::Continue
        }
    }

    fn read_ahead_wanted(&mut self) -> bool {
        self.record(Call::AskedReadAhead);
        match self.behaviour.wanted {
            Wanted::Never => false,
            Wanted::Always => true,
            Wanted::Until(blocks) => self.blocks < blocks,
            Wanted::Random(_) => self.wanted_rng.below(3) != 0,
        }
    }

    fn on_disconnected(&mut self, _peer: &Mutex<Peer>) {
        self.record(Call::Disconnected);
    }
}

/// Everything observable about one connection.
#[derive(Debug)]
struct Outcome {
    /// The calls the server's stand-in received, in order.
    calls: Vec<Call>,
    /// What the peer received, in order.
    replies: Vec<Message>,
    /// How the connection ended.
    reason: String,
    /// How many of the blocks arrived with their hashes, which only a
    /// block the reader thread read ahead does.
    hashed_blocks: usize,
}

/// Serve one connection with recording hooks, send it `stream` in one
/// write, close the sending side and collect everything observable.
///
/// The peer only half-closes and then reads until the node closes, so
/// the node never writes to a connection the peer has abandoned: a reset
/// could otherwise end one run early and not the other.  With
/// `await_replies` it half-closes only once it has read that many
/// messages, so that the node's output loop has written every reply
/// before the end of the stream ends the connection.  Otherwise the
/// replies still queued when the node tears the connection down are
/// lost, as they are without read-ahead, and how many is a race between
/// the node's own input and output loops.
fn exchange(stream: &[u8], behaviour: Behaviour, await_replies: Option<usize>) -> Outcome {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);
    let hashed_blocks = Arc::new(AtomicUsize::new(0));
    let hashed = Arc::clone(&hashed_blocks);
    let (addr, reason_rx) = serve(Duration::from_secs(60), NO_STALL, move |killer| Recorder {
        calls: recorded,
        behaviour,
        killer,
        received_base: 0,
        messages: 0,
        blocks: 0,
        wanted_rng: Lcg(match behaviour.wanted {
            Wanted::Random(seed) => seed,
            _ => 0,
        }),
        hashed_blocks: hashed,
    });
    let mut transport = dial(addr);
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");
    // A torn-down connection may refuse part of the stream.
    let _ = sender.write_all(stream);

    let mut replies = Vec::new();
    while replies.len() < await_replies.unwrap_or(0) {
        replies.push(transport.read_message().expect("a reply the node owes"));
    }
    let _ = sender.shutdown(Shutdown::Write);
    while let Ok(msg) = transport.read_message() {
        replies.push(msg);
    }
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("the connection must end");
    let calls = calls.lock().expect("calls").clone();
    Outcome {
        calls,
        replies,
        reason: format!("{reason:?}"),
        hashed_blocks: hashed_blocks.load(Ordering::SeqCst),
    }
}

/// How many connections have started a reader thread in this process,
/// from the line the daemon logs at shutdown.
fn reader_threads_started() -> u64 {
    let Some(line) = dcroxide_node::readahead::shutdown_line(0) else {
        return 0;
    };
    let rest = line.split_once(" bytes) on ").expect("the line's shape").1;
    rest.split_once(" connections")
        .expect("the line's shape")
        .0
        .parse()
        .expect("a count")
}

/// The central test: whatever the peer sends and however the server
/// answers, the server sees the same calls with the same contents in the
/// same order, the peer gets the same replies, and the connection ends
/// the same way, whether or not the connection is read ahead.
///
/// Each seed makes a stream of blocks and other messages that ends in a
/// close or in one of three malformed frames, and a script for the
/// server: when reading ahead is wanted, whether a message is answered
/// with a disconnect or tears the connection down, and whether a wire
/// violation bans.  The stream is run once with the input thread reading
/// for itself and once with reading ahead wanted as scripted.
#[test]
fn the_handler_sees_the_same_calls_with_and_without_read_ahead() {
    let readers_before = reader_threads_started();
    let (mut with_blocks, mut violations, mut torn_down, mut refused) = (0, 0, 0, 0);
    let (mut hashed_ahead, mut blocks_handled) = (0, 0);
    for seed in 0..300u64 {
        let mut rng = Lcg(seed.wrapping_mul(0x9e37_79b9).wrapping_add(1));
        let frames = 3 + rng.below(30) as usize;
        let messages: Vec<Message> = (0..frames)
            .map(|i| any_message(&mut rng, (seed as u32) << 8 | i as u32))
            .collect();
        let ending = match rng.below(4) {
            0 => Ending::Close,
            1 => Ending::BadChecksum,
            2 => Ending::UnknownCommand,
            _ => Ending::TrailingByte,
        };
        let sizes: Vec<u64> = messages.iter().map(|m| framed(m).len() as u64).collect();
        let mut stream: Vec<u8> = messages.iter().flat_map(framed).collect();
        stream.extend(ending_frame(ending));

        let scripted = rng.below(5);
        let script = Behaviour {
            wanted: Wanted::Never,
            disconnect_at: (scripted == 1).then(|| rng.below(frames as u64) as usize),
            tear_down_at: (scripted == 2).then(|| rng.below(frames as u64) as usize),
            ban_violations: rng.below(2) == 0,
            block_delay: if rng.below(6) == 0 {
                Duration::from_millis(1)
            } else {
                Duration::ZERO
            },
        };
        let wanted = match rng.below(4) {
            0 | 1 => Wanted::Always,
            2 => Wanted::Until(rng.below(6) as usize),
            _ => Wanted::Random(seed),
        };

        // What the node owes the peer: the request for header
        // announcements every served connection begins with, then a pong
        // for every ping it handles, in order.
        let cut = script
            .disconnect_at
            .or(script.tear_down_at)
            .map_or(frames, |at| at + 1);
        let mut owed = vec![Message::SendHeaders];
        owed.extend(messages[..cut].iter().filter_map(|msg| match msg {
            Message::Ping(ping) => Some(Message::Pong(MsgPong { nonce: ping.nonce })),
            _ => None,
        }));
        // Only a stream the peer ends itself is sure to have every reply
        // written before the connection ends.  A disconnect or a
        // teardown scripted for the last message ends it from the node's
        // side as one scripted for any other message does, with the
        // replies before it possibly still queued.
        let unbroken = matches!(ending, Ending::Close)
            && script.disconnect_at.is_none()
            && script.tear_down_at.is_none();
        let await_replies = unbroken.then_some(owed.len());

        let inline = exchange(&stream, script, await_replies);
        let ahead = exchange(&stream, Behaviour { wanted, ..script }, await_replies);
        let context = format!("seed {seed}: {ending:?}, {script:?}, {wanted:?}");
        assert_eq!(ahead.calls, inline.calls, "{context}");
        assert_eq!(ahead.reason, inline.reason, "{context}");
        // A block the input thread reads for itself never comes hashed.
        assert_eq!(inline.hashed_blocks, 0, "{context}");
        hashed_ahead += ahead.hashed_blocks;
        blocks_handled += ahead
            .calls
            .iter()
            .filter(|call| {
                matches!(
                    call,
                    Call::Message {
                        msg: Message::Block(_),
                        ..
                    }
                )
            })
            .count();
        for (mode, outcome) in [("inline", &inline), ("ahead", &ahead)] {
            if unbroken {
                assert_eq!(outcome.replies, owed, "{mode}, {context}");
            } else {
                // Nothing but what is owed, in order; the tail may have
                // been cut off by the teardown.
                assert!(
                    outcome.replies.len() <= owed.len()
                        && outcome.replies == owed[..outcome.replies.len()],
                    "{mode}, {context}: {:?} is not the start of {owed:?}",
                    outcome.replies
                );
            }
        }

        // What the inline run saw is what was sent: every message up to
        // the scripted end, each with the bytes of the frames so far.
        let handled: Vec<&Call> = inline
            .calls
            .iter()
            .filter(|call| matches!(call, Call::Message { .. }))
            .collect();
        assert_eq!(handled.len(), cut, "seed {seed}");
        let mut total = 0;
        for (i, call) in handled.iter().enumerate() {
            total += sizes[i];
            let Call::Message { msg, received, .. } = call else {
                unreachable!("filtered above");
            };
            assert_eq!(msg, &messages[i], "seed {seed}: message {i}");
            assert_eq!(*received, total, "seed {seed}: bytes at message {i}");
        }

        with_blocks += usize::from(messages.iter().any(|m| matches!(m, Message::Block(_))));
        violations += usize::from(
            inline
                .calls
                .iter()
                .any(|call| matches!(call, Call::WireViolation(_))),
        );
        torn_down += usize::from(inline.reason.contains("torn down locally"));
        refused += usize::from(inline.reason.contains("the script says so"));
    }

    // The seeds cover what they are meant to.
    assert!(with_blocks > 250, "{with_blocks} streams with a block");
    assert!(violations > 60, "{violations} streams ended in a violation");
    assert!(torn_down > 30, "{torn_down} connections were torn down");
    assert!(refused > 30, "{refused} connections were refused");
    let readers = reader_threads_started() - readers_before;
    assert!(
        readers > 150,
        "only {readers} of the connections were read ahead"
    );
    // Most of the blocks handled while reading ahead came through the
    // reader thread, hashed: every block behind the first of a
    // connection that wanted it.
    assert!(
        hashed_ahead * 2 > blocks_handled,
        "{hashed_ahead} of {blocks_handled} blocks arrived hashed"
    );
}

/// Hooks for the scenario tests: a handler closure, an answer to whether
/// reading ahead is wanted, and a count of wire violations, which are
/// answered with a ban that disconnects.
struct Scenario<F> {
    wanted: bool,
    handle: F,
    violations: Arc<AtomicUsize>,
}

impl<F> ServeHooks for Scenario<F>
where
    F: FnMut(&Message, &OutboundQueue) -> ServeSignal,
{
    fn on_message(
        &mut self,
        _peer: &Mutex<Peer>,
        msg: Message,
        _mix_hash: Option<Hash>,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        (self.handle)(&msg, outbound)
    }

    fn on_wire_violation(&mut self, _err: &str) -> ServeSignal {
        self.violations.fetch_add(1, Ordering::SeqCst);
        ServeSignal::Disconnect("banned".into())
    }

    fn read_ahead_wanted(&mut self) -> bool {
        self.wanted
    }
}

/// Send the blocks, in order, in one write.
fn send_blocks(transport: &mut WireTransport<TcpStream>, blocks: &[MsgBlock]) {
    let bytes: Vec<u8> = blocks
        .iter()
        .flat_map(|b| framed(&Message::Block(b.clone())))
        .collect();
    transport
        .get_ref()
        .try_clone()
        .expect("clone the socket")
        .write_all(&bytes)
        .expect("send the blocks");
}

/// Read messages until one of `command` arrives.
fn read_until(transport: &mut WireTransport<TcpStream>, command: &str) -> Message {
    loop {
        let msg = transport
            .read_message()
            .unwrap_or_else(|e| panic!("waiting for {command}: {e}"));
        if msg.command() == command {
            return msg;
        }
    }
}

/// Ping the served peer and prove it is still answering.
fn assert_still_serving(transport: &mut WireTransport<TcpStream>, nonce: u64) {
    transport
        .write_message(&Message::Ping(MsgPing { nonce }))
        .expect("send ping");
    match read_until(transport, "pong") {
        Message::Pong(pong) => assert_eq!(pong.nonce, nonce),
        other => panic!("expected pong, got {other:?}"),
    }
}

/// A block that was read ahead settles its stall deadline when it is
/// handled, not when it is read.
///
/// The detector forgives the node's own handling time for the latest
/// check interval only, as dcrd's does (`peer/peer.go:1260-1279`), so a
/// requested block that waits behind two long handlers misses its
/// deadline and its peer is dropped as stalled, in dcrd and here.  With
/// reading ahead the block has long been read by then; were its deadline
/// settled at the read, the connection would survive.  It must end the
/// same way whether or not the connection is read ahead.
#[test]
fn a_block_read_ahead_settles_its_deadline_only_when_it_is_handled() {
    const STALL: StallConfig = StallConfig {
        tick: Duration::from_millis(50),
        response_timeout: Duration::from_millis(300),
    };
    const SLOW: Duration = Duration::from_millis(900);
    let blocks: Vec<MsgBlock> = (0..4).map(|i| block(i, 1)).collect();

    for wanted in [false, true] {
        let wanted_block = block_inv(&blocks[3]);
        let slow: Vec<Hash> = blocks[1..3].iter().map(|b| b.header.block_hash()).collect();
        let handled = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&handled);
        let (addr, reason_rx) = serve(NEVER, STALL, move |_killer| Scenario {
            wanted,
            violations: Arc::new(AtomicUsize::new(0)),
            handle: move |msg: &Message, outbound: &OutboundQueue| {
                match msg {
                    // The request whose deadline is under test.
                    Message::Ping(_) => {
                        let request = Message::GetData(MsgGetData {
                            inv_list: vec![wanted_block],
                        });
                        outbound.queue_message(request).expect("queue getdata");
                    }
                    Message::Block(block) => {
                        let hash = block.header.block_hash();
                        seen.lock().expect("seen").push(hash);
                        if slow.contains(&hash) {
                            thread::sleep(SLOW);
                        }
                    }
                    _ => {}
                }
                ServeSignal::Continue
            },
        });

        let mut transport = dial(addr);
        // The first block is handled at once; behind it the connection
        // is read ahead, if that is wanted.
        send_blocks(&mut transport, &blocks[..1]);
        transport
            .write_message(&Message::Ping(MsgPing { nonce: 1 }))
            .expect("send ping");
        read_until(&mut transport, "getdata");
        // Two blocks that are slow to handle, then the requested one.
        send_blocks(&mut transport, &blocks[1..]);

        let reason = reason_rx
            .recv_timeout(SLOW * 4)
            .unwrap_or_else(|_| panic!("read ahead {wanted}: the deadline was settled early"));
        assert!(
            matches!(&reason, DisconnectReason::Protocol(r) if r.contains("stalled")),
            "read ahead {wanted}: {reason:?}"
        );
        // The requested block was never handled.
        assert!(
            !handled
                .lock()
                .expect("handled")
                .contains(&blocks[3].header.block_hash()),
            "read ahead {wanted}"
        );
        drop(transport);
    }
}

/// A handler that takes longer than the response timeout does not get an
/// honest peer dropped while blocks it has delivered wait in the queue
/// behind it: the handler-active window covers a block that was read
/// ahead exactly as it covers one still in the socket.
#[test]
fn a_slow_handler_with_blocks_queued_does_not_stall_an_honest_peer() {
    // A response timeout with room for a loaded machine to deliver the
    // blocks inside it, and a handler three times as long.
    const STALL: StallConfig = StallConfig {
        tick: Duration::from_millis(50),
        response_timeout: Duration::from_millis(400),
    };
    const SLOW: Duration = Duration::from_millis(1200);
    let blocks: Vec<MsgBlock> = (0..5).map(|i| block(i, 1)).collect();

    for wanted in [false, true] {
        let requested: Vec<InvVect> = blocks[1..].iter().map(block_inv).collect();
        let slow = blocks[1].header.block_hash();
        let handled = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&handled);
        let (addr, reason_rx) = serve(NEVER, STALL, move |_killer| Scenario {
            wanted,
            violations: Arc::new(AtomicUsize::new(0)),
            handle: move |msg: &Message, outbound: &OutboundQueue| {
                match msg {
                    Message::Ping(ping) if ping.nonce == 1 => {
                        let request = Message::GetData(MsgGetData {
                            inv_list: requested.clone(),
                        });
                        outbound.queue_message(request).expect("queue getdata");
                    }
                    Message::Block(block) => {
                        // The stand-in for a long connect.
                        if block.header.block_hash() == slow {
                            thread::sleep(SLOW);
                        }
                        seen.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                ServeSignal::Continue
            },
        });

        let mut transport = dial(addr);
        send_blocks(&mut transport, &blocks[..1]);
        transport
            .write_message(&Message::Ping(MsgPing { nonce: 1 }))
            .expect("send ping");
        read_until(&mut transport, "getdata");
        // Every requested block at once: the first is slow to handle and
        // the rest wait behind it, read or not.
        send_blocks(&mut transport, &blocks[1..]);

        thread::sleep(SLOW + Duration::from_millis(400));
        assert!(
            reason_rx.try_recv().is_err(),
            "read ahead {wanted}: a slow local handler must not disconnect an honest peer"
        );
        assert_still_serving(&mut transport, 2);
        assert_eq!(handled.load(Ordering::SeqCst), blocks.len());

        drop(transport);
        let reason = reason_rx
            .recv_timeout(PATIENCE)
            .expect("closing the connection must end the loop");
        assert!(
            !format!("{reason:?}").contains("stalled"),
            "read ahead {wanted}: {reason:?}"
        );
    }
}

/// A served connection of the frame-order scenarios, and what its
/// server recorded.
struct BlockServer {
    addr: SocketAddr,
    reason: mpsc::Receiver<DisconnectReason>,
    /// The nonces of the blocks handled, in order.
    handled: Arc<Mutex<Vec<u32>>>,
    /// How many wire violations the server was told of.
    violations: Arc<AtomicUsize>,
}

/// The server for the frame-order scenarios: every block is recorded,
/// the one with `slow` in its header's nonce takes a while, and the one
/// named by `last` is answered as it says.
fn serve_blocks(slow: u32, last: Option<(u32, AtLast)>) -> BlockServer {
    let handled = Arc::new(Mutex::new(Vec::new()));
    let violations = Arc::new(AtomicUsize::new(0));
    let (seen, counted) = (Arc::clone(&handled), Arc::clone(&violations));
    let (addr, reason) = serve(NEVER, NO_STALL, move |killer| Scenario {
        wanted: true,
        violations: counted,
        handle: move |msg: &Message, _outbound: &OutboundQueue| {
            let Message::Block(block) = msg else {
                return ServeSignal::Continue;
            };
            let nonce = block.header.nonce;
            seen.lock().expect("seen").push(nonce);
            if nonce == slow {
                thread::sleep(Duration::from_millis(300));
            }
            match last {
                Some((at, AtLast::Disconnect)) if at == nonce => {
                    ServeSignal::Disconnect("unwanted block".into())
                }
                Some((at, AtLast::TearDown)) if at == nonce => {
                    killer.disconnect();
                    ServeSignal::Continue
                }
                _ => ServeSignal::Continue,
            }
        },
    });
    BlockServer {
        addr,
        reason,
        handled,
        violations,
    }
}

/// What the server of [`serve_blocks`] does with its last block.
#[derive(Clone, Copy)]
enum AtLast {
    /// The handler answers with a disconnect.
    Disconnect,
    /// The handler tears the connection down and keeps serving, as a
    /// sync-manager disconnect action does.
    TearDown,
}

/// A malformed frame behind good blocks is acted on only after every
/// block before it has been handled, although it was read, and found
/// malformed, while they were still queued.
#[test]
fn a_bad_frame_behind_good_blocks_bans_after_them() {
    let server = serve_blocks(1, None);
    let mut transport = dial(server.addr);
    let mut stream: Vec<u8> = (0..4u32)
        .flat_map(|i| framed(&Message::Block(block(i, 1))))
        .collect();
    stream.extend(ending_frame(Ending::BadChecksum));
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");
    sender.write_all(&stream).expect("send the stream");

    let reason = server
        .reason
        .recv_timeout(PATIENCE)
        .expect("the violation ends the connection");
    assert!(
        matches!(&reason, DisconnectReason::Protocol(r) if r == "banned"),
        "{reason:?}"
    );
    assert_eq!(*server.handled.lock().expect("handled"), vec![0, 1, 2, 3]);
    assert_eq!(server.violations.load(Ordering::SeqCst), 1);
    while transport.read_message().is_ok() {}
}

/// A malformed frame behind a block that gets the peer disconnected is
/// never acted on: no ban is recorded for it, as none would be for a
/// frame still unread in the socket.  The same holds when the block's
/// handler tears the connection down and returns normally.
#[test]
fn a_bad_frame_behind_a_disconnecting_block_is_ignored() {
    for at_last in [AtLast::Disconnect, AtLast::TearDown] {
        // The last block is also the slow one, so the malformed frame
        // behind it is read and queued before its handler returns.
        let server = serve_blocks(2, Some((2, at_last)));
        let mut transport = dial(server.addr);
        let mut stream: Vec<u8> = (0..3u32)
            .flat_map(|i| framed(&Message::Block(block(i, 1))))
            .collect();
        stream.extend(ending_frame(Ending::BadChecksum));
        stream.extend(framed(&Message::Block(block(7, 1))));
        let mut sender = transport.get_ref().try_clone().expect("clone the socket");
        sender.write_all(&stream).expect("send the stream");

        let reason = server
            .reason
            .recv_timeout(PATIENCE)
            .expect("the block ends the connection");
        match at_last {
            AtLast::Disconnect => assert!(
                matches!(&reason, DisconnectReason::Protocol(r) if r == "unwanted block"),
                "{reason:?}"
            ),
            AtLast::TearDown => assert!(
                matches!(&reason, DisconnectReason::ReadError(r) if r.contains("torn down locally")),
                "{reason:?}"
            ),
        }
        assert_eq!(*server.handled.lock().expect("handled"), vec![0, 1, 2]);
        assert_eq!(
            server.violations.load(Ordering::SeqCst),
            0,
            "a frame behind the disconnect was acted on"
        );
        while transport.read_message().is_ok() {}
    }
}

/// A peer that goes silent is dropped one idle budget after the handler
/// went idle, not one budget after the reader began the read it never
/// finishes, which was while the handler was still busy for longer than
/// a budget.  The budget is longer than the interval at which a waiting
/// handler looks at the connection's flag again, so the instant its wait
/// began has to hold through that.
#[test]
fn a_silent_peer_is_dropped_one_budget_after_the_handler_went_idle() {
    const BUDGET: Duration = Duration::from_millis(1500);
    const BUSY: Duration = Duration::from_millis(2000);
    const _: () = assert!(BUDGET.as_millis() > READ_POLL_INTERVAL.as_millis());
    for wanted in [false, true] {
        let idle_from = Arc::new(Mutex::new(None::<Instant>));
        let went_idle = Arc::clone(&idle_from);
        let (addr, reason_rx) = serve(BUDGET, NO_STALL, move |_killer| Scenario {
            wanted,
            violations: Arc::new(AtomicUsize::new(0)),
            handle: move |msg: &Message, _outbound: &OutboundQueue| {
                if matches!(msg, Message::Block(block) if block.header.nonce == 1) {
                    thread::sleep(BUSY);
                    *went_idle.lock().expect("idle") = Some(Instant::now());
                }
                ServeSignal::Continue
            },
        });

        let mut transport = dial(addr);
        send_blocks(&mut transport, &[block(0, 1), block(1, 1)]);
        // And then nothing, with the connection held open.
        let reason = reason_rx
            .recv_timeout(PATIENCE)
            .expect("the idle budget ends the connection");
        let ended = Instant::now();
        assert!(
            matches!(&reason, DisconnectReason::ReadError(r) if r == "read timed out"),
            "read ahead {wanted}: {reason:?}"
        );
        let idle_from = idle_from.lock().expect("idle").expect("the handler ran");
        let idle = ended.saturating_duration_since(idle_from);
        assert!(
            idle >= BUDGET,
            "read ahead {wanted}: dropped {idle:?} after the handler went idle, inside the \
             {BUDGET:?} budget"
        );
        assert!(
            idle < BUDGET + READ_POLL_INTERVAL * 2,
            "read ahead {wanted}: dropped {idle:?} after the handler went idle"
        );
        drop(transport);
    }
}

/// How one run of the late-block scenario ended.
enum LateBlock {
    /// The block was handled and the ping behind it answered.
    Kept,
    /// The connection ended before the block was handled: its last byte
    /// missed the budget, which says nothing about the frame behind it.
    BlockMissedBudget,
    /// The block was handled and the connection ended all the same.
    Dropped(DisconnectReason),
}

/// One connection of the late-block scenario: a first block, then a
/// large block whose last byte is sent `lead` before the idle budget of
/// the wait for it ends, then a ping a third of a budget later.
fn late_block_run(wanted: bool, budget: Duration, frame: &[u8], lead: Duration) -> LateBlock {
    let idle_from = Arc::new(Mutex::new(None::<Instant>));
    let went_idle = Arc::clone(&idle_from);
    let handled = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&handled);
    let (addr, reason_rx) = serve(budget, NO_STALL, move |_killer| Scenario {
        wanted,
        violations: Arc::new(AtomicUsize::new(0)),
        handle: move |msg: &Message, _outbound: &OutboundQueue| {
            if let Message::Block(block) = msg {
                if block.header.nonce == 0 {
                    *went_idle.lock().expect("idle") = Some(Instant::now());
                } else {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            }
            ServeSignal::Continue
        },
    });

    let mut transport = dial(addr);
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");
    // The first block, behind which the connection is read ahead if that
    // is wanted, and with it all of the large block but its last byte.
    let (last, rest) = frame.split_last().expect("a frame");
    let mut early = framed(&Message::Block(block(0, 1)));
    early.extend_from_slice(rest);
    sender.write_all(&early).expect("send the blocks");
    let deadline = Instant::now() + PATIENCE;
    let idle_from = loop {
        if let Some(at) = *idle_from.lock().expect("idle") {
            break at;
        }
        assert!(Instant::now() < deadline, "the first block was not handled");
        thread::sleep(Duration::from_millis(1));
    };

    // The last byte, just inside the budget of the wait for the block.
    let send_at = idle_from + budget - lead;
    thread::sleep(send_at.saturating_duration_since(Instant::now()));
    sender.write_all(&[*last]).expect("send the last byte");
    // The frame behind it: past the end of that budget, and well inside
    // one that starts when the block has been handled.
    thread::sleep(budget / 3);
    // A connection that has been dropped may refuse it.
    let _ = transport.write_message(&Message::Ping(MsgPing { nonce: 7 }));
    let answered = loop {
        match transport.read_message() {
            Ok(Message::Pong(pong)) => break pong.nonce == 7,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    if answered {
        drop(sender);
        drop(transport);
        let _ = reason_rx
            .recv_timeout(PATIENCE)
            .expect("closing the connection ends it");
        return LateBlock::Kept;
    }
    let reason = reason_rx
        .recv_timeout(PATIENCE)
        .expect("a connection that stopped answering has ended");
    if handled.load(Ordering::SeqCst) == 0 {
        LateBlock::BlockMissedBudget
    } else {
        LateBlock::Dropped(reason)
    }
}

/// The frame behind a block has an idle budget of its own, whether or
/// not the connection is read ahead: dcrd arms a fresh deadline for
/// every read (`readMessage`, `peer/peer.go:963-964`).
///
/// The block here is close to the largest a block may be.  Its last byte
/// arrives just inside the budget of the wait for it, and checking,
/// decoding and hashing it runs past the end of that budget.  A ping
/// follows well inside the next budget and must be answered.  With
/// reading ahead, the reader thread goes on to the frame behind the block
/// while the block is still queued for a handler that has by then been
/// waiting for more than a whole budget, and that wait is not the new
/// frame's.
///
/// How long before the end of the budget the last byte is sent is taken
/// from how long this build spends on the block, so that the work spans
/// the end of the budget where it is slow enough to (an unoptimized
/// build), and the byte still arrives in time where it is not.  A run in
/// which the byte misses the budget all the same is repeated.
#[test]
fn the_frame_behind_a_block_that_arrived_late_in_its_budget_has_its_own_budget() {
    const BUDGET: Duration = Duration::from_millis(1500);
    let frame = framed(&Message::Block(block(1, 6_000)));
    let work = (0..3)
        .map(|_| {
            let began = Instant::now();
            let (msg, _) = dcroxide_wire::read_message(&frame, MAX_PROTOCOL_VERSION, NET)
                .expect("the block decodes");
            let Message::Block(decoded) = msg else {
                unreachable!("a block was framed");
            };
            let _ = HashedBlock::new(Arc::new(decoded));
            began.elapsed()
        })
        .min()
        .expect("three runs");
    let lead = (work / 2).clamp(Duration::from_millis(25), BUDGET / 3);

    for wanted in [false, true] {
        let mut kept = false;
        for _ in 0..4 {
            match late_block_run(wanted, BUDGET, &frame, lead) {
                LateBlock::Kept => {
                    kept = true;
                    break;
                }
                LateBlock::BlockMissedBudget => {}
                LateBlock::Dropped(reason) => panic!(
                    "read ahead {wanted}: the block arrived inside its budget and the frame \
                     behind it was not given one of its own: {reason:?}"
                ),
            }
        }
        assert!(
            kept,
            "read ahead {wanted}: the block's last byte, sent {lead:?} before the end of its \
             budget, never arrived inside it"
        );
    }
}

/// A ping behind queued blocks is answered when the handler reaches it,
/// in stream order, not when the reader reads it.
#[test]
fn pings_are_answered_in_stream_order_while_blocks_are_queued() {
    const SLOW: Duration = Duration::from_millis(400);
    let done = Arc::new(Mutex::new(None::<Instant>));
    let slow_done = Arc::clone(&done);
    let (addr, reason_rx) = serve(NEVER, NO_STALL, move |_killer| Scenario {
        wanted: true,
        violations: Arc::new(AtomicUsize::new(0)),
        handle: move |msg: &Message, _outbound: &OutboundQueue| {
            if matches!(msg, Message::Block(block) if block.header.nonce == 1) {
                thread::sleep(SLOW);
                *slow_done.lock().expect("done") = Some(Instant::now());
            }
            ServeSignal::Continue
        },
    });

    let mut transport = dial(addr);
    // A block to start reading ahead behind, a slow block, and behind it
    // a ping, a block, and another ping.
    let stream: Vec<u8> = [
        Message::Block(block(0, 1)),
        Message::Block(block(1, 1)),
        Message::Ping(MsgPing { nonce: 11 }),
        Message::Block(block(2, 1)),
        Message::Ping(MsgPing { nonce: 12 }),
    ]
    .iter()
    .flat_map(framed)
    .collect();
    let mut sender = transport.get_ref().try_clone().expect("clone the socket");
    sender.write_all(&stream).expect("send the stream");

    let first = read_until(&mut transport, "pong");
    let first_at = Instant::now();
    let second = read_until(&mut transport, "pong");
    assert_eq!(first, Message::Pong(MsgPong { nonce: 11 }));
    assert_eq!(second, Message::Pong(MsgPong { nonce: 12 }));
    let slow_done = done
        .lock()
        .expect("done")
        .expect("the slow block was handled");
    assert!(
        first_at >= slow_done,
        "the ping behind the slow block was answered before the block was handled"
    );

    drop(sender);
    drop(transport);
    let _ = reason_rx
        .recv_timeout(PATIENCE)
        .expect("the connection ends");
}

/// A shutdown that arrives while blocks are queued ends the connection
/// once the handler has finished the block it is on: nothing queued is
/// handled, and the reader thread is gone when the connection returns.
#[test]
fn shutdown_with_blocks_queued_ends_the_connection_without_handling_them() {
    // The read-ahead's bound (`READ_AHEAD_MAX_ITEMS`, private to the
    // crate), so that the blocks behind the held one fill the queue and
    // the reader waits for room when the shutdown comes.
    const DEPTH: u32 = 16;
    let handled = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&handled);
    let (entered_tx, entered) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let (killer_tx, killer_rx) = mpsc::channel();
    let (addr, reason_rx) = serve(NEVER, NO_STALL, move |killer| {
        killer_tx.send(killer).expect("hand the test a handle");
        Scenario {
            wanted: true,
            violations: Arc::new(AtomicUsize::new(0)),
            handle: move |msg: &Message, _outbound: &OutboundQueue| {
                if let Message::Block(block) = msg {
                    seen.lock().expect("seen").push(block.header.nonce);
                    if block.header.nonce == 1 {
                        let _ = entered_tx.send(());
                        let _ = released.recv_timeout(PATIENCE);
                    }
                }
                ServeSignal::Continue
            },
        }
    });

    let mut transport = dial(addr);
    let blocks: Vec<MsgBlock> = (0..DEPTH + 2).map(|i| block(i, 1)).collect();
    send_blocks(&mut transport, &blocks);
    entered
        .recv_timeout(PATIENCE)
        .expect("the handler reaches the second block");
    // The blocks behind it are read ahead while it is held, until the
    // queue is full.
    thread::sleep(Duration::from_millis(200));

    // The node shuts down: every connection is torn down from another
    // thread, and the handler then finishes the block it is on.
    let killer = killer_rx.recv_timeout(PATIENCE).expect("a handle");
    killer.disconnect_for_shutdown();
    let torn_down = Instant::now();
    release.send(()).expect("release the handler");

    let reason = reason_rx
        .recv_timeout(READ_POLL_INTERVAL * 3)
        .expect("the connection ends, its reader thread joined");
    assert!(torn_down.elapsed() < READ_POLL_INTERVAL * 3);
    assert!(
        matches!(&reason, DisconnectReason::ReadError(r) if r.contains("torn down locally")),
        "{reason:?}"
    );
    assert_eq!(*handled.lock().expect("handled"), vec![0, 1]);
    while transport.read_message().is_ok() {}
}
