// SPDX-License-Identifier: ISC
//! The three error lines dcrd logs for an outbound peer whose address
//! the address manager does not hold, and their absence everywhere
//! else.
//!
//! dcrd updates the address manager at three points of an outbound
//! connection and logs each failure at error level under SRVR:
//!
//! - at the dial, `Marking address as attempted failed: %v`
//!   (`attemptDcrdDial`, `server.go:1930-1937`);
//! - when the peer's version message arrives, ahead of every rejection,
//!   `Setting services for address failed: %v` (`OnVersion`,
//!   `server.go:986-990`);
//! - once the handshake has completed, ahead of `New valid peer`,
//!   `Marking address as good failed: %v` (`handleAddPeer`,
//!   `server.go:2661-2665`).
//!
//! `AddAddresses` drops an address that is not routable without a word
//! (`addrmgr/addrmanager.go:300-304`), so for a peer on a loopback or
//! private address all three fail with `address <ip:port> not found`.
//! That is the usual `--connect` or `--addpeer` target on the same host
//! or LAN, and the three lines are what both daemons print for it at
//! every connection.  The port made the second call and discarded its
//! error.
//!
//! None of the three is logged for a peer whose address the manager
//! holds; for an inbound peer, which is not dialed and for which both
//! handlers leave the manager alone (`server.go:986`, `:2639`); or on
//! simnet and regnet, where dcrd makes none of the three updates
//! (`server.go:1917`, `:986`, `:2639`).
//!
//! Every daemon here runs with `--noseeders` and either `--connect` or
//! no address to dial, and every connection it makes or takes is with
//! the test itself over the loopback interface, so nothing leaves the
//! host.  The peer with a routable address is dialed through `--proxy`,
//! and the proxy is the test.

// The lines pinned here are the same on every platform, so the daemon
// is started on one, the one `review_dial_logs.rs` starts it on.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, Peer, PeerGlobals};
use dcroxide_wire::{CurrencyNet, REMOVE_REJECT_VERSION, ServiceFlag};

/// How long the daemon has to start, connect and settle the peer.
const DEADLINE: Duration = Duration::from_secs(90);

/// The line the server logs once a peer is admitted (dcrd `AddPeer`,
/// `server.go:2700`), which comes after everything pinned here.
const NEW_VALID_PEER: &str = "[INF] SRVR: New valid peer ";

/// The line the connection manager logs for a listener, which ends with
/// the address it bound.
const SERVER_LISTENING: &str = "[INF] CMGR: Server listening on ";

/// Kills the daemon however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The stand-in peer's end of the connection, kept open once its part
/// in the handshake is over.
type Held = WireTransport<TcpStream>;

/// What the stand-in peer advertises: a full node, which is what an
/// outbound peer must be to be admitted (`server.go:1030-1036`), at the
/// protocol version given, where 0 is the newest.
fn peer_config(net: CurrencyNet, protocol_version: u32) -> Config {
    Config {
        net,
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: "standin".to_string(),
        user_agent_version: "1.0.0".to_string(),
        protocol_version,
        ..Config::default()
    }
}

/// Take the dialed side of the version handshake.  `completes` is
/// whether the daemon is expected to see it through.
fn answer_handshake(
    stream: TcpStream,
    net: CurrencyNet,
    protocol_version: u32,
    completes: bool,
) -> Held {
    stream
        .set_read_timeout(Some(DEADLINE))
        .expect("read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, net);
    let handshake = Peer::new_inbound(peer_config(net, protocol_version))
        .negotiate_inbound_protocol(
            &mut transport,
            &mut NodePeerEnv::new(),
            &PeerGlobals::new(),
            None,
        );
    match (handshake, completes) {
        (Ok(_), true) | (Err(_), false) => {}
        (Err(e), true) => panic!("the daemon gave up its handshake: {}", e.message),
        (Ok(_), false) => panic!("the daemon completed a handshake it rejects"),
    }
    transport
}

/// A peer listening on a loopback port of the system's choosing, which
/// answers the first connection's handshake.  Returns its address.
fn listening_peer(
    net: CurrencyNet,
    protocol_version: u32,
    completes: bool,
) -> (String, JoinHandle<Held>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let peer = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        answer_handshake(stream, net, protocol_version, completes)
    });
    (addr, peer)
}

/// A peer listening on a loopback port of the system's choosing, which
/// answers the first connection's handshake, hangs up on it when told
/// to, and answers the handshake of the next.  Returns its address and
/// the way to tell it.
fn redialed_peer(net: CurrencyNet) -> (String, mpsc::Sender<()>, JoinHandle<Held>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let (hang_up_tx, hang_up) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let first = answer_handshake(stream, net, 0, true);
        // Kept until the daemon has logged the admission, which dcrd
        // logs only for a peer that is still connected
        // (`server.go:2699-2700`).
        let _ = hang_up.recv();
        drop(first);
        let (stream, _) = listener.accept().expect("accept");
        answer_handshake(stream, net, 0, true)
    });
    (addr, hang_up_tx, peer)
}

/// A SOCKS5 proxy on a loopback port that, instead of connecting
/// anywhere, plays the peer its first connection asks for.  Returns its
/// address and, once a connection has asked, the `host:port` it asked
/// for.
fn proxied_peer(net: CurrencyNet) -> (String, mpsc::Receiver<String>, JoinHandle<Held>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let (asked_tx, asked) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(DEADLINE)).expect("read timeout");

        // The greeting, answered with "no authentication".
        let mut head = [0u8; 2];
        conn.read_exact(&mut head).expect("greeting");
        assert_eq!(head[0], 5, "the SOCKS version");
        let mut methods = vec![0u8; usize::from(head[1])];
        conn.read_exact(&mut methods).expect("methods");
        conn.write_all(&[5, 0]).expect("method choice");

        // The connect request, which carries the target as a name.
        let mut head = [0u8; 5];
        conn.read_exact(&mut head).expect("request");
        assert_eq!(&head[..4], &[5, 1, 0, 3], "a connect to a name");
        let mut host = vec![0u8; usize::from(head[4])];
        conn.read_exact(&mut host).expect("host");
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).expect("port");
        let _ = asked_tx.send(format!(
            "{}:{}",
            String::from_utf8_lossy(&host),
            u16::from_be_bytes(port)
        ));

        // Success, with a bound address the client has no use for.
        conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .expect("reply");
        answer_handshake(conn, net, 0, true)
    });
    (addr, asked, peer)
}

/// A peer that dials the daemon's listener and completes the handshake
/// it starts.
fn dialing_peer(addr: String, net: CurrencyNet) -> JoinHandle<Held> {
    std::thread::spawn(move || {
        let stream = TcpStream::connect(&addr).expect("the daemon is listening");
        stream
            .set_read_timeout(Some(DEADLINE))
            .expect("read timeout");
        let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, net);
        if let Err(e) = Peer::new_outbound(peer_config(net, 0), &addr)
            .expect("the daemon's address")
            .negotiate_outbound_protocol(
                &mut transport,
                &mut NodePeerEnv::new(),
                &PeerGlobals::new(),
                None,
            )
        {
            panic!("the daemon gave up the handshake: {}", e.message);
        }
        transport
    })
}

/// The stand-in peer's connection once its thread has ended.  A panic
/// in that thread, a failed handshake or a proxy request of the wrong
/// form, fails the test with the daemon's log.
fn joined(peer: JoinHandle<Held>, seen: &[String]) -> Held {
    peer.join()
        .unwrap_or_else(|_| panic!("the stand-in peer failed; the daemon logged {seen:#?}"))
}

/// How the stand-in peer comes to be connected.
enum StandIn {
    /// It is listening, as itself or as a proxy, for the daemon's dial.
    Dialed(JoinHandle<Held>),
    /// It is listening for the daemon's dial and, told to, hangs up on
    /// it and waits for the redial.
    Redialed(JoinHandle<Held>, mpsc::Sender<()>),
    /// It dials the listener the daemon logs, on this network.
    Dials(CurrencyNet),
}

/// Run a daemon with the arguments until it logs a line starting with
/// `until`, and return what it logged up to and including that line,
/// each line with its timestamp cut off, as `[LVL] TAG: message`.  A
/// peer that is to be redialed is told to hang up at the first such
/// line, and the run ends at the second.
fn log_until(args: &[String], stand_in: StandIn, until: &str) -> Vec<String> {
    let appdata = tempfile::tempdir().expect("tempdir");
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_dcroxide"))
            .args(["--norpc", "--noseeders"])
            .arg(format!("--appdata={}", appdata.path().display()))
            .args(args)
            .env_remove("DCRD_APPDATA")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn"),
    );

    let (lines_tx, lines) = mpsc::channel::<String>();
    let stdout = child.0.stdout.take().expect("stdout");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(at) = line.find(" [") {
                let _ = lines_tx.send(line[at + 1..].to_string());
            }
        }
    });

    let (mut peer, mut dials, mut hang_up) = match stand_in {
        StandIn::Dialed(peer) => (Some(peer), None, None),
        StandIn::Redialed(peer, hang_up) => (Some(peer), None, Some(hang_up)),
        StandIn::Dials(net) => (None, Some(net), None),
    };
    // The peer's end of the connection stays open until the daemon is
    // gone, and a peer that failed ends the wait at once.
    let mut held: Option<Held> = None;
    let mut seen: Vec<String> = Vec::new();
    let deadline = Instant::now() + DEADLINE;
    let mut reached = false;
    while !reached && Instant::now() < deadline {
        if peer.as_ref().is_some_and(JoinHandle::is_finished) {
            held = Some(joined(peer.take().expect("checked above"), &seen));
        }
        match lines.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if let Some(addr) = line.strip_prefix(SERVER_LISTENING)
                    && let Some(net) = dials.take()
                {
                    peer = Some(dialing_peer(addr.to_string(), net));
                }
                if line.starts_with(until) {
                    if let Some(hang_up) = hang_up.take() {
                        let _ = hang_up.send(());
                    } else {
                        reached = true;
                    }
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(child);
    assert!(reached, "the daemon never logged {until:?}: {seen:#?}");
    // The daemon logged the line over its connection to the peer and is
    // gone, so a peer still in its handshake comes out of it now.
    if let Some(peer) = peer {
        held = Some(joined(peer, &seen));
    }
    drop(held);
    seen
}

/// The lines logged at error level, by any subsystem.
fn error_lines(seen: &[String]) -> Vec<&str> {
    seen.iter()
        .map(String::as_str)
        .filter(|line| line.starts_with("[ERR] "))
        .collect()
}

/// The three lines for a peer at the address, in dcrd's order.
fn address_errors(target: &str) -> [String; 3] {
    [
        format!("[ERR] SRVR: Marking address as attempted failed: address {target} not found"),
        format!("[ERR] SRVR: Setting services for address failed: address {target} not found"),
        format!("[ERR] SRVR: Marking address as good failed: address {target} not found"),
    ]
}

#[test]
fn an_outbound_loopback_peer_logs_dcrds_three_address_errors() {
    let (target, peer) = listening_peer(CurrencyNet::TEST_NET3, 0, true);
    let seen = log_until(
        &[
            "--testnet".to_string(),
            "--nolisten".to_string(),
            format!("--connect={target}"),
        ],
        StandIn::Dialed(peer),
        NEW_VALID_PEER,
    );

    assert!(
        seen.last()
            .expect("the admission line")
            .starts_with(&format!("{NEW_VALID_PEER}{target} (outbound) (")),
        "the peer is the --connect target: {seen:#?}"
    );
    // One connection, so each line once, and nothing else at error
    // level: the dial, the version message, the admission.
    assert_eq!(
        error_lines(&seen),
        address_errors(&target),
        "dcrd's three lines, in its order: {seen:#?}"
    );
}

#[test]
fn a_redialed_peer_logs_the_three_address_errors_again() {
    // dcrd keeps no record of a failed update: the dial, the version
    // handler and the admission each make theirs at every connection,
    // and a persistent peer that hung up is redialed through the same
    // dial (`internal/connmgr/connmanager.go:1986`, `server.go:4296`).
    // A connection that lasted less than the retry interval is redialed
    // after a backoff of 2.5 to 5 seconds (`connmanager.go:1950-1962`,
    // `:1883-1903`), which is how long this test takes.
    let (target, hang_up, peer) = redialed_peer(CurrencyNet::TEST_NET3);
    let seen = log_until(
        &[
            "--testnet".to_string(),
            "--nolisten".to_string(),
            format!("--connect={target}"),
        ],
        StandIn::Redialed(peer, hang_up),
        NEW_VALID_PEER,
    );

    let once = address_errors(&target);
    assert_eq!(
        error_lines(&seen),
        [&once[..], &once[..]].concat(),
        "dcrd's three lines for each of the two connections: {seen:#?}"
    );
}

#[test]
fn the_services_error_is_logged_ahead_of_the_old_protocol_rejection() {
    // dcrd updates the services before it rejects a peer that is too
    // old, so that a peer not yet upgraded still has them recorded
    // (the NOTE at `server.go:981-983`), and so logs the failed update
    // for a peer it then turns away.
    let too_old = REMOVE_REJECT_VERSION - 1;
    let (target, peer) = listening_peer(CurrencyNet::TEST_NET3, too_old, false);
    let rejected = format!(
        "[DBG] SRVR: Failed handshake for outbound peer {target}: rejecting protocol version \
         {too_old} prior to the required version {REMOVE_REJECT_VERSION}"
    );
    let seen = log_until(
        &[
            "--testnet".to_string(),
            "--nolisten".to_string(),
            "--debuglevel=SRVR=debug".to_string(),
            format!("--connect={target}"),
        ],
        StandIn::Dialed(peer),
        &rejected,
    );

    // The peer was never admitted, so the third line has no occasion.
    assert_eq!(
        error_lines(&seen),
        address_errors(&target)[..2],
        "the dial's line and the version message's: {seen:#?}"
    );
}

#[test]
fn an_outbound_peer_with_a_routable_address_logs_no_address_error() {
    // An address the manager holds once the dial has added it.  It is
    // asked of the proxy and never dialed.
    let target = "8.8.8.8:19108";
    let (proxy, asked, peer) = proxied_peer(CurrencyNet::TEST_NET3);
    let seen = log_until(
        &[
            "--testnet".to_string(),
            "--nolisten".to_string(),
            // Lookups go to the system resolver, which answers an
            // address literal without a query, and not to the proxy as
            // Tor requests, which the stand-in does not speak.
            "--noonion".to_string(),
            format!("--proxy={proxy}"),
            format!("--connect={target}"),
        ],
        StandIn::Dialed(peer),
        NEW_VALID_PEER,
    );

    assert_eq!(asked.try_recv().as_deref(), Ok(target));
    assert!(
        seen.last()
            .expect("the admission line")
            .starts_with(&format!("{NEW_VALID_PEER}{target} (outbound) (")),
        "the peer is the --connect target: {seen:#?}"
    );
    assert_eq!(error_lines(&seen), Vec::<&str>::new(), "{seen:#?}");
}

#[test]
fn an_inbound_loopback_peer_logs_no_address_error() {
    let seen = log_until(
        &["--testnet".to_string(), "--listen=127.0.0.1:0".to_string()],
        StandIn::Dials(CurrencyNet::TEST_NET3),
        NEW_VALID_PEER,
    );

    let admission = seen.last().expect("the admission line");
    assert!(
        admission.starts_with(&format!("{NEW_VALID_PEER}127.0.0.1:"))
            && admission.contains(" (inbound) ("),
        "the peer is inbound: {seen:#?}"
    );
    assert_eq!(error_lines(&seen), Vec::<&str>::new(), "{seen:#?}");
}

#[test]
fn an_outbound_loopback_peer_on_simnet_or_regnet_logs_no_address_error() {
    for (network, net) in [
        ("--simnet", CurrencyNet::SIM_NET),
        ("--regnet", CurrencyNet::REG_NET),
    ] {
        let (target, peer) = listening_peer(net, 0, true);
        let seen = log_until(
            &[
                network.to_string(),
                "--nolisten".to_string(),
                format!("--connect={target}"),
            ],
            StandIn::Dialed(peer),
            NEW_VALID_PEER,
        );

        assert!(
            seen.last()
                .expect("the admission line")
                .starts_with(&format!("{NEW_VALID_PEER}{target} (outbound) (")),
            "the peer is the --connect target on {network}: {seen:#?}"
        );
        assert_eq!(
            error_lines(&seen),
            Vec::<&str>::new(),
            "{network}: {seen:#?}"
        );
    }
}
