// SPDX-License-Identifier: ISC
//! The peer state and protocol decisions (dcrd peer `peer.go`).

use dcroxide_chainhash::Hash;
use dcroxide_containers::lru;
use dcroxide_wire::{
    CurrencyNet, InvVect, Message, MsgAddr, MsgGetBlocks, MsgGetHeaders, MsgPing, MsgPong,
    MsgVersion, NetAddress, NetAddressV2, ServiceFlag,
};

use crate::{MAX_KNOWN_INVENTORY, MAX_KNOWN_INVENTORY_TTL, MAX_PROTOCOL_VERSION, MsgTransport};

/// The default user agent of dcrd's wire module, which local version
/// messages start from (Go `wire.DefaultUserAgent`).
const DEFAULT_USER_AGENT: &str = "/dcrwire:1.0.0/";

/// The maximum user agent length (Go `wire.MaxUserAgentLen`).
const MAX_USER_AGENT_LEN: usize = 256;

/// The maximum addresses in an addr message (Go `wire.MaxAddrPerMsg`).
const MAX_ADDR_PER_MSG: usize = 1000;

/// The environment the peer draws on: the wall clock and randomness
/// dcrd reads from `time.Now` and `crypto/rand`.
pub trait PeerEnv {
    /// The current time in unix nanoseconds.
    fn now_nanos(&mut self) -> i64;
    /// A fresh nonce for the local version message.
    fn rand_u64(&mut self) -> u64;
    /// Shuffle addresses for an over-full addr message (dcrd
    /// `rand.ShuffleSlice`).
    fn shuffle_addrs(&mut self, addrs: &mut [NetAddress]);
    /// Shuffle v2 addresses for an over-full addrv2 message (dcrd
    /// `rand.ShuffleSlice`).
    fn shuffle_addrs_v2(&mut self, addrs: &mut [NetAddressV2]);
}

/// State dcrd keeps in package globals, owned by the daemon and
/// shared across peers: the peer id counter and the nonces of sent
/// version messages used to detect self connections.
pub struct PeerGlobals {
    node_count: i32,
    sent_nonces: lru::Set<u64>,
    /// Bypass for the self-connection check (dcrd's test-only
    /// `allowSelfConns`).
    pub allow_self_conns: bool,
}

impl PeerGlobals {
    /// Fresh globals (dcrd package init).
    pub fn new() -> PeerGlobals {
        PeerGlobals {
            node_count: 0,
            sent_nonces: lru::Set::new(crate::SENT_NONCES_LIMIT),
            allow_self_conns: false,
        }
    }

    fn next_id(&mut self) -> i32 {
        self.node_count = self.node_count.wrapping_add(1);
        self.node_count
    }

    /// Insert a nonce into the sent-nonce cache directly.
    #[doc(hidden)]
    pub fn put_sent_nonce(&mut self, nonce: u64) {
        self.sent_nonces.put(nonce);
    }
}

impl Default for PeerGlobals {
    fn default() -> Self {
        PeerGlobals::new()
    }
}

// The callbacks are `Send` so a peer holding them can move between the
// daemon's per-peer threads (the peer itself is guarded by a mutex, so
// `Sync` is not required).
type HostToNetAddressFn =
    Box<dyn FnMut(&str, u16, ServiceFlag) -> Result<NetAddressV2, String> + Send>;
type NewestBlockFn = Box<dyn FnMut() -> Result<(Hash, i64), String> + Send>;

/// The peer configuration (dcrd `Config`).  The message listener
/// callbacks are daemon-phase; the equivalents here are the values
/// returned by the negotiation and handler methods.
pub struct Config {
    /// Returns the newest block details (dcrd `NewestBlock`).
    pub newest_block: Option<NewestBlockFn>,
    /// Converts a host to a network address (dcrd
    /// `HostToNetAddress`).
    pub host_to_net_address: Option<HostToNetAddressFn>,
    /// The proxy address in host:port form, used to hide the remote
    /// address in the local version message when the connection comes
    /// through the proxy (dcrd `Proxy`).
    pub proxy: String,
    /// The user agent name to advertise.
    pub user_agent_name: String,
    /// The user agent version to advertise.
    pub user_agent_version: String,
    /// The user agent comments to advertise.
    pub user_agent_comments: Vec<String>,
    /// The network (defaults to testnet, exactly like dcrd).
    pub net: CurrencyNet,
    /// The services to advertise.
    pub services: ServiceFlag,
    /// The maximum protocol version to use (0 means the package
    /// maximum).
    pub protocol_version: u32,
    /// Whether to advertise that transactions should not be relayed.
    pub disable_relay_tx: bool,
    /// The idle timeout in nanoseconds (0 means the default);
    /// enforced by the daemon's read loop.
    pub idle_timeout_nanos: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            newest_block: None,
            host_to_net_address: None,
            proxy: String::new(),
            user_agent_name: String::new(),
            user_agent_version: String::new(),
            user_agent_comments: Vec::new(),
            net: CurrencyNet(0),
            services: ServiceFlag(0),
            protocol_version: 0,
            disable_relay_tx: false,
            idle_timeout_nanos: 0,
        }
    }
}

/// A snapshot of the current peer flags and statistics (dcrd
/// `StatsSnap`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatsSnap {
    /// The peer id.
    pub id: i32,
    /// The peer address.
    pub addr: String,
    /// The advertised services.
    pub services: ServiceFlag,
    /// The unix nanosecond times of the last send and receive.
    pub last_send_nanos: i64,
    /// The unix nanosecond time of the last receive.
    pub last_recv_nanos: i64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_recv: u64,
    /// When the connection was made, unix nanoseconds.
    pub connected_nanos: i64,
    /// The negotiated time offset in seconds.
    pub time_offset: i64,
    /// The remote user agent.
    pub version: String,
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// The height of the remote's newest block at connect time.
    pub starting_height: i64,
    /// The last block the remote announced.
    pub last_block: i64,
    /// The nonce of the last outstanding ping.
    pub last_ping_nonce: u64,
    /// The last measured round trip in microseconds.
    pub last_ping_micros: i64,
    /// The unix nanosecond time of the last ping.
    pub last_ping_time_nanos: i64,
    /// The negotiated protocol version.
    pub protocol_version: u32,
}

/// An error from version negotiation (dcrd returns these from the
/// negotiate functions).  When the remote's version message was read
/// before the failure, it is carried here so the daemon can fire its
/// version listener first, matching dcrd's callback ordering.
#[derive(Debug)]
pub struct NegotiateError {
    /// The error text, matching dcrd's.
    pub message: String,
    /// The typed kind for errors dcrd 2.2's `peer/error.go` names;
    /// `None` for transport-level failures dcrd surfaces untyped.
    pub kind: Option<NegotiateErrorKind>,
    /// The remote version message, when one was read.
    pub remote_version: Option<Box<MsgVersion>>,
}

/// The typed handshake error kinds (dcrd 2.2 `peer/error.go`); each
/// [`kind_name`](NegotiateErrorKind::kind_name) matches dcrd's
/// `ErrorKind` string exactly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NegotiateErrorKind {
    /// The first message was not a version message.
    NotVersionMessage,
    /// The connection is to ourselves.
    SelfConnection,
    /// The peer's protocol version is too old.
    ProtocolVerTooOld,
    /// The message following the version message was not a verack.
    NotVerAckMessage,
    /// The handshake did not complete in time.  The daemon's
    /// negotiate read budget currently surfaces this as a transport
    /// read error; the kind is reserved for dcrd's typed
    /// `errHandshakeTimeout` mapping.
    HandshakeTimeout,
}

impl NegotiateErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            NegotiateErrorKind::NotVersionMessage => "ErrNotVersionMessage",
            NegotiateErrorKind::SelfConnection => "ErrSelfConnection",
            NegotiateErrorKind::ProtocolVerTooOld => "ErrProtocolVerTooOld",
            NegotiateErrorKind::NotVerAckMessage => "ErrNotVerAckMessage",
            NegotiateErrorKind::HandshakeTimeout => "ErrHandshakeTimeout",
        }
    }
}

impl NegotiateError {
    fn new(message: &str) -> NegotiateError {
        NegotiateError {
            message: message.to_string(),
            kind: None,
            remote_version: None,
        }
    }

    /// A typed error (dcrd `makeError`).
    fn typed(kind: NegotiateErrorKind, message: &str) -> NegotiateError {
        NegotiateError {
            message: message.to_string(),
            kind: Some(kind),
            remote_version: None,
        }
    }
}

/// The version callback the handshake fires (dcrd
/// `OnVersionCallback`); an error aborts the handshake.  The peer is
/// passed alongside the message so the daemon can read the state the
/// version read just negotiated, matching dcrd's `sp` receiver.
pub type OnVersionFn<'p> = dyn FnMut(&Peer, &MsgVersion) -> Result<(), String> + 'p;

/// A completed handshake (dcrd's post-`Handshake` state): the remote
/// version and any messages a legacy peer sent before its verack,
/// which the input handler must replay first.
pub struct HandshakeOutcome {
    /// The remote peer's version message.
    pub remote_version: Box<MsgVersion>,
    /// Messages read while waiting for a legacy verack.
    pub delayed: Vec<Message>,
}

/// The synchronous peer core (dcrd `Peer` minus its handler
/// goroutines and connection plumbing).
pub struct Peer {
    cfg: Config,
    inbound: bool,
    addr: String,
    na: NetAddressV2,

    id: i32,
    services: ServiceFlag,
    user_agent: String,
    version_known: bool,
    advertised_proto_ver: u32,
    protocol_version: u32,
    send_headers_preferred: bool,
    verack_received: bool,
    handshake_done: bool,

    known_inventory: lru::Set<InvVect>,
    prev_get_blocks: Option<(Hash, Hash)>,
    prev_get_hdrs: Option<(Hash, Hash)>,

    time_offset: i64,
    time_connected_nanos: i64,
    starting_height: i64,
    last_block: i64,
    last_announced_block: Option<Hash>,
    last_ping_nonce: u64,
    last_ping_time_nanos: i64,
    last_ping_micros: i64,

    bytes_received: u64,
    bytes_sent: u64,
    last_send_nanos: i64,
    last_recv_nanos: i64,
}

fn min_u32(a: u32, b: u32) -> u32 {
    if a < b { a } else { b }
}

/// Render a wire IP the way Go's `net.IP.String` does for the forms
/// the proxy check compares: dotted for IPv4-mapped, RFC 5952 IPv6
/// otherwise.
fn ip_string(ip: &[u8; 16]) -> String {
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        return format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    }
    std::net::Ipv6Addr::from(*ip).to_string()
}

impl Peer {
    fn new_base(mut cfg: Config, inbound: bool) -> Peer {
        // Default to the max supported protocol version.  Override to
        // the version specified by the caller if configured.
        let mut protocol_version = MAX_PROTOCOL_VERSION;
        if cfg.protocol_version != 0 {
            protocol_version = cfg.protocol_version;
        }

        // Set the network if the caller did not specify one.  The
        // default is testnet, exactly like dcrd.
        if cfg.net == CurrencyNet(0) {
            cfg.net = CurrencyNet::TEST_NET3;
        }

        // Set a default idle timeout if the caller did not specify
        // one.
        if cfg.idle_timeout_nanos == 0 {
            cfg.idle_timeout_nanos = crate::DEFAULT_IDLE_TIMEOUT;
        }

        Peer {
            cfg,
            inbound,
            addr: String::new(),
            na: NetAddressV2 {
                timestamp: 0,
                services: ServiceFlag(0),
                addr_type: dcroxide_wire::NetAddressType::UNKNOWN,
                encoded_addr: Vec::new(),
                port: 0,
            },
            id: 0,
            // The remote's services are unknown until its version
            // message arrives (dcrd 2.2 `remoteServices`; pre-2.2
            // seeded the local services here).
            services: ServiceFlag(0),
            user_agent: String::new(),
            version_known: false,
            advertised_proto_ver: 0,
            protocol_version,
            send_headers_preferred: false,
            verack_received: false,
            handshake_done: false,
            known_inventory: lru::Set::new_with_default_ttl(
                MAX_KNOWN_INVENTORY,
                MAX_KNOWN_INVENTORY_TTL,
            ),
            prev_get_blocks: None,
            prev_get_hdrs: None,
            time_offset: 0,
            time_connected_nanos: 0,
            starting_height: 0,
            last_block: 0,
            last_announced_block: None,
            last_ping_nonce: 0,
            last_ping_time_nanos: 0,
            last_ping_micros: 0,
            bytes_received: 0,
            bytes_sent: 0,
            last_send_nanos: 0,
            last_recv_nanos: 0,
        }
    }

    /// A new inbound peer (dcrd `NewInboundPeer`).  The daemon sets
    /// the address and network address when it associates the
    /// connection.
    pub fn new_inbound(cfg: Config) -> Peer {
        Peer::new_base(cfg, true)
    }

    /// A new outbound peer (dcrd `NewOutboundPeer`).
    pub fn new_outbound(cfg: Config, addr: &str) -> Result<Peer, String> {
        let mut p = Peer::new_base(cfg, false);
        p.addr = addr.to_string();

        let (host, port_str) = crate::netaddress::split_host_port(addr)?;
        let port: u16 = if port_str.bytes().all(|c| c.is_ascii_digit()) && !port_str.is_empty() {
            port_str.parse().map_err(|_| {
                format!("strconv.ParseUint: parsing \"{port_str}\": value out of range")
            })?
        } else {
            return Err(format!(
                "strconv.ParseUint: parsing \"{port_str}\": invalid syntax"
            ));
        };

        if let Some(resolve) = p.cfg.host_to_net_address.as_mut() {
            p.na = resolve(&host, port, ServiceFlag(0))?;
        } else {
            let ip = host
                .parse::<std::net::IpAddr>()
                .map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => {
                        let mut out = [0u8; 16];
                        out[10] = 0xff;
                        out[11] = 0xff;
                        out[12..16].copy_from_slice(&v4.octets());
                        out
                    }
                    std::net::IpAddr::V6(v6) => v6.octets(),
                })
                .unwrap_or([0u8; 16]);
            p.na = NetAddressV2::from_ip_port(ip, port, ServiceFlag(0), 0);
        }

        Ok(p)
    }

    /// Set the peer's address and network address when a connection
    /// is associated (the sync half of dcrd `AssociateConnection`).
    pub fn associate(&mut self, addr: &str, na: NetAddressV2, now_nanos: i64) {
        self.addr = addr.to_string();
        self.na = na;
        self.time_connected_nanos = now_nanos;
    }

    // -- Accessors mirroring dcrd's --

    /// The peer id (dcrd `ID`).
    pub fn id(&self) -> i32 {
        self.id
    }

    /// The peer address (dcrd `Addr`).
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The peer network address (dcrd `NA`).
    pub fn na(&self) -> &NetAddressV2 {
        &self.na
    }

    /// Whether the peer is inbound (dcrd `Inbound`).
    pub fn inbound(&self) -> bool {
        self.inbound
    }

    /// The remote peer's advertised services (dcrd `Services`).
    pub fn services(&self) -> ServiceFlag {
        self.services
    }

    /// The remote peer's user agent (dcrd `UserAgent`).
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Whether the version handshake has completed (dcrd
    /// `VersionKnown`).
    pub fn version_known(&self) -> bool {
        self.version_known
    }

    /// Whether the full initial handshake is done (dcrd
    /// `HandshakeDone`).
    pub fn handshake_done(&self) -> bool {
        self.handshake_done
    }

    /// Whether a verack was received (dcrd `VerAckReceived`).
    pub fn verack_received(&self) -> bool {
        self.verack_received
    }

    /// The negotiated protocol version (dcrd `ProtocolVersion`).
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// The protocol version the remote advertised.
    pub fn advertised_proto_ver(&self) -> u32 {
        self.advertised_proto_ver
    }

    /// The last block the remote announced (dcrd `LastBlock`).
    pub fn last_block(&self) -> i64 {
        self.last_block
    }

    /// The remote's starting height (dcrd `StartingHeight`).
    pub fn starting_height(&self) -> i64 {
        self.starting_height
    }

    /// The negotiated time offset in seconds (dcrd `TimeOffset`).
    pub fn time_offset(&self) -> i64 {
        self.time_offset
    }

    /// The nonce of the last outstanding ping (dcrd `LastPingNonce`).
    pub fn last_ping_nonce(&self) -> u64 {
        self.last_ping_nonce
    }

    /// The last measured ping round trip in microseconds (dcrd
    /// `LastPingMicros`).
    pub fn last_ping_micros(&self) -> i64 {
        self.last_ping_micros
    }

    /// Whether the remote prefers header announcements (dcrd
    /// `WantsHeaders`).
    pub fn wants_headers(&self) -> bool {
        self.send_headers_preferred
    }

    /// Update the last announced block (dcrd
    /// `UpdateLastAnnouncedBlock`).
    pub fn update_last_announced_block(&mut self, hash: Hash) {
        self.last_announced_block = Some(hash);
    }

    /// Update the last known block height (dcrd
    /// `UpdateLastBlockHeight`).
    pub fn update_last_block_height(&mut self, new_height: i64) {
        self.last_block = new_height;
    }

    /// Record bytes and time of a completed send; the daemon's output
    /// loop calls this (dcrd's write path bookkeeping).
    pub fn record_send(&mut self, bytes: u64, now_nanos: i64) {
        self.bytes_sent = self.bytes_sent.wrapping_add(bytes);
        self.last_send_nanos = now_nanos;
    }

    /// Record bytes and time of a completed receive (dcrd's read path
    /// bookkeeping).
    pub fn record_recv(&mut self, bytes: u64, now_nanos: i64) {
        self.bytes_received = self.bytes_received.wrapping_add(bytes);
        self.last_recv_nanos = now_nanos;
    }

    /// A snapshot of the current peer state (dcrd `StatsSnapshot`).
    pub fn stats_snapshot(&self) -> StatsSnap {
        StatsSnap {
            id: self.id,
            addr: self.addr.clone(),
            services: self.services,
            last_send_nanos: self.last_send_nanos,
            last_recv_nanos: self.last_recv_nanos,
            bytes_sent: self.bytes_sent,
            bytes_recv: self.bytes_received,
            connected_nanos: self.time_connected_nanos,
            time_offset: self.time_offset,
            version: self.user_agent.clone(),
            inbound: self.inbound,
            starting_height: self.starting_height,
            last_block: self.last_block,
            last_ping_nonce: self.last_ping_nonce,
            last_ping_micros: self.last_ping_micros,
            last_ping_time_nanos: self.last_ping_time_nanos,
            protocol_version: self.protocol_version,
        }
    }

    // -- Known inventory --

    /// Add the passed inventory to the known-inventory cache (dcrd
    /// `AddKnownInventory`).
    pub fn add_known_inventory(&mut self, inv_vect: InvVect) {
        self.known_inventory.put(inv_vect);
    }

    /// Whether the peer is known to have the passed inventory (dcrd
    /// `IsKnownInventory`).
    pub fn is_known_inventory(&mut self, inv_vect: &InvVect) -> bool {
        self.known_inventory.contains(inv_vect)
    }

    // -- Push builders --

    /// Send an addrv2 message with the provided addresses, shuffling
    /// and truncating past the per-message maximum and returning the
    /// message plus the list actually sent (dcrd `PushAddrV2Msg`).
    pub fn push_addr_v2_msg<E: PeerEnv>(
        &mut self,
        env: &mut E,
        addresses: &[NetAddressV2],
    ) -> Option<(Message, Vec<NetAddressV2>)> {
        // Nothing to send.
        if addresses.is_empty() {
            return None;
        }

        let mut addr_list: Vec<NetAddressV2> = addresses.to_vec();

        // Randomize the addresses sent if there are more than the
        // maximum allowed.
        if addr_list.len() > dcroxide_wire::MAX_ADDR_PER_V2_MSG as usize {
            env.shuffle_addrs_v2(&mut addr_list);
            addr_list.truncate(dcroxide_wire::MAX_ADDR_PER_V2_MSG as usize);
        }

        Some((
            Message::AddrV2(dcroxide_wire::MsgAddrV2 {
                addr_list: addr_list.clone(),
            }),
            addr_list,
        ))
    }

    /// Build an addr message for the provided addresses, limiting and
    /// randomizing them when there are too many (dcrd `PushAddrMsg`).
    /// Returns the message to queue and the addresses actually sent.
    #[allow(clippy::type_complexity)]
    pub fn push_addr_msg<E: PeerEnv>(
        &mut self,
        env: &mut E,
        addresses: &[NetAddress],
    ) -> Option<(Message, Vec<NetAddress>)> {
        // Nothing to send.
        if addresses.is_empty() {
            return None;
        }

        let mut addr_list: Vec<NetAddress> = addresses.to_vec();

        // Randomize the addresses sent if there are more than the
        // maximum allowed.
        if addr_list.len() > MAX_ADDR_PER_MSG {
            env.shuffle_addrs(&mut addr_list);
            addr_list.truncate(MAX_ADDR_PER_MSG);
        }

        let msg = Message::Addr(MsgAddr {
            addr_list: addr_list.clone(),
        });
        Some((msg, addr_list))
    }

    /// Build a getblocks message for the provided block locator and
    /// stop hash, ignoring back-to-back duplicate requests (dcrd
    /// `PushGetBlocksMsg`).  Returns the message to queue, or `None`
    /// when the request duplicates the previous one.
    pub fn push_get_blocks_msg(&mut self, locator: &[Hash], stop_hash: &Hash) -> Option<Message> {
        // Extract the begin hash from the block locator, if one was
        // specified, to use for filtering duplicate requests.
        let begin_hash = locator.first().copied();

        // Filter duplicate getblocks requests.
        if let (Some((prev_begin, prev_stop)), Some(begin)) = (&self.prev_get_blocks, begin_hash)
            && *stop_hash == *prev_stop
            && begin == *prev_begin
        {
            return None;
        }

        let msg = Message::GetBlocks(MsgGetBlocks(dcroxide_wire::BlockLocator {
            protocol_version: dcroxide_wire::PROTOCOL_VERSION,
            block_locator_hashes: locator.to_vec(),
            hash_stop: *stop_hash,
        }));

        // Update the previous getblocks request information.  dcrd
        // records the begin hash only when the locator had one.
        if let Some(begin) = begin_hash {
            self.prev_get_blocks = Some((begin, *stop_hash));
        }
        Some(msg)
    }

    /// Build a getheaders message for the provided block locator and
    /// stop hash, ignoring back-to-back duplicate requests (dcrd
    /// `PushGetHeadersMsg`).
    pub fn push_get_headers_msg(&mut self, locator: &[Hash], stop_hash: &Hash) -> Option<Message> {
        let begin_hash = locator.first().copied();

        // Filter duplicate getheaders requests.
        if let (Some((prev_begin, prev_stop)), Some(begin)) = (&self.prev_get_hdrs, begin_hash)
            && *stop_hash == *prev_stop
            && begin == *prev_begin
        {
            return None;
        }

        // dcrd's NewMsgGetHeaders leaves the protocol version zero.
        let msg = Message::GetHeaders(MsgGetHeaders(dcroxide_wire::BlockLocator {
            protocol_version: 0,
            block_locator_hashes: locator.to_vec(),
            hash_stop: *stop_hash,
        }));

        if let Some(begin) = begin_hash {
            self.prev_get_hdrs = Some((begin, *stop_hash));
        }
        Some(msg)
    }

    // -- Message handlers --

    /// Handle a ping message, returning the pong reply to queue (dcrd
    /// `handlePingMsg`).
    pub fn handle_ping_msg(&mut self, msg: &MsgPing) -> Message {
        // Include nonce from ping so pong can be identified.
        Message::Pong(MsgPong { nonce: msg.nonce })
    }

    /// Record a ping the daemon queued for sending (dcrd's output
    /// handler bookkeeping for `MsgPing`).
    pub fn record_sent_ping<E: PeerEnv>(&mut self, env: &mut E, msg: &MsgPing) {
        self.last_ping_nonce = msg.nonce;
        self.last_ping_time_nanos = env.now_nanos();
    }

    /// Handle a pong message, updating the ping statistics when it
    /// answers the last outstanding ping (dcrd `handlePongMsg`).
    pub fn handle_pong_msg<E: PeerEnv>(&mut self, env: &mut E, msg: &MsgPong) {
        if self.last_ping_nonce != 0 && msg.nonce == self.last_ping_nonce {
            let elapsed = env.now_nanos().saturating_sub(self.last_ping_time_nanos);
            self.last_ping_micros = elapsed.wrapping_div(1000);
            self.last_ping_nonce = 0;
        }
    }

    /// Record receipt of a sendheaders message (the flag half of
    /// dcrd's input handler for `MsgSendHeaders`).
    pub fn handle_send_headers_msg(&mut self) {
        self.send_headers_preferred = true;
    }

    /// Record receipt of a verack message (the flag half of dcrd's
    /// input handler for `MsgVerAck`).
    pub fn handle_verack_msg(&mut self) {
        self.verack_received = true;
    }

    // -- Version negotiation --

    /// Read and validate the remote version message (dcrd
    /// `readRemoteVersionMsg`).
    fn read_remote_version_msg<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
        on_version: Option<&mut OnVersionFn<'_>>,
    ) -> Result<MsgVersion, NegotiateError> {
        // Read their version message.
        let remote_msg = transport
            .read_message()
            .map_err(|e| NegotiateError::new(&e.message))?;

        // Disconnect clients if the first message is not a version
        // message.
        let msg = match remote_msg {
            Message::Version(msg) => msg,
            _ => {
                return Err(NegotiateError::typed(
                    NegotiateErrorKind::NotVersionMessage,
                    "a version message must precede all others",
                ));
            }
        };

        // Detect self connections.
        if !globals.allow_self_conns && globals.sent_nonces.contains(&msg.nonce) {
            return Err(NegotiateError::typed(
                NegotiateErrorKind::SelfConnection,
                "disconnecting peer connected to self",
            ));
        }

        // Negotiate the protocol version and set the services to what
        // the remote peer advertised.  Subsequent handshake reads
        // frame at the negotiated version (dcrd's `readMessage` uses
        // the live `ProtocolVersion` on every read).
        self.advertised_proto_ver = msg.protocol_version as u32;
        self.protocol_version = min_u32(self.protocol_version, self.advertised_proto_ver);
        transport.set_protocol_version(self.protocol_version);
        self.version_known = true;
        self.services = msg.services;
        self.na.services = msg.services;

        // Update stats.
        self.last_block = msg.last_block as i64;
        self.starting_height = msg.last_block as i64;

        // Set the peer's time offset.
        self.time_offset = msg
            .timestamp
            .wrapping_sub(env.now_nanos().wrapping_div(1_000_000_000));

        // Set the peer's ID and user agent.
        self.id = globals.next_id();
        self.user_agent = msg.user_agent.clone();

        // Fire the daemon's version listener exactly where dcrd's
        // onVersion callback runs: after the state updates, before
        // the too-old rejection; an error aborts the handshake.
        if let Some(on_version) = on_version
            && let Err(e) = on_version(self, &msg)
        {
            return Err(NegotiateError::new(&e));
        }

        // Disconnect clients that have a protocol version that is too
        // old.
        let req_protocol_version = dcroxide_wire::REMOVE_REJECT_VERSION as i32;
        if msg.protocol_version < req_protocol_version {
            return Err(NegotiateError {
                message: format!("protocol version must be {req_protocol_version} or greater"),
                kind: Some(NegotiateErrorKind::ProtocolVerTooOld),
                remote_version: Some(Box::new(msg)),
            });
        }

        Ok(msg)
    }

    /// Create the local version message to send to the remote peer
    /// (dcrd `localVersionMsg`).
    fn local_version_msg<E: PeerEnv>(
        &mut self,
        env: &mut E,
        globals: &mut PeerGlobals,
    ) -> Result<MsgVersion, String> {
        let mut block_num: i64 = 0;
        if let Some(newest) = self.cfg.newest_block.as_mut() {
            let (_, num) = newest()?;
            block_num = num;
        }

        // Convert the peer's v2 address to the legacy form the version
        // message carries (dcrd building `theirNA` from the v2
        // `EncodedAddr`): Go's `To16` yields the mapped form for a
        // 4-byte address, the bytes unchanged for 16, and nil — all
        // zero bytes on the wire — for any other length, notably a
        // 32-byte Tor v3 key.
        let mut their_ip = [0u8; 16];
        match self.na.encoded_addr.len() {
            4 => {
                their_ip[10] = 0xff;
                their_ip[11] = 0xff;
                their_ip[12..16].copy_from_slice(&self.na.encoded_addr);
            }
            16 => their_ip.copy_from_slice(&self.na.encoded_addr),
            _ => {}
        }
        let mut their_na = NetAddress {
            timestamp: 0,
            services: self.na.services,
            ip: their_ip,
            port: self.na.port,
        };

        // If we are behind a proxy and the connection comes from the
        // proxy then we return an unroutable address as their address.
        // This is to prevent leaking the tor proxy address.
        if !self.cfg.proxy.is_empty() {
            let split = crate::netaddress::split_host_port(&self.cfg.proxy);
            let hide = match split {
                // An invalid proxy means poorly configured; be on the
                // safe side.
                Err(_) => true,
                Ok((proxy_address, _)) => ip_string(&their_na.ip) == proxy_address,
            };
            if hide {
                their_na = NetAddress {
                    timestamp: 0,
                    services: their_na.services,
                    // Go builds this from a 4-byte zero IP, which the
                    // wire address stores in the mapped form.
                    ip: {
                        let mut ip = [0u8; 16];
                        ip[10] = 0xff;
                        ip[11] = 0xff;
                        ip
                    },
                    port: 0,
                };
            }
        }

        // A network address with only the services set is used as the
        // "addrme" in the version message.
        let our_na = NetAddress {
            timestamp: 0,
            services: self.cfg.services,
            ip: [0u8; 16],
            port: 0,
        };

        // Generate a unique nonce for this peer so self connections
        // can be detected.
        let nonce = env.rand_u64();
        globals.sent_nonces.put(nonce);

        // Version message.
        let mut msg = MsgVersion {
            protocol_version: self.protocol_version() as i32,
            services: self.cfg.services,
            timestamp: env.now_nanos().wrapping_div(1_000_000_000),
            addr_you: their_na,
            addr_me: our_na,
            nonce,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            last_block: block_num as i32,
            disable_relay_tx: self.cfg.disable_relay_tx,
        };

        // Advertise the user agent, silently keeping the default when
        // the result would be invalid, exactly like dcrd, which
        // ignores the error from AddUserAgent.
        let mut new_user_agent = format!(
            "{}:{}",
            self.cfg.user_agent_name, self.cfg.user_agent_version
        );
        if !self.cfg.user_agent_comments.is_empty() {
            new_user_agent = format!(
                "{new_user_agent}({})",
                self.cfg.user_agent_comments.join("; ")
            );
        }
        let new_user_agent = format!("{}{new_user_agent}/", msg.user_agent);
        if new_user_agent.len() <= MAX_USER_AGENT_LEN
            && new_user_agent.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            msg.user_agent = new_user_agent;
        }

        Ok(msg)
    }

    /// Write our version message to the remote peer (dcrd
    /// `writeLocalVersionMsg`).
    fn write_local_version_msg<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
    ) -> Result<(), NegotiateError> {
        let local_ver_msg = self
            .local_version_msg(env, globals)
            .map_err(|e| NegotiateError::new(&e))?;
        transport
            .write_message(&Message::Version(local_ver_msg))
            .map_err(|e| NegotiateError::new(&e))
    }

    /// Read the remote verack strictly (dcrd `readRemoteVerAckMsg`,
    /// used at protocol versions with addrv2 support): any other
    /// message disconnects.
    fn read_remote_verack_msg<T: MsgTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), NegotiateError> {
        let remote_msg = transport
            .read_message()
            .map_err(|e| NegotiateError::new(&e.message))?;
        match remote_msg {
            Message::VerAck => {
                self.verack_received = true;
                Ok(())
            }
            _ => Err(NegotiateError::typed(
                NegotiateErrorKind::NotVerAckMessage,
                "the verack message must follow the version message and precede all others",
            )),
        }
    }

    /// Read the remote verack tolerantly (dcrd
    /// `readRemoteVerAckMsgLegacy`, used below the addrv2 protocol
    /// version): up to three non-verack messages are queued for the
    /// input handler to replay after the handshake.
    fn read_remote_verack_msg_legacy<T: MsgTransport>(
        &mut self,
        transport: &mut T,
        delayed: &mut Vec<Message>,
    ) -> Result<(), NegotiateError> {
        const MAX_NON_VER_ACKS: usize = 3;
        for _ in 0..MAX_NON_VER_ACKS {
            let msg = transport
                .read_message()
                .map_err(|e| NegotiateError::new(&e.message))?;
            match msg {
                Message::VerAck => {
                    self.verack_received = true;
                    return Ok(());
                }
                other => delayed.push(other),
            }
        }
        Err(NegotiateError::typed(
            NegotiateErrorKind::NotVerAckMessage,
            &format!(
                "the verack message must follow the version message within {MAX_NON_VER_ACKS} messages"
            ),
        ))
    }

    /// Read the remote verack with the strictness the negotiated
    /// protocol version selects (dcrd's `readRemoteVerAckMsgFn`
    /// dispatch in the handshake).
    fn read_remote_verack<T: MsgTransport>(
        &mut self,
        transport: &mut T,
        delayed: &mut Vec<Message>,
    ) -> Result<(), NegotiateError> {
        if self.protocol_version() < dcroxide_wire::ADDR_V2_VERSION {
            self.read_remote_verack_msg_legacy(transport, delayed)
        } else {
            self.read_remote_verack_msg(transport)
        }
    }

    /// Wait to receive a version message from the peer, send ours,
    /// then exchange veracks (dcrd `inboundHandshake`).  The version
    /// callback runs inside the version read exactly where dcrd's
    /// `onVersion` does — after the peer state updates, before the
    /// too-old rejection — and its error aborts the handshake.
    /// Returns the remote version plus any messages a legacy peer
    /// sent before its verack for the input handler to replay.
    pub fn negotiate_inbound_protocol<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
        on_version: Option<&mut OnVersionFn<'_>>,
    ) -> Result<HandshakeOutcome, NegotiateError> {
        let remote = self.read_remote_version_msg(transport, env, globals, on_version)?;
        self.write_local_version_msg(transport, env, globals)?;
        transport
            .write_message(&Message::VerAck)
            .map_err(|e| NegotiateError::new(&e))?;
        let mut delayed = Vec::new();
        self.read_remote_verack(transport, &mut delayed)?;
        self.handshake_done = true;
        Ok(HandshakeOutcome {
            remote_version: Box::new(remote),
            delayed,
        })
    }

    /// Send our version message, wait to receive one from the peer,
    /// then exchange veracks (dcrd `outboundHandshake`); the verack
    /// read precedes our verack write on the outbound side.
    pub fn negotiate_outbound_protocol<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
        on_version: Option<&mut OnVersionFn<'_>>,
    ) -> Result<HandshakeOutcome, NegotiateError> {
        self.write_local_version_msg(transport, env, globals)?;
        let remote = self.read_remote_version_msg(transport, env, globals, on_version)?;
        let mut delayed = Vec::new();
        self.read_remote_verack(transport, &mut delayed)?;
        transport
            .write_message(&Message::VerAck)
            .map_err(|e| NegotiateError::new(&e))?;
        self.handshake_done = true;
        Ok(HandshakeOutcome {
            remote_version: Box::new(remote),
            delayed,
        })
    }
}
