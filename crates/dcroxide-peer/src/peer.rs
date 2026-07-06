// SPDX-License-Identifier: ISC
//! The peer state and protocol decisions (dcrd peer `peer.go`).

use dcroxide_chainhash::Hash;
use dcroxide_containers::lru;
use dcroxide_wire::{
    CurrencyNet, InvVect, Message, MsgAddr, MsgGetBlocks, MsgGetHeaders, MsgPing, MsgPong,
    MsgVersion, NetAddress, ServiceFlag,
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

type HostToNetAddressFn = Box<dyn FnMut(&str, u16, ServiceFlag) -> Result<NetAddress, String>>;
type NewestBlockFn = Box<dyn FnMut() -> Result<(Hash, i64), String>>;

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
    /// The remote version message, when one was read.
    pub remote_version: Option<Box<MsgVersion>>,
}

impl NegotiateError {
    fn new(message: &str) -> NegotiateError {
        NegotiateError {
            message: message.to_string(),
            remote_version: None,
        }
    }
}

/// The synchronous peer core (dcrd `Peer` minus its handler
/// goroutines and connection plumbing).
pub struct Peer {
    cfg: Config,
    inbound: bool,
    addr: String,
    na: NetAddress,

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

        let services = cfg.services;
        Peer {
            cfg,
            inbound,
            addr: String::new(),
            na: NetAddress {
                timestamp: 0,
                services: ServiceFlag(0),
                ip: [0u8; 16],
                port: 0,
            },
            id: 0,
            services,
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
            p.na = NetAddress {
                timestamp: 0,
                services: ServiceFlag(0),
                ip,
                port,
            };
        }

        Ok(p)
    }

    /// Set the peer's address and network address when a connection
    /// is associated (the sync half of dcrd `AssociateConnection`).
    pub fn associate(&mut self, addr: &str, na: NetAddress, now_nanos: i64) {
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
    pub fn na(&self) -> &NetAddress {
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
        if let (Some((prev_begin, prev_stop)), Some(begin)) = (&self.prev_get_blocks, begin_hash) {
            if *stop_hash == *prev_stop && begin == *prev_begin {
                return None;
            }
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
        if let (Some((prev_begin, prev_stop)), Some(begin)) = (&self.prev_get_hdrs, begin_hash) {
            if *stop_hash == *prev_stop && begin == *prev_begin {
                return None;
            }
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
    ) -> Result<MsgVersion, NegotiateError> {
        // Read their version message.
        let remote_msg = transport
            .read_message()
            .map_err(|e| NegotiateError::new(&e))?;

        // Disconnect clients if the first message is not a version
        // message.
        let msg = match remote_msg {
            Message::Version(msg) => msg,
            _ => {
                return Err(NegotiateError::new(
                    "a version message must precede all others",
                ));
            }
        };

        // Detect self connections.
        if !globals.allow_self_conns && globals.sent_nonces.contains(&msg.nonce) {
            return Err(NegotiateError::new("disconnecting peer connected to self"));
        }

        // Negotiate the protocol version and set the services to what
        // the remote peer advertised.
        self.advertised_proto_ver = msg.protocol_version as u32;
        self.protocol_version = min_u32(self.protocol_version, self.advertised_proto_ver);
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

        // Disconnect clients that have a protocol version that is too
        // old.
        let req_protocol_version = dcroxide_wire::REMOVE_REJECT_VERSION as i32;
        if msg.protocol_version < req_protocol_version {
            return Err(NegotiateError {
                message: format!("protocol version must be {req_protocol_version} or greater"),
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

        let mut their_na = self.na;

        // If we are behind a proxy and the connection comes from the
        // proxy then we return an unroutable address as their address.
        // This is to prevent leaking the tor proxy address.
        if !self.cfg.proxy.is_empty() {
            let split = crate::netaddress::split_host_port(&self.cfg.proxy);
            let hide = match split {
                // An invalid proxy means poorly configured; be on the
                // safe side.
                Err(_) => true,
                Ok((proxy_address, _)) => ip_string(&self.na.ip) == proxy_address,
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

    /// Wait to receive a version message from the peer then send ours
    /// (dcrd `negotiateInboundProtocol`).  Returns the remote version
    /// message for the daemon's version listener.
    pub fn negotiate_inbound_protocol<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
    ) -> Result<MsgVersion, NegotiateError> {
        let remote = self.read_remote_version_msg(transport, env, globals)?;
        self.write_local_version_msg(transport, env, globals)?;
        self.handshake_done = true;
        Ok(remote)
    }

    /// Send our version message then wait to receive one from the
    /// peer (dcrd `negotiateOutboundProtocol`).
    pub fn negotiate_outbound_protocol<T: MsgTransport, E: PeerEnv>(
        &mut self,
        transport: &mut T,
        env: &mut E,
        globals: &mut PeerGlobals,
    ) -> Result<MsgVersion, NegotiateError> {
        self.write_local_version_msg(transport, env, globals)?;
        let remote = self.read_remote_version_msg(transport, env, globals)?;
        self.handshake_done = true;
        Ok(remote)
    }
}
