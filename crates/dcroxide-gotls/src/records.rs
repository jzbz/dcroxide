// SPDX-License-Identifier: ISC
//! Go's checks on the records a client sends after its first ClientHello,
//! while Go's server would still answer a refusal in the clear: the
//! record layer's version and length checks (`readRecordOrCCS`,
//! `crypto/tls/conn.go:652-675`), and, after a HelloRetryRequest, the
//! checks Go's TLS 1.3 server makes of the second ClientHello
//! (`doHelloRetryRequest`, `crypto/tls/handshake_server_tls13.go:581-655`,
//! with `illegalClientHelloChange`, `:657-714`).
//!
//! rustls makes neither.  It takes a record of any version `0x03XX`, as
//! RFC 8446 §5.1 asks of a TLS 1.3 implementation, where Go, once it has
//! read the first ClientHello and set the version, refuses any record
//! whose version is not TLS 1.2's `0x0303` with `protocol_version` and
//! `tls: received record with version 301 when expecting version 303`.
//! And of a second ClientHello rustls checks only that it withdraws no
//! PSK and offers no early data (`rustls-0.23.46/src/server/tls13.rs`),
//! where Go also requires one key share, for the group the
//! HelloRetryRequest named, and every field it compares unchanged, and
//! refuses with `illegal_parameter` and its own text otherwise.
//!
//! [`GoRecordChecks`] makes those checks over the bytes as they pass
//! between the socket and rustls, ahead of rustls, so that a refused
//! record is never processed: in TLS 1.3, over the records from the end
//! of the first ClientHello to the end of the second, after a
//! HelloRetryRequest; in TLS 1.2, over the client's records up to its
//! Finished.  Past those points Go's server has keys in use and would
//! send its alert encrypted, which only rustls could do; PARITY.md
//! records what is left there.

use crate::server::GoRefusal;

/// The `random` of a HelloRetryRequest (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The record version Go expects of every record after the first
/// ClientHello, in TLS 1.2 and TLS 1.3 alike (`conn.go:652-657`).
const EXPECTED_RECORD_VERSION: u16 = 0x0303;

/// The longest record Go reads in TLS 1.2, 2^14 plus 2048
/// (`maxCiphertext`, `crypto/tls/common.go`).
const MAX_CIPHERTEXT: usize = 18432;

/// The longest record Go reads in TLS 1.3, 2^14 plus 256
/// (`maxCiphertextTLS13`, `crypto/tls/common.go`).
const MAX_CIPHERTEXT_TLS13: usize = 16640;

/// The longest handshake message Go reads (`maxHandshake`,
/// `crypto/tls/common.go`); a longer second ClientHello is left to rustls.
const MAX_HANDSHAKE: usize = 65536;

/// The most client bytes kept from before the server's first flight is
/// seen, which a client has no reason to send at all.
const MAX_PENDING: usize = 1 << 17;

/// A cursor over handshake bytes, every read bounds-checked, after
/// Go's `cryptobyte.String`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        match *self.take(2)? {
            [hi, lo] => Some(u16::from_be_bytes([hi, lo])),
            _ => None,
        }
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// Two-byte values to the end, as Go's `ReadUint16` loops read them:
    /// `None` for an odd length.
    fn u16s(bytes: &[u8]) -> Option<Vec<u16>> {
        let (pairs, rest) = bytes.as_chunks::<2>();
        rest.is_empty()
            .then(|| pairs.iter().map(|&pair| u16::from_be_bytes(pair)).collect())
    }
}

/// The handshake message at the start of `records`, reassembled from the
/// handshake records it spans, and the number of bytes those records
/// take: `None` when they do not hold a whole one.  Records of another
/// type end the search.
pub(crate) fn first_handshake_message(records: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut rest = Reader(records);
    let mut message = Vec::new();
    loop {
        let content_type = rest.u8()?;
        let _record_version = rest.u16()?;
        let fragment = rest.vec16()?;
        if content_type != 22 {
            return None;
        }
        message.extend_from_slice(fragment);
        if let [_, a, b, c, ..] = message[..] {
            let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).ok()?;
            let total = len.checked_add(4)?;
            if message.len() >= total {
                message.truncate(total);
                let consumed = records.len().checked_sub(rest.0.len())?;
                return Some((message, consumed));
            }
        }
    }
}

/// Go's `clientHelloMsg` (`crypto/tls/handshake_messages.go:72-110`), the
/// fields its server compares between a first and a second ClientHello and
/// those it checks of the second, read by its `unmarshal` (`:420-679`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GoClientHello {
    vers: u16,
    random: Vec<u8>,
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    server_name: Vec<u8>,
    ocsp_stapling: bool,
    supported_curves: Vec<u16>,
    supported_points: Vec<u8>,
    ticket_supported: bool,
    session_ticket: Vec<u8>,
    supported_signature_algorithms: Vec<u16>,
    supported_signature_algorithms_cert: Vec<u16>,
    secure_renegotiation_supported: bool,
    secure_renegotiation: Vec<u8>,
    alpn_protocols: Vec<Vec<u8>>,
    scts: bool,
    supported_versions: Vec<u16>,
    cookie: Vec<u8>,
    /// The group of each key share, in the client's order.
    key_shares: Vec<u16>,
    early_data: bool,
    psk_modes: Vec<u8>,
}

impl GoClientHello {
    /// Go's `clientHelloMsg.unmarshal` of `message`, a whole handshake
    /// message with its four-byte header: `None` where it returns false.
    fn parse(message: &[u8]) -> Option<GoClientHello> {
        let mut s = Reader(message);
        s.take(4)?;
        let mut m = GoClientHello {
            vers: s.u16()?,
            random: s.take(32)?.to_vec(),
            session_id: s.vec8()?.to_vec(),
            ..GoClientHello::default()
        };
        m.cipher_suites = Reader::u16s(s.vec16()?)?;
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
        m.secure_renegotiation_supported = m.cipher_suites.contains(&0x00ff);
        m.compression_methods = s.vec8()?.to_vec();
        if s.0.is_empty() {
            return Some(m);
        }
        let mut extensions = Reader(s.vec16()?);
        if !s.0.is_empty() {
            return None;
        }
        let mut seen: Vec<u16> = Vec::new();
        while !extensions.0.is_empty() {
            let extension = extensions.u16()?;
            let mut data = Reader(extensions.vec16()?);
            if seen.contains(&extension) {
                return None;
            }
            seen.push(extension);
            match extension {
                // server_name (RFC 6066 §3).
                0 => {
                    let mut names = Reader(data.vec16()?);
                    if names.0.is_empty() {
                        return None;
                    }
                    while !names.0.is_empty() {
                        let name_type = names.u8()?;
                        let name = names.vec16()?;
                        if name.is_empty() {
                            return None;
                        }
                        if name_type != 0 {
                            continue;
                        }
                        if !m.server_name.is_empty() || name.ends_with(b".") {
                            return None;
                        }
                        m.server_name = name.to_vec();
                    }
                }
                // status_request.
                5 => {
                    let status_type = data.u8()?;
                    data.vec16()?;
                    data.vec16()?;
                    m.ocsp_stapling = status_type == 1;
                }
                // supported_groups.
                10 => {
                    let curves = data.vec16()?;
                    if curves.is_empty() {
                        return None;
                    }
                    m.supported_curves = Reader::u16s(curves)?;
                }
                // ec_point_formats.
                11 => {
                    let points = data.vec8()?;
                    if points.is_empty() {
                        return None;
                    }
                    m.supported_points = points.to_vec();
                }
                // session_ticket.
                35 => {
                    m.ticket_supported = true;
                    m.session_ticket = data.take(data.0.len())?.to_vec();
                }
                // signature_algorithms and signature_algorithms_cert.
                13 | 50 => {
                    let algorithms = data.vec16()?;
                    if algorithms.is_empty() {
                        return None;
                    }
                    let algorithms = Reader::u16s(algorithms)?;
                    if extension == 13 {
                        m.supported_signature_algorithms = algorithms;
                    } else {
                        m.supported_signature_algorithms_cert = algorithms;
                    }
                }
                // renegotiation_info.
                0xff01 => {
                    m.secure_renegotiation = data.vec8()?.to_vec();
                    m.secure_renegotiation_supported = true;
                }
                // extended_master_secret, read and kept by Go but not
                // compared.
                23 => {}
                // application_layer_protocol_negotiation.
                16 => {
                    let mut protocols = Reader(data.vec16()?);
                    if protocols.0.is_empty() {
                        return None;
                    }
                    while !protocols.0.is_empty() {
                        let protocol = protocols.vec8()?;
                        if protocol.is_empty() {
                            return None;
                        }
                        m.alpn_protocols.push(protocol.to_vec());
                    }
                }
                // signed_certificate_timestamp.
                18 => m.scts = true,
                // supported_versions.
                43 => {
                    let versions = data.vec8()?;
                    if versions.is_empty() {
                        return None;
                    }
                    m.supported_versions = Reader::u16s(versions)?;
                }
                // cookie.
                44 => {
                    let cookie = data.vec16()?;
                    if cookie.is_empty() {
                        return None;
                    }
                    m.cookie = cookie.to_vec();
                }
                // key_share.
                51 => {
                    let mut shares = Reader(data.vec16()?);
                    while !shares.0.is_empty() {
                        let group = shares.u16()?;
                        if shares.vec16()?.is_empty() {
                            return None;
                        }
                        m.key_shares.push(group);
                    }
                }
                // early_data.
                42 => m.early_data = true,
                // psk_key_exchange_modes.
                45 => m.psk_modes = data.vec8()?.to_vec(),
                // quic_transport_parameters and encrypted_client_hello,
                // whose contents Go takes whole.
                57 | 0xfe0d => {
                    data.take(data.0.len())?;
                }
                // pre_shared_key, which must come last.
                41 => {
                    if !extensions.0.is_empty() {
                        return None;
                    }
                    let mut identities = Reader(data.vec16()?);
                    if identities.0.is_empty() {
                        return None;
                    }
                    while !identities.0.is_empty() {
                        if identities.vec16()?.is_empty() {
                            return None;
                        }
                        identities.take(4)?;
                    }
                    let mut binders = Reader(data.vec16()?);
                    if binders.0.is_empty() {
                        return None;
                    }
                    while !binders.0.is_empty() {
                        if binders.vec8()?.is_empty() {
                            return None;
                        }
                    }
                }
                // Go ignores an extension it does not know, and what is in it.
                _ => continue,
            }
            if !data.0.is_empty() {
                return None;
            }
        }
        Some(m)
    }

    /// Go's `illegalClientHelloChange(ch, ch1)` for `self`, the second
    /// ClientHello, and `first`: whether a field Go compares differs.
    fn illegally_changed_from(&self, first: &GoClientHello) -> bool {
        self.supported_versions != first.supported_versions
            || self.cipher_suites != first.cipher_suites
            || self.supported_curves != first.supported_curves
            || self.supported_signature_algorithms != first.supported_signature_algorithms
            || self.supported_signature_algorithms_cert != first.supported_signature_algorithms_cert
            || self.alpn_protocols != first.alpn_protocols
            || self.vers != first.vers
            || self.random != first.random
            || self.session_id != first.session_id
            || self.compression_methods != first.compression_methods
            || self.server_name != first.server_name
            || self.ocsp_stapling != first.ocsp_stapling
            || self.supported_points != first.supported_points
            || self.ticket_supported != first.ticket_supported
            || self.session_ticket != first.session_ticket
            || self.secure_renegotiation_supported != first.secure_renegotiation_supported
            || self.secure_renegotiation != first.secure_renegotiation
            || self.scts != first.scts
            || self.cookie != first.cookie
            || self.psk_modes != first.psk_modes
    }

    /// Go's refusal of `self`, the ClientHello sent after a
    /// HelloRetryRequest naming `group`, given the first (`first`), each
    /// with `illegal_parameter` (`handshake_server_tls13.go:636-655`).
    fn second_hello_refusal(&self, first: &GoClientHello, group: u16) -> Option<GoRefusal> {
        let text = match self.key_shares.as_slice() {
            [share] if *share != group => {
                "tls: client sent unexpected key share in second ClientHello"
            }
            [_] if self.early_data => "tls: client indicated early data in second ClientHello",
            [_] if self.illegally_changed_from(first) => {
                "tls: client illegally modified second ClientHello"
            }
            [_] => return None,
            _ => "tls: client didn't send one key share in second ClientHello",
        };
        Some(GoRefusal {
            alert: 47,
            text: text.to_string(),
            record_version: EXPECTED_RECORD_VERSION,
        })
    }
}

/// Where a connection stands for [`GoRecordChecks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The server's first flight has not been seen.
    AwaitingServer,
    /// The server sent a HelloRetryRequest for `group`; the client's
    /// records up to the end of its second ClientHello are checked.
    Retry { group: u16 },
    /// TLS 1.2 was negotiated; the client's records up to its Finished,
    /// the one after its ChangeCipherSpec, are checked.
    Tls12 { change_cipher_spec_seen: bool },
    /// Nothing more is checked.
    Done,
}

/// The record a stream of records is in the middle of.
#[derive(Debug, Default)]
struct RecordCursor {
    /// The header bytes read so far.
    header: [u8; 5],
    header_len: usize,
    /// The body bytes still to come.
    body_left: usize,
}

impl RecordCursor {
    /// Take header bytes from the front of `bytes`: the header, once it
    /// is whole, and how many bytes were taken.
    fn header_from(&mut self, bytes: &[u8]) -> (Option<[u8; 5]>, usize) {
        let n = self
            .header
            .len()
            .saturating_sub(self.header_len)
            .min(bytes.len());
        if let (Some(to), Some(from)) = (
            self.header
                .get_mut(self.header_len..self.header_len.saturating_add(n)),
            bytes.get(..n),
        ) {
            to.copy_from_slice(from);
        }
        self.header_len = self.header_len.saturating_add(n);
        if self.header_len < self.header.len() {
            return (None, n);
        }
        self.header_len = 0;
        self.body_left = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
        (Some(self.header), n)
    }
}

/// Go's record-layer and second-ClientHello checks for one connection,
/// fed the bytes it carries after the first ClientHello in each direction
/// (module documentation).
///
/// [`handshake`](crate::handshake) runs one itself.  A driver over
/// another transport builds one with [`GoRecordChecks::new`] from the
/// connection's opening bytes once rustls's `Acceptor` has the
/// ClientHello, passes it every byte rustls writes to the client
/// ([`GoRecordChecks::server_sent`]) and every byte read from the client
/// before rustls is given it ([`GoRecordChecks::client_sent`]), and on a
/// refusal gives rustls only the bytes before the refused record,
/// processes them, and, if rustls refuses nothing in them, sends Go's
/// alert ([`GoRefusal::record`]) in place of anything rustls queued.
#[derive(Debug)]
pub struct GoRecordChecks {
    /// The first ClientHello as Go reads it, `None` where Go's reader
    /// refuses what rustls took.
    first: Option<GoClientHello>,
    stage: Stage,
    /// The client's bytes after the first ClientHello that arrived before
    /// the server's first flight was seen.
    pending: Vec<u8>,
    /// The client's records.
    client: RecordCursor,
    /// The type of the client's record in progress.
    client_type: u8,
    /// The second ClientHello's bytes, gathered from its records.
    second: Vec<u8>,
    /// The body of a ChangeCipherSpec record in progress.
    change_cipher_spec: Vec<u8>,
    /// The server's records.
    server: RecordCursor,
    /// The body of the server's first handshake record, while it is read.
    server_first: Option<Vec<u8>>,
}

impl GoRecordChecks {
    /// The checks for a connection that opened with `opening`, the
    /// client's bytes as rustls's `Acceptor` read them, the whole first
    /// ClientHello first.  Bytes after it, which a client sends before
    /// any answer only out of turn, are checked once the server's first
    /// flight is seen.  When `opening` holds no whole ClientHello the
    /// checks are off.
    pub fn new(opening: &[u8]) -> GoRecordChecks {
        let mut checks = GoRecordChecks {
            first: None,
            stage: Stage::Done,
            pending: Vec::new(),
            client: RecordCursor::default(),
            client_type: 0,
            second: Vec::new(),
            change_cipher_spec: Vec::new(),
            server: RecordCursor::default(),
            server_first: Some(Vec::new()),
        };
        if let Some((message, consumed)) = first_handshake_message(opening)
            && message.first() == Some(&1)
        {
            checks.first = GoClientHello::parse(&message);
            checks.stage = Stage::AwaitingServer;
            checks.pending = opening.get(consumed..).unwrap_or_default().to_vec();
        }
        checks
    }

    /// Checks that are off, for a connection whose opening bytes were not
    /// all kept.
    pub(crate) fn off() -> GoRecordChecks {
        GoRecordChecks::new(&[])
    }

    /// Account for `bytes`, written by rustls to the client.
    pub fn server_sent(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.stage != Stage::Done {
            if self.server.body_left == 0 {
                let (header, n) = self.server.header_from(bytes);
                bytes = bytes.get(n..).unwrap_or_default();
                let Some(header) = header else {
                    continue;
                };
                if let Stage::Tls12 { .. } = self.stage
                    && header[0] == 20
                {
                    // The server's ChangeCipherSpec: what it sends from
                    // here on is protected.
                    self.stage = Stage::Done;
                    return;
                }
                if self.stage == Stage::AwaitingServer && header[0] != 22 {
                    self.stage = Stage::Done;
                    return;
                }
                if self.server.body_left == 0 {
                    self.server_record_done();
                }
                continue;
            }
            let n = self.server.body_left.min(bytes.len());
            if let Some(first) = &mut self.server_first
                && self.stage == Stage::AwaitingServer
            {
                first.extend_from_slice(bytes.get(..n).unwrap_or_default());
            }
            self.server.body_left = self.server.body_left.saturating_sub(n);
            bytes = bytes.get(n..).unwrap_or_default();
            if self.server.body_left == 0 {
                self.server_record_done();
            }
        }
    }

    /// The server finished a record: its first handshake record says what
    /// it answered the first ClientHello with.
    fn server_record_done(&mut self) {
        if self.stage != Stage::AwaitingServer {
            return;
        }
        let Some(body) = self.server_first.take() else {
            self.stage = Stage::Done;
            return;
        };
        self.stage = server_hello_stage(&body);
    }

    /// Account for `bytes`, read from the client and not yet given to
    /// rustls: `None` while Go would go on, or the offset in `bytes` of
    /// the first byte of the record Go refuses and Go's refusal.  An
    /// offset of zero may also mean a record among bytes that arrived
    /// earlier, before the server's first flight was seen.
    pub fn client_sent(&mut self, bytes: &[u8]) -> Option<(usize, GoRefusal)> {
        match self.stage {
            Stage::Done => return None,
            Stage::AwaitingServer => {
                if self.pending.len().saturating_add(bytes.len()) > MAX_PENDING {
                    self.stage = Stage::Done;
                } else {
                    self.pending.extend_from_slice(bytes);
                }
                return None;
            }
            Stage::Retry { .. } | Stage::Tls12 { .. } => {}
        }
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            if let Some((_, refusal)) = self.walk(&pending) {
                return Some((0, refusal));
            }
        }
        self.walk(bytes)
    }

    /// Walk the client's `bytes` record by record under the current stage.
    fn walk(&mut self, bytes: &[u8]) -> Option<(usize, GoRefusal)> {
        let mut at = 0usize;
        // The offset of the record in progress, in `bytes`; zero for one
        // that began in an earlier call.
        let mut record_start = 0usize;
        while let Some(rest) = bytes.get(at..).filter(|rest| !rest.is_empty()) {
            if self.stage == Stage::Done {
                return None;
            }
            if self.client.body_left == 0 {
                if self.client.header_len == 0 {
                    record_start = at;
                }
                let (header, n) = self.client.header_from(rest);
                at = at.saturating_add(n);
                let Some(header) = header else {
                    continue;
                };
                if let Some(refusal) = self.record_header(header) {
                    self.stage = Stage::Done;
                    return Some((record_start, refusal));
                }
                if self.client.body_left == 0
                    && let Some(refusal) = self.record_done()
                {
                    self.stage = Stage::Done;
                    return Some((record_start, refusal));
                }
                continue;
            }
            let n = self.client.body_left.min(rest.len());
            let body = rest.get(..n).unwrap_or_default();
            if let Stage::Retry { .. } = self.stage {
                match self.client_type {
                    22 => self.second.extend_from_slice(body),
                    20 => self.change_cipher_spec.extend_from_slice(body),
                    _ => {}
                }
            }
            self.client.body_left = self.client.body_left.saturating_sub(n);
            at = at.saturating_add(n);
            if self.client.body_left == 0
                && let Some(refusal) = self.record_done()
            {
                self.stage = Stage::Done;
                return Some((record_start, refusal));
            }
        }
        None
    }

    /// Go's record header checks (`conn.go:652-675`), then what the
    /// stage makes of a record of this type.
    fn record_header(&mut self, header: [u8; 5]) -> Option<GoRefusal> {
        let [content_type, version_hi, version_lo, _, _] = header;
        let version = u16::from_be_bytes([version_hi, version_lo]);
        if version != EXPECTED_RECORD_VERSION {
            return Some(GoRefusal {
                alert: 70,
                text: format!(
                    "tls: received record with version {version:x} when expecting version \
                     {EXPECTED_RECORD_VERSION:x}"
                ),
                record_version: EXPECTED_RECORD_VERSION,
            });
        }
        let limit = match self.stage {
            Stage::Retry { .. } => MAX_CIPHERTEXT_TLS13,
            _ => MAX_CIPHERTEXT,
        };
        if self.client.body_left > limit {
            return Some(GoRefusal {
                alert: 22,
                text: format!(
                    "tls: oversized record received with length {}",
                    self.client.body_left
                ),
                record_version: EXPECTED_RECORD_VERSION,
            });
        }
        self.client_type = content_type;
        match self.stage {
            Stage::Tls12 {
                change_cipher_spec_seen: true,
            } => {
                // The client's Finished: Go answers what follows it with
                // its own keys in use.
                self.stage = Stage::Done;
            }
            Stage::Tls12 {
                change_cipher_spec_seen: false,
            } if content_type == 20 => {
                self.stage = Stage::Tls12 {
                    change_cipher_spec_seen: true,
                };
            }
            // In the retry, a ChangeCipherSpec is skipped as Go skips one
            // in TLS 1.3, and a record of another type than these two is
            // left to rustls.
            Stage::Retry { .. } if content_type != 22 && content_type != 20 => {
                self.stage = Stage::Done;
            }
            _ => {}
        }
        None
    }

    /// A client record is whole: in the retry, a ChangeCipherSpec Go
    /// would refuse is left to rustls, which refuses it too, and a whole
    /// second ClientHello is checked as Go checks it.
    fn record_done(&mut self) -> Option<GoRefusal> {
        let Stage::Retry { group } = self.stage else {
            return None;
        };
        if self.client_type == 20 {
            let change_cipher_spec = std::mem::take(&mut self.change_cipher_spec);
            if change_cipher_spec != [1] || !self.second.is_empty() {
                self.stage = Stage::Done;
            }
            return None;
        }
        let [msg_type, a, b, c, ..] = self.second[..] else {
            return None;
        };
        let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).unwrap_or(usize::MAX);
        if msg_type != 1 || len > MAX_HANDSHAKE {
            self.stage = Stage::Done;
            return None;
        }
        if self.second.len() < len.saturating_add(4) {
            return None;
        }
        self.second.truncate(len.saturating_add(4));
        // From here on Go has sent its ServerHello and protects its alerts.
        self.stage = Stage::Done;
        let second = GoClientHello::parse(&self.second)?;
        let first = self.first.as_ref()?;
        second.second_hello_refusal(first, group)
    }
}

/// What the server's first handshake record, `body`, makes of the
/// connection: a HelloRetryRequest starts the retry for the group it
/// names, a ServerHello for TLS 1.2 the TLS 1.2 checks, and anything else
/// ends them.
fn server_hello_stage(body: &[u8]) -> Stage {
    let parsed = (|| {
        let mut s = Reader(body);
        if s.u8()? != 2 {
            return None;
        }
        let [a, b, c] = [s.u8()?, s.u8()?, s.u8()?];
        let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).ok()?;
        let mut hello = Reader(s.take(len)?);
        let legacy_version = hello.u16()?;
        let random = hello.take(32)?;
        hello.vec8()?;
        hello.u16()?;
        hello.u8()?;
        let mut selected_version = None;
        let mut selected_group = None;
        if !hello.0.is_empty() {
            let mut extensions = Reader(hello.vec16()?);
            while !extensions.0.is_empty() {
                let extension = extensions.u16()?;
                let mut data = Reader(extensions.vec16()?);
                match extension {
                    43 => selected_version = Some(data.u16()?),
                    51 => selected_group = Some(data.u16()?),
                    _ => {}
                }
            }
        }
        Some((
            legacy_version,
            random == HRR_RANDOM,
            selected_version,
            selected_group,
        ))
    })();
    match parsed {
        Some((_, true, Some(0x0304), Some(group))) => Stage::Retry { group },
        Some((0x0303, false, None, _)) => Stage::Tls12 {
            change_cipher_spec_seen: false,
        },
        _ => Stage::Done,
    }
}

/// A TLS 1.3 ClientHello record offering X25519 alone, with `shares` as
/// the groups of its key shares, in a record of `record_version`, for
/// [`fuzz_record_checks`].
fn fuzz_hello(shares: &[u16], record_version: u16) -> Vec<u8> {
    let mut share_list = Vec::new();
    for group in shares {
        share_list.extend_from_slice(&group.to_be_bytes());
        share_list.extend_from_slice(&[0, 32]);
        share_list.extend_from_slice(&[9; 32]);
    }
    let mut extensions: Vec<u8> = vec![
        0, 10, 0, 4, 0, 2, 0, 0x1d, // supported_groups: X25519
        0, 13, 0, 4, 0, 2, 8, 7, // signature_algorithms: Ed25519
        0, 43, 0, 3, 2, 3, 4, // supported_versions: TLS 1.3
        0, 51, // key_share
    ];
    let shares_len = u16::try_from(share_list.len()).unwrap_or(0);
    extensions.extend_from_slice(&shares_len.saturating_add(2).to_be_bytes());
    extensions.extend_from_slice(&shares_len.to_be_bytes());
    extensions.extend_from_slice(&share_list);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&extensions);
    let len = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
    let mut message = vec![1];
    message.extend_from_slice(len.get(1..).unwrap_or_default());
    message.extend_from_slice(&body);
    let mut record = vec![22];
    record.extend_from_slice(&record_version.to_be_bytes());
    record.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// A server's first record, a HelloRetryRequest for X25519 when `retry`,
/// otherwise a TLS 1.2 ServerHello, for [`fuzz_record_checks`].
fn fuzz_server_hello(retry: bool) -> Vec<u8> {
    let mut body = vec![3, 3];
    if retry {
        body.extend_from_slice(&HRR_RANDOM);
        body.extend_from_slice(&[0, 0x13, 0x01, 0]);
        body.extend_from_slice(&[0, 12, 0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 0x1d]);
    } else {
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0xc0, 0x2b, 0]);
    }
    let len = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
    let mut message = vec![2];
    message.extend_from_slice(len.get(1..).unwrap_or_default());
    message.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// The body of the `rpc_record_checks` fuzz target: [`GoRecordChecks`]
/// over what a client controls, which never panics.  The first byte
/// picks how the rest is used, its low two bits the stage:
///
/// - 0: the rest is the connection's opening bytes, read for the first
///   ClientHello, then a HelloRetryRequest, then the rest again as the
///   client's next bytes;
/// - 1: a first ClientHello, a HelloRetryRequest for X25519, and the rest
///   as the client's next bytes, which reach the second ClientHello's
///   reader and Go's comparison;
/// - 2: a first ClientHello, a TLS 1.2 ServerHello, and the rest as the
///   client's next bytes;
/// - 3: a first ClientHello, the rest as the server's bytes, and a second
///   ClientHello from the client.
///
/// Its high six bits, plus one, are the size of the pieces the client's
/// bytes are fed in, each refusal's offset held within its piece.
/// Whether the checks refused anything.  For the fuzz target only; not
/// part of the API.
#[doc(hidden)]
pub fn fuzz_record_checks(data: &[u8]) -> bool {
    let Some((&mode, rest)) = data.split_first() else {
        return false;
    };
    let piece = usize::from(mode >> 2).saturating_add(1);
    let feed = |checks: &mut GoRecordChecks, bytes: &[u8]| {
        for chunk in bytes.chunks(piece) {
            if let Some((at, refusal)) = checks.client_sent(chunk) {
                assert!(at <= chunk.len(), "a refusal past its piece");
                assert!(
                    matches!(refusal.alert, 22 | 47 | 70),
                    "an alert Go does not send here"
                );
                return true;
            }
        }
        false
    };
    match mode & 3 {
        0 => {
            let mut checks = GoRecordChecks::new(rest);
            checks.server_sent(&fuzz_server_hello(true));
            feed(&mut checks, rest)
        }
        1 | 2 => {
            let mut checks = GoRecordChecks::new(&fuzz_hello(&[], 0x0301));
            checks.server_sent(&fuzz_server_hello(mode & 3 == 1));
            feed(&mut checks, rest)
        }
        _ => {
            let mut checks = GoRecordChecks::new(&fuzz_hello(&[], 0x0301));
            checks.server_sent(rest);
            feed(&mut checks, &fuzz_hello(&[0x001d], 0x0303))
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn len8(bytes: &[u8]) -> Vec<u8> {
        [&[u8::try_from(bytes.len()).expect("short")][..], bytes].concat()
    }

    fn len16(bytes: &[u8]) -> Vec<u8> {
        let len = u16::try_from(bytes.len()).expect("short").to_be_bytes();
        [&len[..], bytes].concat()
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        [&kind.to_be_bytes()[..], &len16(data)].concat()
    }

    fn message(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).expect("short").to_be_bytes();
        [&[msg_type][..], &len[1..], body].concat()
    }

    fn record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
        [&[content_type][..], &version.to_be_bytes(), &len16(body)].concat()
    }

    /// A TLS 1.3 ClientHello's message: X25519 offered, `shares` its key
    /// shares' groups, with `extra` extensions after the usual ones.
    fn hello_message(random: u8, shares: &[u16], extra: &[Vec<u8>]) -> Vec<u8> {
        let share_list: Vec<u8> = shares
            .iter()
            .flat_map(|group| [&group.to_be_bytes()[..], &len16(&[9; 32])].concat())
            .collect();
        let mut extensions = vec![
            extension(0, &len16(&[&[0][..], &len16(b"localhost")].concat())),
            extension(10, &len16(&[0x00, 0x1d, 0x00, 0x17])),
            extension(13, &len16(&[0x04, 0x03, 0x08, 0x07])),
            extension(43, &len8(&[0x03, 0x04])),
            extension(51, &len16(&share_list)),
        ];
        extensions.extend(extra.iter().cloned());
        let body = [
            &[0x03, 0x03][..],
            &[random; 32],
            &len8(&[]),
            &len16(&[0x13, 0x01]),
            &len8(&[0]),
            &len16(&extensions.concat()),
        ]
        .concat();
        message(1, &body)
    }

    /// A ServerHello's message, a HelloRetryRequest when `retry`, with
    /// supported_versions and key_share when given.
    fn server_hello(retry: bool, version: Option<u16>, group: Option<u16>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(version) = version {
            extensions.push(extension(43, &version.to_be_bytes()));
        }
        if let Some(group) = group {
            extensions.push(extension(51, &group.to_be_bytes()));
        }
        let random = if retry { HRR_RANDOM } else { [7; 32] };
        let body = [
            &[0x03, 0x03][..],
            &random,
            &len8(&[]),
            &[0x13, 0x01],
            &[0],
            &len16(&extensions.concat()),
        ]
        .concat();
        message(2, &body)
    }

    /// Checks past a HelloRetryRequest for X25519 after `first`.
    fn retried(first: &[u8]) -> GoRecordChecks {
        let mut checks = GoRecordChecks::new(&record(22, 0x0301, first));
        checks.server_sent(&record(
            22,
            0x0303,
            &server_hello(true, Some(0x0304), Some(0x001d)),
        ));
        assert_eq!(checks.stage, Stage::Retry { group: 0x001d });
        checks
    }

    /// Go's reader of a ClientHello takes what its `unmarshal` takes and
    /// refuses what it refuses: a duplicate extension, bytes after a known
    /// extension's contents, an empty list where Go requires entries, a
    /// trailing dot in the server name, two host names, and a
    /// pre_shared_key that is not last; and it ignores an unknown
    /// extension's contents, a server name of another type, and reads the
    /// renegotiation SCSV as renegotiation_info.
    #[test]
    fn the_client_hello_reads_as_gos_unmarshal() {
        let base = GoClientHello::parse(&hello_message(1, &[0x001d], &[])).expect("a hello");
        assert_eq!(base.vers, 0x0303);
        assert_eq!(base.server_name, b"localhost");
        assert_eq!(base.supported_curves, [0x001d, 0x0017]);
        assert_eq!(base.key_shares, [0x001d]);
        assert!(!base.secure_renegotiation_supported);
        let refused = [
            ("a duplicate", vec![extension(10, &len16(&[0x00, 0x1d]))]),
            (
                "bytes after ALPN",
                vec![extension(16, &[0, 3, 2, b'h', b'2', 0])],
            ),
            ("an empty ALPN list", vec![extension(16, &len16(&[]))]),
            ("an empty protocol", vec![extension(16, &len16(&[0]))]),
            ("an empty cookie", vec![extension(44, &len16(&[]))]),
            ("an odd version list", vec![extension(50, &len16(&[4]))]),
            ("early_data with contents", vec![extension(42, &[0])]),
            (
                "pre_shared_key before another",
                vec![
                    extension(41, &[0, 7, 0, 1, 1, 0, 0, 0, 0, 0, 2, 1, 1]),
                    extension(45, &len8(&[1])),
                ],
            ),
        ];
        for (what, extra) in refused {
            assert_eq!(
                GoClientHello::parse(&hello_message(1, &[0x001d], &extra)),
                None,
                "{what}"
            );
        }
        let dotted = [
            &[0x03, 0x03][..],
            &[1; 32],
            &len8(&[]),
            &len16(&[0x13, 0x01]),
            &len8(&[0]),
            &len16(&extension(0, &len16(&[&[0][..], &len16(b"a.")].concat()))),
        ]
        .concat();
        assert_eq!(GoClientHello::parse(&message(1, &dotted)), None);
        let two_names = [
            &[0x03, 0x03][..],
            &[1; 32],
            &len8(&[]),
            &len16(&[0x13, 0x01]),
            &len8(&[0]),
            &len16(&extension(
                0,
                &len16(&[&[0][..], &len16(b"a"), &[0], &len16(b"b")].concat()),
            )),
        ]
        .concat();
        assert_eq!(GoClientHello::parse(&message(1, &two_names)), None);
        let taken = GoClientHello::parse(&hello_message(
            1,
            &[0x001d],
            &[
                extension(0x7a7a, &[1, 2, 3]),
                extension(0xff01, &len8(&[])),
                extension(41, &[0, 7, 0, 1, 1, 0, 0, 0, 0, 0, 2, 1, 1]),
            ],
        ))
        .expect("taken");
        assert!(taken.secure_renegotiation_supported);
        let mut scsv = hello_message(1, &[0x001d], &[]);
        // The suite list's one suite becomes the SCSV.
        let at = 4 + 2 + 32 + 1 + 2;
        scsv[at..at + 2].copy_from_slice(&[0x00, 0xff]);
        assert!(
            GoClientHello::parse(&scsv)
                .expect("an SCSV hello")
                .secure_renegotiation_supported
        );
        // A second name of another type is passed over.
        let other_type = [
            &[0x03, 0x03][..],
            &[1; 32],
            &len8(&[]),
            &len16(&[0x13, 0x01]),
            &len8(&[0]),
            &len16(&extension(
                0,
                &len16(&[&[0][..], &len16(b"a"), &[1], &len16(b"b")].concat()),
            )),
        ]
        .concat();
        assert_eq!(
            GoClientHello::parse(&message(1, &other_type))
                .expect("taken")
                .server_name,
            b"a"
        );
    }

    /// Each field `illegalClientHelloChange` compares refuses a second
    /// ClientHello that changes it, and the key share and the fields Go
    /// does not compare do not; the key share's count and group and
    /// early_data are refused first, each with its own text.
    #[test]
    fn a_second_hello_is_held_to_gos_comparison() {
        let first = GoClientHello::parse(&hello_message(1, &[], &[])).expect("first");
        let second = |random: u8, shares: &[u16], extra: &[Vec<u8>]| {
            GoClientHello::parse(&hello_message(random, shares, extra)).expect("second")
        };
        let refusal = |hello: &GoClientHello| {
            hello
                .second_hello_refusal(&first, 0x001d)
                .map(|refusal| (refusal.alert, refusal.text))
        };
        assert_eq!(refusal(&second(1, &[0x001d], &[])), None);
        // Fields Go reads and does not compare.
        assert_eq!(
            refusal(&second(
                1,
                &[0x001d],
                &[extension(23, &[]), extension(21, &[0; 9])]
            )),
            None
        );
        let changed = "tls: client illegally modified second ClientHello";
        let cases: Vec<(&str, GoClientHello)> = vec![
            ("random", second(2, &[0x001d], &[])),
            (
                "ALPN",
                second(1, &[0x001d], &[extension(16, &len16(&len8(b"h2")))]),
            ),
            (
                "cookie",
                second(1, &[0x001d], &[extension(44, &len16(&[1]))]),
            ),
            (
                "psk modes",
                second(1, &[0x001d], &[extension(45, &len8(&[1]))]),
            ),
            ("SCT", second(1, &[0x001d], &[extension(18, &[])])),
            (
                "status_request",
                second(1, &[0x001d], &[extension(5, &[1, 0, 0, 0, 0])]),
            ),
            (
                "session ticket",
                second(1, &[0x001d], &[extension(35, &[])]),
            ),
            (
                "point formats",
                second(1, &[0x001d], &[extension(11, &len8(&[0]))]),
            ),
            (
                "signature_algorithms_cert",
                second(1, &[0x001d], &[extension(50, &len16(&[4, 3]))]),
            ),
            (
                "renegotiation_info",
                second(1, &[0x001d], &[extension(0xff01, &len8(&[]))]),
            ),
        ];
        for (what, hello) in &cases {
            assert_eq!(refusal(hello), Some((47, changed.to_string())), "{what}");
        }
        // The session id and versions, written over a copy.
        let mut session = second(1, &[0x001d], &[]);
        session.session_id = vec![1];
        assert_eq!(refusal(&session), Some((47, changed.to_string())));
        let mut legacy = second(1, &[0x001d], &[]);
        legacy.vers = 0x0301;
        assert_eq!(refusal(&legacy), Some((47, changed.to_string())));
        assert_eq!(
            refusal(&second(2, &[], &[])),
            Some((
                47,
                "tls: client didn't send one key share in second ClientHello".to_string()
            ))
        );
        assert_eq!(
            refusal(&second(2, &[0x001d, 0x0017], &[])),
            Some((
                47,
                "tls: client didn't send one key share in second ClientHello".to_string()
            ))
        );
        assert_eq!(
            refusal(&second(2, &[0x0017], &[])),
            Some((
                47,
                "tls: client sent unexpected key share in second ClientHello".to_string()
            ))
        );
        assert_eq!(
            refusal(&second(2, &[0x001d], &[extension(42, &[])])),
            Some((
                47,
                "tls: client indicated early data in second ClientHello".to_string()
            ))
        );
    }

    /// The server's first record sets what is checked: a HelloRetryRequest
    /// the retry, for the group it names; a TLS 1.2 ServerHello the TLS
    /// 1.2 records; a TLS 1.3 ServerHello, or anything else, nothing.
    #[test]
    fn the_servers_first_record_sets_the_checks() {
        let hello = record(22, 0x0301, &hello_message(1, &[], &[]));
        let stage = |server: &[u8]| {
            let mut checks = GoRecordChecks::new(&hello);
            // One byte at a time, as a write may split it.
            for byte in server {
                checks.server_sent(std::slice::from_ref(byte));
            }
            checks.stage
        };
        assert_eq!(
            stage(&record(
                22,
                0x0303,
                &server_hello(true, Some(0x0304), Some(0x0017))
            )),
            Stage::Retry { group: 0x0017 }
        );
        assert_eq!(
            stage(&record(22, 0x0303, &server_hello(false, None, None))),
            Stage::Tls12 {
                change_cipher_spec_seen: false
            }
        );
        assert_eq!(
            stage(&record(
                22,
                0x0303,
                &server_hello(false, Some(0x0304), Some(0x001d))
            )),
            Stage::Done
        );
        assert_eq!(stage(&record(21, 0x0303, &[2, 40])), Stage::Done);
        assert_eq!(GoRecordChecks::new(b"not a hello").stage, Stage::Done);
        assert_eq!(GoRecordChecks::off().stage, Stage::Done);
    }

    /// After a HelloRetryRequest every record up to the end of the second
    /// ClientHello is held to Go's record version and length, a
    /// ChangeCipherSpec is passed over, and the second ClientHello,
    /// across records or in one, is refused at the offset of the record
    /// that completes it; nothing after it is checked.
    #[test]
    fn the_retry_is_checked_record_by_record() {
        let first = hello_message(1, &[], &[]);
        let ccs = record(20, 0x0303, &[1]);
        let changed = hello_message(2, &[0x001d], &[]);

        let mut checks = retried(&first);
        let bytes = [ccs.clone(), record(22, 0x0303, &changed)].concat();
        let (at, refusal) = checks.client_sent(&bytes).expect("refused");
        assert_eq!(at, ccs.len());
        assert_eq!(refusal.alert, 47);
        assert_eq!(refusal.record(), [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 47]);

        // Split over two records and fed a byte at a time.
        let mut checks = retried(&first);
        let (head, tail) = changed.split_at(10);
        let bytes = [record(22, 0x0303, head), record(22, 0x0303, tail)].concat();
        let mut refused = None;
        for (i, byte) in bytes.iter().enumerate() {
            if let Some((at, refusal)) = checks.client_sent(std::slice::from_ref(byte)) {
                refused = Some((i, at, refusal.text));
                break;
            }
        }
        assert_eq!(
            refused,
            Some((
                bytes.len() - 1,
                0,
                "tls: client illegally modified second ClientHello".to_string()
            ))
        );

        // An unchanged second hello passes, and a record after it in
        // another version is not checked.
        let mut checks = retried(&first);
        let same = hello_message(1, &[0x001d], &[]);
        let bytes = [record(22, 0x0303, &same), record(23, 0x0301, &[0; 4])].concat();
        assert_eq!(checks.client_sent(&bytes), None);
        assert_eq!(checks.stage, Stage::Done);

        // A record of another version, the ChangeCipherSpec or the hello.
        for (what, bytes, at) in [
            (
                "CCS",
                [record(20, 0x0301, &[1]), record(22, 0x0303, &same)].concat(),
                0,
            ),
            (
                "hello",
                [ccs.clone(), record(22, 0x0301, &same)].concat(),
                ccs.len(),
            ),
        ] {
            let mut checks = retried(&first);
            let (offset, refusal) = checks.client_sent(&bytes).expect(what);
            assert_eq!(offset, at, "{what}");
            assert_eq!(
                (refusal.alert, refusal.text.as_str(), refusal.record()),
                (
                    70,
                    "tls: received record with version 301 when expecting version 303",
                    [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 70]
                ),
                "{what}"
            );
        }

        // A TLS 1.3 record past 2^14 + 256 bytes, on its header alone.
        let mut checks = retried(&first);
        let (_, refusal) = checks
            .client_sent(&[22, 3, 3, 0x41, 0x01])
            .expect("oversized");
        assert_eq!(
            (refusal.alert, refusal.text.as_str()),
            (22, "tls: oversized record received with length 16641")
        );

        // A malformed ChangeCipherSpec, an alert, or a hello Go cannot
        // read are left to rustls.
        for bytes in [
            [record(20, 0x0303, &[2]), record(22, 0x0303, &changed)].concat(),
            [record(21, 0x0303, &[2, 40]), record(22, 0x0303, &changed)].concat(),
            record(22, 0x0303, &message(1, &[3, 3])),
        ] {
            let mut checks = retried(&first);
            assert_eq!(checks.client_sent(&bytes), None);
            assert_eq!(checks.stage, Stage::Done);
        }
    }

    /// In TLS 1.2 the client's records are held to Go's version and
    /// length up to its Finished, the record after its ChangeCipherSpec,
    /// or until the server's own ChangeCipherSpec; bytes the client sent
    /// before the server's flight are checked once it is seen.
    #[test]
    fn tls12_records_are_checked_to_the_finished() {
        let hello = record(22, 0x0301, &hello_message(1, &[0x001d], &[]));
        let server = record(22, 0x0303, &server_hello(false, None, None));
        let tls12 = |opening: &[u8]| {
            let mut checks = GoRecordChecks::new(opening);
            checks.server_sent(&server);
            checks
        };
        let wrong = "tls: received record with version 301 when expecting version 303";

        let mut checks = tls12(&hello);
        let flight = [
            record(22, 0x0303, &[16, 0, 0, 1, 0]),
            record(20, 0x0303, &[1]),
        ]
        .concat();
        assert_eq!(checks.client_sent(&flight), None);
        let (at, refusal) = checks
            .client_sent(&record(22, 0x0301, &[0; 16]))
            .expect("the Finished");
        assert_eq!((at, refusal.text.as_str()), (0, wrong));

        let mut checks = tls12(&hello);
        assert_eq!(
            checks.client_sent(
                &[
                    record(20, 0x0303, &[1]),
                    record(22, 0x0303, &[0; 16]),
                    record(23, 0x0301, &[0; 4]),
                ]
                .concat()
            ),
            None
        );

        let mut checks = tls12(&hello);
        checks.server_sent(&record(20, 0x0303, &[1]));
        assert_eq!(checks.client_sent(&record(22, 0x0301, &[0; 16])), None);

        let mut checks = tls12(&hello);
        let (_, refusal) = checks
            .client_sent(&[22, 3, 3, 0x48, 0x01])
            .expect("oversized");
        assert_eq!(
            refusal.text,
            "tls: oversized record received with length 18433"
        );

        // Sent before the server's flight, behind the first hello.
        let opening = [hello.clone(), record(22, 0x0301, &[0; 4])].concat();
        let mut checks = tls12(&opening);
        assert_eq!(
            checks
                .client_sent(&[])
                .map(|(at, refusal)| (at, refusal.text)),
            Some((0, wrong.to_string()))
        );
    }

    /// The checks answer the same whatever pieces the client's bytes come
    /// in, over random records after a HelloRetryRequest and in TLS 1.2,
    /// each refusal at the offset, within its piece, of the record it
    /// refuses; and the fuzz body's fixed messages are the ones its
    /// documentation names.
    #[test]
    fn the_checks_do_not_depend_on_how_the_bytes_are_cut() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let first = fuzz_hello(&[], 0x0301);
        assert!(GoRecordChecks::new(&first).first.is_some());
        let mut retried = GoRecordChecks::new(&first);
        retried.server_sent(&fuzz_server_hello(true));
        assert_eq!(retried.stage, Stage::Retry { group: 0x001d });
        assert_eq!(retried.client_sent(&fuzz_hello(&[0x001d], 0x0303)), None);
        assert_eq!(retried.stage, Stage::Done);
        for round in 0..2000 {
            let retry = round % 2 == 0;
            // A few records: CCS, handshake fragments of a second hello,
            // others, in TLS 1.2's version mostly.
            let mut bytes = Vec::new();
            let mut second = hello_message(1 + (next() % 2) as u8, &[0x001d], &[]);
            if next() % 3 == 0 {
                let at = next() as usize % second.len();
                second[at] ^= 1 << (next() % 8);
            }
            for _ in 0..(1 + next() % 4) {
                let version = if next() % 6 == 0 { 0x0301 } else { 0x0303 };
                match next() % 4 {
                    0 => bytes.extend(record(20, version, &[1])),
                    1 if !second.is_empty() => {
                        let cut = 1 + next() as usize % second.len();
                        let fragment: Vec<u8> = second.drain(..cut).collect();
                        bytes.extend(record(22, version, &fragment));
                    }
                    2 => bytes.extend(record(21, version, &[2, 40])),
                    _ => bytes.extend(record(22, version, &[16, 0, 0, 1, 0])),
                }
            }
            let run = |pieces: &[usize]| {
                let mut checks = GoRecordChecks::new(&first);
                checks.server_sent(&fuzz_server_hello(retry));
                let mut at = 0;
                for &piece in pieces {
                    let end = (at + piece).min(bytes.len());
                    if let Some((offset, refusal)) = checks.client_sent(&bytes[at..end]) {
                        assert!(offset <= end - at);
                        return Some((at + offset, refusal.text));
                    }
                    at = end;
                }
                None
            };
            let whole = run(&[bytes.len()]);
            let mut pieces = Vec::new();
            let mut left = bytes.len();
            while left > 0 {
                let piece = 1 + next() as usize % left.min(9);
                pieces.push(piece);
                left -= piece;
            }
            let cut = run(&pieces);
            // A refusal found in one piece points at its record's start
            // in that piece, or at zero for a record begun before it.
            assert_eq!(
                whole.as_ref().map(|(_, text)| text),
                cut.as_ref().map(|(_, text)| text),
                "round {round}"
            );
            if let (Some((whole_at, _)), Some((cut_at, _))) = (&whole, &cut) {
                assert!(
                    cut_at <= &bytes.len() && whole_at <= cut_at,
                    "round {round}"
                );
            }
        }
        for mode in 0..=255u8 {
            let _ = fuzz_record_checks(&[mode, 22, 3, 3, 0, 1, 1]);
        }
    }
}
