// SPDX-License-Identifier: ISC
//! Pure helper functions shared by the RPC handlers (dcrd
//! internal/rpcserver `rpcserver.go`).

// Bounded conversions over fixed-size buffers mirror Go.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::{HASH_SIZE, Hash};
use dcroxide_dcrjson::RPCError;
use dcroxide_wire::BlockHeader;
use num_bigint::BigInt;

use crate::rpcerrors::rpc_decode_hex_error;

/// The size in bytes of a 256-bit value (dcrd `uint256Size`).
pub const UINT256_SIZE: usize = 32;

/// The getwork data length for blake256: the header plus internal
/// blake256 padding (dcrd `getworkDataLenBlake256`).
pub const GETWORK_DATA_LEN_BLAKE256: usize =
    (1 + ((MAX_BLOCK_HEADER_PAYLOAD * 8 + 65) / (64 * 8))) * 64;

/// The getwork data length for blake3: the header padded to the
/// blake3 block size (dcrd `getworkDataLenBlake3`).
pub const GETWORK_DATA_LEN_BLAKE3: usize = MAX_BLOCK_HEADER_PAYLOAD.div_ceil(64) * 64;

/// The wire block header size (Go `wire.MaxBlockHeaderPayload`).
const MAX_BLOCK_HEADER_PAYLOAD: usize = 180;

/// The size of the merkle root plus stake root template key (dcrd
/// `merkleRootPairSize`).
pub const MERKLE_ROOT_PAIR_SIZE: usize = 64;

/// A string representing the direction of a connection (dcrd
/// `directionString`).
pub fn direction_string(inbound: bool) -> &'static str {
    if inbound { "inbound" } else { "outbound" }
}

/// The result of looking up a host as a local network interface name
/// (Go `net.InterfaceByName` + `Addrs`), injectable because it is
/// system state.  `None` means the host is not an interface name.
pub trait InterfaceLookup {
    /// The interface's index and first address in CIDR form, when the
    /// host names an interface with addresses.
    fn interface_addr(&mut self, name: &str) -> Option<(u32, String)>;
}

/// An interface lookup for systems where handlers never pass
/// interface names (the common case) or where the lookup is
/// unavailable.
pub struct NoInterfaces;

impl InterfaceLookup for NoInterfaces {
    fn interface_addr(&mut self, _name: &str) -> Option<(u32, String)> {
        None
    }
}

/// Return a host:port form of the address with the default port added
/// when one is missing, substituting the address of a local interface
/// when the host names one (dcrd `normalizeAddress`).
pub fn normalize_address<L: InterfaceLookup + ?Sized>(
    lookup: &mut L,
    addr: &str,
    default_port: &str,
) -> String {
    let mut host = addr.to_string();
    let mut port = default_port.to_string();
    if let Ok((a, p)) = split_host_port(addr) {
        host = a;
        port = p;
    }
    let Some((index, cidr)) = lookup.interface_addr(&host) else {
        return join_host_port(&host, &port);
    };
    let Some((ip_str, _)) = cidr.rsplit_once('/') else {
        return join_host_port(&host, &port);
    };
    let mut dial_addr = ip_str.to_string();
    if let Ok(std::net::IpAddr::V6(v6)) = ip_str.parse::<std::net::IpAddr>() {
        // Link-local addresses need the interface zone.
        let seg = v6.segments();
        let link_local_unicast = seg[0] & 0xffc0 == 0xfe80;
        let link_local_multicast = seg[0] & 0xff0f == 0xff02;
        if link_local_unicast || link_local_multicast {
            dial_addr = format!("{dial_addr}%{index}");
        }
    }
    join_host_port(&dial_addr, &port)
}

/// Go `net.JoinHostPort`.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Go `net.SplitHostPort` success cases (errors keep the original
/// address exactly as `normalizeAddress` does).
pub(crate) fn split_host_port(hostport: &str) -> Result<(String, String), ()> {
    if let Some(stripped) = hostport.strip_prefix('[') {
        let end = stripped.find(']').ok_or(())?;
        let rest = &stripped[end + 1..];
        let port = rest.strip_prefix(':').ok_or(())?;
        if port.contains(':') {
            return Err(());
        }
        return Ok((stripped[..end].to_string(), port.to_string()));
    }
    let colon = hostport.rfind(':').ok_or(())?;
    let host = &hostport[..colon];
    let port = &hostport[colon + 1..];
    if host.contains(':') || hostport.contains('[') || hostport.contains(']') {
        return Err(());
    }
    Ok((host.to_string(), port.to_string()))
}

/// Decode hash strings that are NOT byte-reversed on top of requiring
/// the full length (dcrd `decodeHashes`).
pub fn decode_hashes(strs: &[String]) -> Result<Vec<Hash>, RPCError> {
    let mut hashes = Vec::with_capacity(strs.len());
    for s in strs {
        if s.len() != 2 * HASH_SIZE {
            return Err(rpc_decode_hex_error(s));
        }
        let mut hash = [0u8; HASH_SIZE];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16);
            let lo = (chunk[1] as char).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => hash[i] = ((hi << 4) | lo) as u8,
                _ => return Err(rpc_decode_hex_error(s)),
            }
        }
        // Unreverse the hash string bytes.
        hash.reverse();
        hashes.push(Hash(hash));
    }
    Ok(hashes)
}

/// Decode standard byte-reversed hash strings (dcrd
/// `decodeHashPointers` over `chainhash.NewHashFromStr`).
pub fn decode_hash_pointers(strs: &[String]) -> Result<Vec<Hash>, RPCError> {
    let mut hashes = Vec::with_capacity(strs.len());
    for s in strs {
        match s.parse::<Hash>() {
            Ok(h) => hashes.push(h),
            Err(_) => return Err(rpc_decode_hex_error(s)),
        }
    }
    Ok(hashes)
}

/// The proof-of-work difficulty as a multiple of the minimum
/// difficulty (dcrd `getDifficultyRatio`): the ratio is rendered
/// through a big rational with eight decimal places and parsed back
/// to a float, exactly like dcrd.
pub fn get_difficulty_ratio(bits: u32, pow_limit_bits: u32) -> f64 {
    let max = dcroxide_standalone::compact_to_big(pow_limit_bits);
    let target = dcroxide_standalone::compact_to_big(bits);
    if target.sign() == num_bigint::Sign::NoSign {
        // A zero target would make the rational undefined; dcrd would
        // panic constructing the Rat, which no valid header reaches.
        return 0.0;
    }

    // big.Rat FloatString(8): round the scaled quotient to nearest
    // with ties away from zero.
    let scale = BigInt::from(100_000_000i64);
    let scaled = max * &scale;
    let doubled = &scaled * 2 + &target * sign_of(&scaled);
    let q: BigInt = doubled / (&target * 2);
    let negative = q.sign() == num_bigint::Sign::Minus;
    let q = q.magnitude().to_string();
    let (int_part, frac_part) = if q.len() > 8 {
        (q[..q.len() - 8].to_string(), q[q.len() - 8..].to_string())
    } else {
        ("0".to_string(), format!("{q:0>8}"))
    };
    let s = format!("{}{int_part}.{frac_part}", if negative { "-" } else { "" });
    s.parse().unwrap_or(0.0)
}

fn sign_of(n: &BigInt) -> i32 {
    match n.sign() {
        num_bigint::Sign::Minus => -1,
        _ => 1,
    }
}

/// Convert a threshold state to the agenda status string the JSON
/// results carry (dcrd `thresholdStateToAgendaStatus`).
pub fn threshold_state_to_agenda_status(state: threshold::State) -> &'static str {
    state.status_string()
}

/// Convert a version:count map into the sorted list the stake version
/// results carry (dcrd `convertVersionMap`).
pub fn convert_version_map(m: &std::collections::HashMap<i64, i64>) -> Vec<(u32, u32)> {
    let mut order: Vec<i64> = m.keys().copied().collect();
    order.sort_unstable();
    order
        .into_iter()
        .map(|v| (v as u32, m[&v] as u32))
        .collect()
}

/// Pad or truncate a big-endian integer to 32 bytes and reverse it to
/// little endian (dcrd `bigToLEUint256`).
pub fn big_to_le_uint256(n: &BigInt) -> [u8; UINT256_SIZE] {
    let n_bytes = n.magnitude().to_bytes_be();
    let nlen = n_bytes.len();
    let (pad, start) = if nlen <= UINT256_SIZE {
        (UINT256_SIZE - nlen, 0)
    } else {
        (0, nlen - UINT256_SIZE)
    };
    let mut buf = [0u8; UINT256_SIZE];
    buf[pad..].copy_from_slice(&n_bytes[start..]);
    buf.reverse();
    buf
}

/// The template key for getwork data: the merkle root and stake root
/// fields (dcrd `getWorkTemplateKey`).
pub fn get_work_template_key(header: &BlockHeader) -> [u8; MERKLE_ROOT_PAIR_SIZE] {
    let mut pair = [0u8; MERKLE_ROOT_PAIR_SIZE];
    pair[..HASH_SIZE].copy_from_slice(header.merkle_root.as_bytes());
    pair[HASH_SIZE..].copy_from_slice(header.stake_root.as_bytes());
    pair
}

/// Serialized data representing work to be solved for the getwork RPC
/// and notifywork notification (dcrd `serializeGetWorkData`): the
/// serialized header followed by the internal padding of the active
/// proof-of-work hash function.
pub fn serialize_get_work_data(
    header: &BlockHeader,
    is_blake3_pow_active: bool,
) -> Result<Vec<u8>, RPCError> {
    let (data_len, pad) = if is_blake3_pow_active {
        (GETWORK_DATA_LEN_BLAKE3, blake3_pad())
    } else {
        (GETWORK_DATA_LEN_BLAKE256, blake256_pad())
    };

    let mut data = header.serialize().to_vec();
    data.resize(data_len, 0);
    data[MAX_BLOCK_HEADER_PAYLOAD..].copy_from_slice(&pad);
    Ok(data)
}

/// The blake256 internal padding (dcrd `blake256Pad`, computed at
/// init).
fn blake256_pad() -> Vec<u8> {
    let mut pad = vec![0u8; GETWORK_DATA_LEN_BLAKE256 - MAX_BLOCK_HEADER_PAYLOAD];
    pad[0] = 0x80;
    let len = pad.len();
    pad[len - 9] |= 0x01;
    let bits = (MAX_BLOCK_HEADER_PAYLOAD * 8) as u64;
    pad[len - 8..].copy_from_slice(&bits.to_be_bytes());
    pad
}

/// The blake3 internal padding: all zeros (dcrd `blake3Pad`).
fn blake3_pad() -> Vec<u8> {
    vec![0u8; GETWORK_DATA_LEN_BLAKE3 - MAX_BLOCK_HEADER_PAYLOAD]
}

/// The threshold states as the RPC layer needs them, decoupled from
/// the blockchain crate's internal representation.
pub mod threshold {
    /// The agenda threshold states (dcrd `blockchain.ThresholdState`).
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum State {
        /// The first state, before the start time.
        Defined,
        /// Voting has started.
        Started,
        /// The vote met the threshold and is locked in.
        LockedIn,
        /// The agenda is active.
        Active,
        /// The agenda failed.
        Failed,
        /// An unrecognized state, mapped like dcrd's default case.
        Invalid,
    }

    impl State {
        /// The status string (dcrd `thresholdStateToAgendaStatus`,
        /// which maps unknown states to defined).
        pub fn status_string(self) -> &'static str {
            match self {
                State::Defined => "defined",
                State::Started => "started",
                State::LockedIn => "lockedin",
                State::Active => "active",
                State::Failed => "failed",
                State::Invalid => "defined",
            }
        }
    }
}
