// SPDX-License-Identifier: ISC
//! Pure helper functions shared by the RPC handlers (dcrd
//! internal/rpcserver `rpcserver.go`).

// Bounded conversions over fixed-size buffers mirror Go.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::{HASH_SIZE, Hash, HashError};
use dcroxide_dcrjson::RPCError;
use dcroxide_wire::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD};
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

/// The size of the merkle root plus stake root template key (dcrd
/// `merkleRootPairSize`).
pub const MERKLE_ROOT_PAIR_SIZE: usize = 64;

/// The number of blocks below the current best height to begin
/// pruning old block work from the template pool (dcrd
/// `getworkExpirationDiff`).
pub const GETWORK_EXPIRATION_DIFF: i64 = 3;

impl crate::server::WorkState {
    /// Prune every template more than [`GETWORK_EXPIRATION_DIFF`] blocks
    /// below the best height from the template pool (dcrd
    /// `workState.pruneOldBlockTemplates`).  Both callers, the getwork
    /// request and the websocket work notification, run this one copy,
    /// as in dcrd; the caller holds the work state lock.
    pub(crate) fn prune_old_block_templates(&mut self, best_height: i64) {
        let prune_height = best_height - GETWORK_EXPIRATION_DIFF;
        self.template_pool
            .retain(|_, block| i64::from(block.header.height) >= prune_height);
    }
}

/// Go's `hex.InvalidByteError` text for the offending byte,
/// `encoding/hex: invalid byte: %#U`.  The `%#U` verb writes `U+%04X`
/// and then the character between single quotes, raw and unescaped,
/// only when `strconv.IsPrint` accepts it; over the Latin-1 range a
/// byte covers, that is space through `~` and U+00A1 through U+00FF
/// except the soft hyphen U+00AD.  Rust's char `Debug` is no stand-in:
/// it escapes `'` and `\` and quotes the control characters Go leaves
/// bare.
pub fn go_hex_invalid_byte_error(b: u8) -> String {
    let mut text = format!("encoding/hex: invalid byte: U+{b:04X}");
    if (0x20..=0x7e).contains(&b) || (b >= 0xa1 && b != 0xad) {
        text.push_str(" '");
        text.push(char::from(b));
        text.push('\'');
    }
    text
}

/// The error text of dcrd's `chainhash.Decode` (and so of
/// `NewHashFromStr`): `ErrHashStrSize` for an overlong string, or Go's
/// `hex.InvalidByteError` for the first byte that is not a hex digit.
/// The chainhash crate's `Display` renders the same texts, which the
/// node's `--assumevalid` error prints directly.
pub fn go_hash_decode_error(e: HashError) -> String {
    match e {
        HashError::InvalidHexByte(b) => go_hex_invalid_byte_error(b),
        HashError::StrSize => e.to_string(),
    }
}

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
    fn interface_addr(&self, name: &str) -> Option<(u32, String)>;
}

/// An interface lookup for systems where handlers never pass
/// interface names (the common case) or where the lookup is
/// unavailable.
pub struct NoInterfaces;

impl InterfaceLookup for NoInterfaces {
    fn interface_addr(&self, _name: &str) -> Option<(u32, String)> {
        None
    }
}

/// Return a host:port form of the address with the default port added
/// when one is missing, substituting the address of a local interface
/// when the host names one (dcrd `normalizeAddress`).
pub fn normalize_address<L: InterfaceLookup + ?Sized>(
    lookup: &L,
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

    // big.Rat FloatString(8): round the magnitude of the scaled
    // quotient half up (ties away from zero), then prefix the sign of
    // the rational -- negative when exactly one of the operands is,
    // and never for a zero numerator, which `SetFrac` normalizes to
    // non-negative.  A negative value that rounds to zero keeps its
    // sign ("-0.00000000"), which parses to -0.
    let negative = max.sign() != num_bigint::Sign::NoSign && max.sign() != target.sign();
    let scale = num_bigint::BigUint::from(100_000_000u64);
    let scaled = max.magnitude() * &scale;
    let divisor = target.magnitude();
    let q = (scaled * 2u32 + divisor) / (divisor * 2u32);
    let q = q.to_string();
    let (int_part, frac_part) = if q.len() > 8 {
        (q[..q.len() - 8].to_string(), q[q.len() - 8..].to_string())
    } else {
        ("0".to_string(), format!("{q:0>8}"))
    };
    let s = format!("{}{int_part}.{frac_part}", if negative { "-" } else { "" });
    s.parse().unwrap_or(0.0)
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
/// proof-of-work hash function.  This is the one copy both callers run
/// (`handlers::handle_get_work_request` and the websocket work
/// notification), as in dcrd.  The error is dcrd's signature; header
/// serialization into memory cannot fail, so it is never returned.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// dcrd's `getDifficultyRatio` goes through `big.Rat.FloatString(8)`,
    /// which rounds the magnitude and then prefixes the sign.  The port
    /// took the rounding offset's sign from the always-positive
    /// numerator, so every negative target (sign bit set in the compact
    /// bits) came out one unit of 1e-8 short in magnitude, exact ratios
    /// included.  Expected values from Go 1.26 over dcrd's
    /// `CompactToBig`, against the mainnet proof-of-work limit, as
    /// float64 bit patterns.  No chain header reaches the negative case
    /// (the proof-of-work range check rejects it), so this is latent.
    #[test]
    fn negative_targets_round_the_magnitude_like_float_string() {
        let pow_limit_bits = 0x1d00_ffff;
        for (bits, want) in [
            (0x1c80_ffffu32, 0xc070_0000_0000_0000u64), // -256.00000000
            (0x1c81_2345, 0xc06c_1fed_df5b_f097),       // -224.99778717
            (0x1b84_04cb, 0xc0cf_d9b5_e150_3c83),       // -16307.42093852
            (0x1d80_ffff, 0xbff0_0000_0000_0000),       // -1.00000000
            (0x3f80_0001, 0x8000_0000_0000_0000),       // -0.00000000
            (0x2080_ffff, 0xbe70_1b2b_29a4_692b),       // -0.00000006
            (0x1a80_abcd, 0xc177_d759_27d4_bd97),       // -24999314.48943862
            (0x1c00_ffff, 0x4070_0000_0000_0000),       // 256.00000000
            (0x1b04_04cb, 0x40cf_d9b5_e150_3c83),       // 16307.42093852
        ] {
            let got = get_difficulty_ratio(bits, pow_limit_bits);
            assert_eq!(
                got.to_bits(),
                want,
                "bits {bits:08x}: got {got}, want {}",
                f64::from_bits(want)
            );
        }
    }

    /// Go's `%#U` appends the quoted character only when
    /// `strconv.IsPrint` holds and never escapes it.  The port rendered
    /// the character with Rust's char `Debug`, which quotes control
    /// characters and escapes `'` and `\`.  Expected texts from Go 1.27's
    /// `hex.InvalidByteError(b).Error()`.
    #[test]
    fn hex_invalid_byte_text_matches_go() {
        for (b, want) in [
            (0x00u8, "encoding/hex: invalid byte: U+0000"),
            (0x01, "encoding/hex: invalid byte: U+0001"),
            (0x09, "encoding/hex: invalid byte: U+0009"),
            (0x1f, "encoding/hex: invalid byte: U+001F"),
            (b' ', "encoding/hex: invalid byte: U+0020 ' '"),
            (b'\'', "encoding/hex: invalid byte: U+0027 '''"),
            (b'\\', "encoding/hex: invalid byte: U+005C '\\'"),
            (b'"', "encoding/hex: invalid byte: U+0022 '\"'"),
            (b'z', "encoding/hex: invalid byte: U+007A 'z'"),
            (b'g', "encoding/hex: invalid byte: U+0067 'g'"),
            (0x7f, "encoding/hex: invalid byte: U+007F"),
            (0x80, "encoding/hex: invalid byte: U+0080"),
            (0x9f, "encoding/hex: invalid byte: U+009F"),
            (0xa0, "encoding/hex: invalid byte: U+00A0"),
            (0xa1, "encoding/hex: invalid byte: U+00A1 '\u{a1}'"),
            (0xad, "encoding/hex: invalid byte: U+00AD"),
            (0xc3, "encoding/hex: invalid byte: U+00C3 '\u{c3}'"),
            (0xff, "encoding/hex: invalid byte: U+00FF '\u{ff}'"),
        ] {
            assert_eq!(go_hex_invalid_byte_error(b), want, "byte {b:#04x}");
        }
    }

    /// A hash string fails with dcrd's `chainhash.Decode` text: Go's
    /// invalid-byte error, and `ErrHashStrSize` for an overlong string.
    #[test]
    fn hash_decode_error_text_matches_go() {
        let text = |s: &str| go_hash_decode_error(s.parse::<Hash>().expect_err("must fail"));
        assert_eq!(text("zz"), "encoding/hex: invalid byte: U+007A 'z'");
        assert_eq!(text("0'"), "encoding/hex: invalid byte: U+0027 '''");
        assert_eq!(text("\\"), "encoding/hex: invalid byte: U+005C '\\'");
        assert_eq!(text("\u{1}"), "encoding/hex: invalid byte: U+0001");
        assert_eq!(text("\u{7f}"), "encoding/hex: invalid byte: U+007F");
        assert_eq!(text(&"0".repeat(65)), "max hash string length is 64 bytes");
    }

    /// The template pool keeps exactly the templates at or above
    /// `best - getworkExpirationDiff`, as dcrd's `pruneOldBlockTemplates`
    /// deletes those with `height < pruneHeight`.
    #[test]
    fn prune_old_block_templates_keeps_the_expiration_window() {
        let (header, _) =
            BlockHeader::from_bytes(&[0u8; MAX_BLOCK_HEADER_PAYLOAD]).expect("header");
        let mut state = crate::server::WorkState::default();
        for height in 0..10u32 {
            let mut block = dcroxide_wire::MsgBlock {
                header,
                transactions: Vec::new(),
                stransactions: Vec::new(),
            };
            block.header.height = height;
            let mut key = [0u8; MERKLE_ROOT_PAIR_SIZE];
            key[0] = height as u8;
            state.template_pool.insert(key, block);
        }
        state.prune_old_block_templates(9);
        let mut kept: Vec<u32> = state
            .template_pool
            .values()
            .map(|b| b.header.height)
            .collect();
        kept.sort_unstable();
        assert_eq!(kept, vec![6, 7, 8, 9]);
    }
}
