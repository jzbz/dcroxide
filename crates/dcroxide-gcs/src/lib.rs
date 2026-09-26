// SPDX-License-Identifier: ISC
//! Golomb-coded set (GCS) filters, ported from dcrd's `gcs/v4` at the
//! parity pin, master `b9634e01` (the package is unchanged since the
//! port's original target, `452c1a6c`): the version 1 and version 2
//! filter formats, matching, serialization, and the DCP0005 version 2
//! block committed filters in [`blockcf2`].
//!
//! SipHash-2-4 comes from the `siphasher` crate, matching the
//! dchest/siphash implementation dcrd links.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

extern crate alloc;

mod bits;
pub mod blockcf2;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::hash::Hasher;

use dcroxide_chainhash::{HASH_SIZE, Hash, hash_h};
use dcroxide_wire::{Cursor, read_var_int, var_int_serialize_size, write_var_int};
use siphasher::sip::SipHasher24;

use bits::{BitReader, BitWriter};

/// The size of the byte array required for key material for the
/// SipHash keyed hash function (dcrd `KeySize`).
pub const KEY_SIZE: usize = 16;

/// The kind of a gcs error; names match dcrd's `ErrorKind` strings.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The provided number of filter entries exceeds the maximum.
    NTooBig,
    /// The provided fp rate P exceeds the maximum (version 1).
    PTooBig,
    /// The provided Golomb coding bin size B exceeds the maximum.
    BTooBig,
    /// A serialized filter is misserialized.
    Misserialized,
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::NTooBig => "ErrNTooBig",
            ErrorKind::PTooBig => "ErrPTooBig",
            ErrorKind::BTooBig => "ErrBTooBig",
            ErrorKind::Misserialized => "ErrMisserialized",
        }
    }
}

/// A gcs error (dcrd `Error`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The kind of error.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

fn gcs_error(kind: ErrorKind, description: impl Into<String>) -> Error {
    Error {
        kind,
        description: description.into(),
    }
}

/// SipHash-2-4 of the data under the split 128-bit key, matching
/// dchest/siphash `Hash`.
fn siphash(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(data);
    hasher.finish()
}

/// The version 1 reduction: plain modulo (dcrd `modReduceV1`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "unsigned, so never MIN % -1; n is N*M, nonzero for every built filter with entries (N <= i32::MAX, M = 2^P <= 2^32), and zero only for a deserialized v1 filter claiming 0 entries over data, where dcrd's x % N panics the same way"
)]
fn mod_reduce_v1(x: u64, n: u64) -> u64 {
    x % n
}

/// The version 2 reduction: multiply-shift (dcrd `fastReduce`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the product of two u64 values fits in u128: (2^64 - 1)^2 < 2^128"
)]
fn fast_reduce(x: u64, n: u64) -> u64 {
    ((u128::from(x) * u128::from(n)) >> 64) as u64
}

fn reduce(version: u16, x: u64, n: u64) -> u64 {
    if version == 1 {
        mod_reduce_v1(x, n)
    } else {
        fast_reduce(x, n)
    }
}

/// The filter's hashed entries reduced to `[0, N*M)` and sorted, with
/// the modulus `N*M` they were reduced over (the value pipeline of dcrd
/// `newFilter`).  Version 2 skips empty entries and removes duplicate
/// hashes, so `N` counts the distinct hashes.
///
/// dcrd deduplicates through a map, reduces, then sorts.  Version 2
/// here sorts the raw hashes, drops adjacent duplicates and reduces in
/// place instead: `fast_reduce` is monotone non-decreasing in its
/// input, so the reduced values come out already sorted and equal to
/// dcrd's, with no set and no second sort on the per-block filter
/// build.  Version 1 keeps every entry and its modulo reduction is not
/// monotone, so it reduces and then sorts as dcrd does.
fn sorted_values(version: u16, m: u64, k0: u64, k1: u64, data: &[&[u8]]) -> (u64, Vec<u64>) {
    let mut values: Vec<u64> = Vec::with_capacity(data.len());
    if version == 1 {
        for d in data {
            values.push(siphash(k0, k1, d));
        }
    } else {
        for d in data {
            if d.is_empty() {
                continue;
            }
            values.push(siphash(k0, k1, d));
        }
        values.sort_unstable();
        values.dedup();
    }

    // The modulus wraps on overflow exactly like Go's uint64 multiply.
    let modulus_nm = (values.len() as u64).wrapping_mul(m);
    for v in values.iter_mut() {
        *v = reduce(version, *v, modulus_nm);
    }
    if version == 1 {
        values.sort_unstable();
    }
    (modulus_nm, values)
}

/// The shared filter core (dcrd's unexported `filter`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Filter {
    version: u16,
    n: u32,
    b: u8,
    modulus_nm: u64,
    /// The full serialization: entry count followed by the bitstream.
    filter_n_data: Vec<u8>,
    /// Offset of the raw filter bitstream within `filter_n_data`.
    data_offset: usize,
}

impl Filter {
    /// Build a filter from the entries (dcrd `newFilter`).  Version 2
    /// skips empty entries and deduplicates hashed values.
    fn new(
        version: u16,
        b: u8,
        m: u64,
        key: [u8; KEY_SIZE],
        data: &[&[u8]],
    ) -> Result<Filter, Error> {
        assert!(b <= 32, "B value of {b} is greater than max allowed 32");
        assert!(
            version == 1 || version == 2,
            "version {version} filters are not supported"
        );

        let num_entries = data.len() as u64;
        if num_entries > i32::MAX as u64 {
            return Err(gcs_error(
                ErrorKind::NTooBig,
                alloc::format!(
                    "unable to create filter with {} entries greater than max allowed {}",
                    data.len(),
                    i32::MAX
                ),
            ));
        }

        let k0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));

        let (modulus_nm, values) = sorted_values(version, m, k0, k1, data);
        let num_entries = values.len() as u64;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "b <= 32 is asserted above, so 1 << b >= 1"
        )]
        let mod_b_mask = (1u64 << b) - 1;
        let mut f = Filter {
            version,
            n: num_entries as u32,
            b,
            modulus_nm,
            filter_n_data: Vec::new(),
            data_offset: 0,
        };
        if values.is_empty() {
            return Ok(f);
        }

        // The entry count goes ahead of the bitstream: big-endian uint32
        // for version 1, varint for version 2.  dcrd codes the deltas
        // into a buffer sized by its hint and then copies them behind
        // the count; the port writes the count first and codes straight
        // after it, into one buffer with room for both.  dcrd's hint:
        // every entry takes B remainder bits and a unary quotient that
        // is 1 on average (2 bits) and 2 (3 bits) next most often, so
        // (NB + 2N/2 + 3N/2) / 8 bytes, with Go's `3*numEntries>>1`
        // parsing as `(3*numEntries)>>1`.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "num_entries <= i32::MAX (checked above) and b <= 32, so the sum is below 2^37"
        )]
        let size_hint = (num_entries * u64::from(b) + num_entries + ((3 * num_entries) >> 1)) >> 3;
        let n_size = match version {
            1 => 4,
            _ => var_int_serialize_size(u64::from(f.n)),
        };
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "n_size <= 9 and size_hint < 2^34, a capacity hint"
        )]
        let mut ndata = Vec::with_capacity(n_size + size_hint as usize);
        match version {
            1 => ndata.extend_from_slice(&f.n.to_be_bytes()),
            _ => write_var_int(&mut ndata, u64::from(f.n)),
        }

        // Golomb/Rice-code the sorted deltas.
        let mut w = BitWriter::after(ndata);
        for (i, v) in values.iter().enumerate() {
            #[allow(clippy::arithmetic_side_effects, reason = "i > 0 in the else arm")]
            let prev = if i == 0 { 0 } else { values[i - 1] };
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "values is sorted ascending, so v >= prev"
            )]
            let delta = v - prev;
            let remainder = delta & mod_b_mask;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "remainder = delta & mod_b_mask <= delta"
            )]
            let mut quotient = (delta - remainder) >> f.b;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "quotient > 0 by the loop condition"
            )]
            while quotient > 0 {
                w.write_one();
                quotient -= 1;
            }
            w.write_zero();
            w.write_n_bits(remainder, u32::from(f.b));
        }

        f.filter_n_data = w.bytes;
        f.data_offset = n_size;
        Ok(f)
    }

    fn filter_data(&self) -> &[u8] {
        &self.filter_n_data[self.data_offset..]
    }

    /// Read a full delta value: unary quotient then B remainder bits
    /// (dcrd `readFullUint64`).
    fn read_full_u64(&self, r: &mut BitReader<'_>) -> Result<u64, ()> {
        let v = r.read_unary()?;
        let rem = r.read_n_bits(u32::from(self.b))?;
        Ok(v << self.b | rem)
    }

    /// Whether the data matches the filter with the (rare) chance of a
    /// false positive (dcrd `Match`).
    fn matches(&self, key: [u8; KEY_SIZE], data: &[u8]) -> bool {
        if self.filter_data().is_empty() || data.is_empty() {
            return false;
        }

        // Hash and reduce the search term.
        let k0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
        let term = reduce(self.version, siphash(k0, k1, data), self.modulus_nm);

        // Walk the sorted deltas until the term is met or passed.
        let mut r = BitReader::new(self.filter_data());
        let mut last_value: u64 = 0;
        while last_value <= term {
            let Ok(value) = self.read_full_u64(&mut r) else {
                return false;
            };
            let value = value.wrapping_add(last_value);
            if value == term {
                return true;
            }
            last_value = value;
        }
        false
    }

    /// Whether any of the data entries match the filter (dcrd
    /// `MatchAny`).
    ///
    /// Quirk parity: like dcrd, the zip search bounds the search index
    /// by the length of the *input* slice rather than the deduplicated
    /// hashed values, so inputs containing empty entries can index past
    /// the values and panic in dcrd; this port saturates instead of
    /// panicking (the outcome for every non-panicking input is
    /// identical, and the panic is unreachable through the block filter
    /// construction paths).
    fn matches_any(&self, key: [u8; KEY_SIZE], data: &[&[u8]]) -> bool {
        if self.filter_data().is_empty() || data.is_empty() {
            return false;
        }

        // Hash and reduce the search terms, skipping empty entries.
        let k0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
        let mut values: Vec<u64> = Vec::with_capacity(data.len());
        for d in data {
            if d.is_empty() {
                continue;
            }
            values.push(reduce(self.version, siphash(k0, k1, d), self.modulus_nm));
        }
        if values.is_empty() {
            return false;
        }
        values.sort_unstable();

        // Zip down the filter values and the sorted search values.
        let mut r = BitReader::new(self.filter_data());
        let mut search_idx = 0usize;
        let mut filter_val: u64 = 0;
        'next_filter_val: for _ in 0..self.n {
            let Ok(delta) = self.read_full_u64(&mut r) else {
                return false;
            };
            filter_val = filter_val.wrapping_add(delta);
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "search_idx < values.len() by the loop condition"
            )]
            while search_idx < values.len() {
                let search_val = values[search_idx];
                if search_val == filter_val {
                    return true;
                }
                if search_val > filter_val {
                    continue 'next_filter_val;
                }
                search_idx += 1;
            }
            break;
        }
        false
    }

    /// The BLAKE-256 hash of the serialized filter; the zero hash for
    /// an empty filter (dcrd `Hash`).
    fn hash(&self) -> Hash {
        if self.filter_n_data.is_empty() {
            return Hash::ZERO;
        }
        hash_h(&self.filter_n_data)
    }
}

/// A version 1 Golomb-coded set filter (dcrd `FilterV1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterV1 {
    filter: Filter,
}

impl FilterV1 {
    /// Build a version 1 filter with false positive rate 2^-P (dcrd
    /// `NewFilterV1`).
    pub fn new(p: u8, key: [u8; KEY_SIZE], data: &[&[u8]]) -> Result<FilterV1, Error> {
        if p > 32 {
            return Err(gcs_error(
                ErrorKind::PTooBig,
                alloc::format!("P value of {p} is greater than max allowed 32"),
            ));
        }
        Ok(FilterV1 {
            filter: Filter::new(1, p, 1 << p, key, data)?,
        })
    }

    /// Deserialize a version 1 filter (dcrd `FromBytesV1`).
    pub fn from_bytes(p: u8, d: &[u8]) -> Result<FilterV1, Error> {
        if p > 32 {
            return Err(gcs_error(
                ErrorKind::PTooBig,
                alloc::format!("P value of {p} is greater than max allowed 32"),
            ));
        }
        let mut n: u32 = 0;
        let mut data_offset = 0usize;
        if d.len() >= 4 {
            n = u32::from_be_bytes(d[0..4].try_into().expect("4 bytes"));
            data_offset = 4;
        } else if !d.is_empty() {
            return Err(gcs_error(
                ErrorKind::Misserialized,
                "number of items serialization missing",
            ));
        }
        Ok(FilterV1 {
            filter: Filter {
                version: 1,
                n,
                b: p,
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "n <= u32::MAX and 1 << p <= 2^32 (p <= 32 checked above), so the product is below 2^64"
                )]
                modulus_nm: u64::from(n) * (1u64 << p),
                filter_n_data: d.to_vec(),
                data_offset,
            },
        })
    }

    /// The false positive rate parameter (dcrd `P`).
    pub fn p(&self) -> u8 {
        self.filter.b
    }

    /// The serialized filter, entry count included (dcrd `Bytes`).
    pub fn bytes(&self) -> &[u8] {
        &self.filter.filter_n_data
    }

    /// The number of filter entries (dcrd `N`).
    pub fn n(&self) -> u32 {
        self.filter.n
    }

    /// Whether the data matches the filter (dcrd `Match`).
    pub fn matches(&self, key: [u8; KEY_SIZE], data: &[u8]) -> bool {
        self.filter.matches(key, data)
    }

    /// Whether any of the data entries match (dcrd `MatchAny`).
    pub fn matches_any(&self, key: [u8; KEY_SIZE], data: &[&[u8]]) -> bool {
        self.filter.matches_any(key, data)
    }

    /// The BLAKE-256 hash of the serialized filter (dcrd `Hash`).
    pub fn hash(&self) -> Hash {
        self.filter.hash()
    }
}

/// A version 2 Golomb-coded set filter (dcrd `FilterV2`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterV2 {
    filter: Filter,
}

impl FilterV2 {
    /// Build a version 2 filter with Golomb bin size 2^-B and false
    /// positive rate 1/M (dcrd `NewFilterV2`).
    pub fn new(b: u8, m: u64, key: [u8; KEY_SIZE], data: &[&[u8]]) -> Result<FilterV2, Error> {
        if b > 32 {
            return Err(gcs_error(
                ErrorKind::BTooBig,
                alloc::format!("B value of {b} is greater than max allowed 32"),
            ));
        }
        Ok(FilterV2 {
            filter: Filter::new(2, b, m, key, data)?,
        })
    }

    /// Deserialize a version 2 filter (dcrd `FromBytesV2`).
    pub fn from_bytes(b: u8, m: u64, d: &[u8]) -> Result<FilterV2, Error> {
        if b > 32 {
            return Err(gcs_error(
                ErrorKind::BTooBig,
                alloc::format!("B value of {b} is greater than max allowed 32"),
            ));
        }
        let mut n: u64 = 0;
        let mut data_offset = 0usize;
        if !d.is_empty() {
            let mut r = Cursor::new(d);
            n = read_var_int(&mut r).map_err(|e| {
                gcs_error(
                    ErrorKind::Misserialized,
                    alloc::format!("failed to read number of filter items: {e}"),
                )
            })?;
            data_offset = var_int_serialize_size(n);
        }
        Ok(FilterV2 {
            filter: Filter {
                version: 2,
                n: n as u32,
                b,
                // A hostile serialized entry count can overflow the
                // modulus; it wraps exactly like Go's uint64 multiply.
                modulus_nm: n.wrapping_mul(m),
                filter_n_data: d.to_vec(),
                data_offset,
            },
        })
    }

    /// The Golomb bin size parameter (dcrd `B`).
    pub fn b(&self) -> u8 {
        self.filter.b
    }

    /// The serialized filter, entry count included (dcrd `Bytes`).
    pub fn bytes(&self) -> &[u8] {
        &self.filter.filter_n_data
    }

    /// The number of filter entries (dcrd `N`).
    pub fn n(&self) -> u32 {
        self.filter.n
    }

    /// Whether the data matches the filter (dcrd `Match`).
    pub fn matches(&self, key: [u8; KEY_SIZE], data: &[u8]) -> bool {
        self.filter.matches(key, data)
    }

    /// Whether any of the data entries match (dcrd `MatchAny`).
    pub fn matches_any(&self, key: [u8; KEY_SIZE], data: &[&[u8]]) -> bool {
        self.filter.matches_any(key, data)
    }

    /// The BLAKE-256 hash of the serialized filter (dcrd `Hash`).
    pub fn hash(&self) -> Hash {
        self.filter.hash()
    }
}

/// The filter header for a version 1 filter: BLAKE-256 over the filter
/// hash concatenated with the previous filter header (dcrd
/// `MakeHeaderForFilter`).
pub fn make_header_for_filter(filter: &FilterV1, prev_header: &Hash) -> Hash {
    let mut filter_tip = [0u8; 2 * HASH_SIZE];
    filter_tip[..HASH_SIZE].copy_from_slice(&filter.hash().0);
    filter_tip[HASH_SIZE..].copy_from_slice(&prev_header.0);
    hash_h(&filter_tip)
}

/// The maximum serialized size of a version 2 filter with the given
/// parameters and entry count (dcrd `MaxFilterV2Size`).
///
/// The arithmetic reproduces Go's uint64 semantics exactly: with no
/// entries the largest difference wraps around to `u64::MAX`, a shift
/// count of 64 or more yields zero, and the final byte rounding wraps
/// rather than saturating.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "only the final sum: the quotient is at most u64::MAX / 8 and n_ser_size <= 9"
)]
pub fn max_filter_v2_size(b: u8, m: u64, n: u32) -> u64 {
    let n = u64::from(n);
    let b = u32::from(b);
    let largest_diff = n.wrapping_mul(m).wrapping_sub(1);
    let max_quo_bits = largest_diff.checked_shr(b).unwrap_or(0);
    let n_ser_size = var_int_serialize_size(n) as u64;
    let max_bits = n
        .wrapping_add(n.wrapping_mul(u64::from(b)))
        .wrapping_add(max_quo_bits);
    max_bits.wrapping_add(7) / 8 + n_ser_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::SplitMix64;

    /// dcrd `newFilter`'s value pipeline as written there: dedupe the
    /// hashes through a set (version 2), reduce every value, then sort.
    fn dcrd_values(version: u16, m: u64, k0: u64, k1: u64, data: &[&[u8]]) -> (u64, Vec<u64>) {
        let mut values = Vec::new();
        let mut seen = alloc::collections::BTreeSet::new();
        for d in data {
            if version == 2 && d.is_empty() {
                continue;
            }
            let v = siphash(k0, k1, d);
            if version == 1 || seen.insert(v) {
                values.push(v);
            }
        }
        let modulus_nm = (values.len() as u64).wrapping_mul(m);
        for v in values.iter_mut() {
            *v = reduce(version, *v, modulus_nm);
        }
        values.sort_unstable();
        (modulus_nm, values)
    }

    /// Sorting and deduplicating the raw version 2 hashes before the
    /// monotone reduction yields exactly dcrd's reduce-then-sort values,
    /// including when distinct hashes reduce to the same value (a tiny
    /// `M`) and when the modulus wraps (a huge `M`).
    #[test]
    fn sorted_values_match_dcrds_pipeline() {
        let mut rng = SplitMix64::from_entropy("gcs-sorted-values");
        for round in 0..2000 {
            let version = 1 + (round % 2) as u16;
            let m = match rng.below(4) {
                0 => 1,
                1 => rng.below(8) + 1,
                2 => blockcf2::M,
                _ => u64::MAX - rng.below(1 << 20),
            };
            let (k0, k1) = (rng.next_u64(), rng.next_u64());
            let n = rng.below(64) as usize;
            let mut entries: Vec<Vec<u8>> = Vec::with_capacity(n);
            for _ in 0..n {
                match rng.below(6) {
                    0 => entries.push(Vec::new()),
                    1 if !entries.is_empty() => {
                        let i = rng.below(entries.len() as u64) as usize;
                        entries.push(entries[i].clone());
                    }
                    _ => {
                        let len = rng.below(8) as usize + 1;
                        entries.push(rng.bytes(len));
                    }
                }
            }
            let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
            assert_eq!(
                sorted_values(version, m, k0, k1, &refs),
                dcrd_values(version, m, k0, k1, &refs),
                "round {round}: version {version}, m {m}"
            );
        }
    }
}
