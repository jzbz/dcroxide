// SPDX-License-Identifier: ISC
//! An optimized Age-Partitioned Bloom Filter (dcrd `container/apbf`).
//!
//! References:
//!   \[APBF\] Age-Partitioned Bloom Filters (Shtul, Baquero, Almeida)
//!   \[LHSP\] Less Hashing, Same Performance: Building a Better Bloom
//!   Filter (Kirsch, Mitzenmacher)
//!   \[BFPV\] Bloom Filters in Probabilistic Verification (Dillinger,
//!   Manolis)

// Bounded bookkeeping arithmetic mirrors Go; the genuinely wrapping
// hash derivations use explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::hash::Hasher;

use siphasher::sip128::{Hasher128, SipHasher24};

/// The 128-bit SipHash-2-4 of the data under the given key, returned
/// as the two 64-bit output words (dchest `siphash.Hash128`; exposed
/// for the differential tests).
#[doc(hidden)]
pub fn siphash128(key0: u64, key1: u64, data: &[u8]) -> (u64, u64) {
    let mut hasher = SipHasher24::new_with_keys(key0, key1);
    hasher.write(data);
    let hash = hasher.finish128();
    (hash.h1, hash.h2)
}

/// Calculate the false positive rate for the provided parameters
/// using the given results map to cache intermediate results (dcrd
/// `calcFPRateInternal`).
fn calc_fp_rate_internal(
    results: &mut HashMap<(u16, u16), f64>,
    k: u8,
    l: u8,
    a: u16,
    i: u16,
) -> f64 {
    // The false positive rate is calculated according to the
    // following recursively-defined function provided in [APBF]:
    //
    //              {1                                        , if a = k
    // F(k,l,a,i) = {0                                        , if i > l + a
    //              {(r_i)F(k,l,a+1,i+1) + (1-r_i)F(k,l,0,i+1), otherwise

    if a == u16::from(k) {
        return 1.0;
    } else if i > u16::from(l) + a {
        return 0.0;
    }

    // Return stored results to avoid a bunch of duplicate work.
    if let Some(result) = results.get(&(a, i)) {
        return *result;
    }

    // Calculate the fill ratio for the slice.
    let mut fill_ratio = 0.5f64;
    if i < u16::from(k) {
        fill_ratio = f64::from(i + 1) / f64::from(2 * u16::from(k));
    }

    let first_term = fill_ratio * calc_fp_rate_internal(results, k, l, a + 1, i + 1);
    let second_term = (1.0 - fill_ratio) * calc_fp_rate_internal(results, k, l, 0, i + 1);
    let result = first_term + second_term;
    results.insert((a, i), result);
    result
}

/// Calculate the false positive rate for an APBF created with the
/// given parameters (dcrd `CalcFPRate`).
///
/// NOTE: This involves allocations, so the result should be cached by
/// the caller if it intends to use it multiple times.
pub fn calc_fp_rate(k: u8, l: u8) -> f64 {
    let mut results = HashMap::with_capacity(2 * usize::from(k) * usize::from(l));
    calc_fp_rate_internal(&mut results, k, l, 0, 0)
}

/// An Age-Partitioned Bloom Filter (dcrd `Filter`): a probabilistic
/// data structure suitable for use in processing unbounded data
/// streams where more recent items are more significant than older
/// ones and some false positives are acceptable.
///
/// Similar to classic Bloom filters, APBFs have a non-zero
/// probability of false positives that can be tuned via parameters
/// and are free from false negatives up to the capacity of the
/// filter.  Unlike classic Bloom filters, APBFs provide a
/// configurable upper bound on the false positive rate for an
/// unbounded number of additions, achieved by adding and retiring
/// disjoint slices of a partitioned Bloom filter over time.
pub struct Filter {
    /// The number of slices which need consecutive matches for an
    /// item to be considered in the filter.
    k: u8,

    /// The additional number of slices which comprise the region of
    /// items that are transitioning to expired.
    l: u8,

    /// The total number of slices.
    k_plus_l: u16,

    /// The number of physical bits occupied by each slice.
    bits_per_slice: u64,

    /// The number of items per generation; the slices are aged every
    /// time this number of items is inserted into the filter.
    items_per_generation: u32,

    /// The keys used to seed the hash function in order to ensure
    /// attackers are not able to intentionally grind false positives.
    key0: u64,
    key1: u64,

    /// The number of items that have been added to the current
    /// generation.
    items_in_cur_generation: u32,

    /// The index of the position of the first slice within the ring
    /// buffer.
    base_index: u16,

    /// The actual filter data implemented as a packed ring buffer
    /// where the individual filter slices perform logical shifts.
    data: Vec<u8>,
}

impl Filter {
    /// The max number of items that were most recently added which
    /// are guaranteed to return true (dcrd `Capacity`).  Adding more
    /// items than the returned value will cause the oldest items to
    /// be expired.
    pub fn capacity(&self) -> u32 {
        u32::from(self.l)
            .wrapping_add(1)
            .wrapping_mul(self.items_per_generation)
    }

    /// The actual false positive rate for the filter (dcrd `FPRate`).
    ///
    /// NOTE: This involves allocations, so the result should be
    /// cached by the caller if it intends to use it multiple times.
    pub fn fp_rate(&self) -> f64 {
        calc_fp_rate(self.k, self.l)
    }

    /// The total bytes occupied by the filter data plus overhead
    /// (dcrd `Size`).
    pub fn size(&self) -> usize {
        const OVERHEAD: usize = 70;
        self.data.len().wrapping_add(OVERHEAD)
    }

    /// The filter configuration parameter for the number of slices
    /// that need consecutive matches (dcrd `K`).
    pub fn k(&self) -> u8 {
        self.k
    }

    /// The filter configuration parameter for the number of
    /// additional slices (dcrd `L`).
    pub fn l(&self) -> u8 {
        self.l
    }

    /// Transition the filter to the next generation which effectively
    /// ages all items and potentially expires the oldest generation
    /// of items (dcrd `nextGeneration`; exposed for tests).
    #[doc(hidden)]
    pub fn next_generation(&mut self) {
        // Shift the position of the first slice within the ring
        // buffer to the left by one.
        if self.base_index == 0 {
            self.base_index = self.k_plus_l;
        }
        self.base_index -= 1;

        // Clear the bits associated with the new logical slice.  Note
        // that since the logical slice was just rotated once
        // backwards around the ring buffer above, this clears what
        // was previously the oldest slice so the new entries take its
        // place.
        let start_bit = u64::from(self.base_index).wrapping_mul(self.bits_per_slice);
        let end_bit = start_bit.wrapping_add(self.bits_per_slice);

        // Clear bits up to the next byte boundary.
        let mut byte_idx = start_bit >> 3;
        let bit = start_bit & 7;
        if bit != 0 {
            self.data[byte_idx as usize] &= (1u16 << bit).wrapping_sub(1) as u8;
            byte_idx += 1;
        }

        // Clear full bytes in one fell swoop when possible.
        let end_byte_idx = end_bit >> 3;
        if end_byte_idx > byte_idx {
            let full_bytes = end_byte_idx - byte_idx;
            let data = &mut self.data[byte_idx as usize..(byte_idx + full_bytes) as usize];
            for b in data.iter_mut() {
                *b = 0;
            }
            byte_idx += full_bytes;
        }

        // Clear any remaining bits.
        if byte_idx < self.data.len() as u64 {
            self.data[byte_idx as usize] &= !((1u16 << (end_bit & 7)).wrapping_sub(1) as u8);
        }

        self.items_in_cur_generation = 0;
    }

    /// Unconditionally set the bit at the provided absolute index in
    /// the underlying filter data (dcrd `setBit`).
    fn set_bit(&mut self, bit: u64) {
        self.data[(bit >> 3) as usize] |= 1 << (bit & 7);
    }

    /// Insert the provided data into the filter (dcrd `Add`).
    pub fn add(&mut self, data: &[u8]) {
        // Transition the filter to the next generation when adding
        // the new item will exceed the number of items per
        // generation.
        if self.items_in_cur_generation == self.items_per_generation {
            self.next_generation();
        }
        self.items_in_cur_generation = self.items_in_cur_generation.wrapping_add(1);

        // Set the relevant bits in the filter for 'k' slices,
        // starting from the first slice, as determined by the
        // equivalent of a separate hash function for each slice via
        // enhanced double hashing, interleaved with the loop over the
        // slices.  A ring buffer is used where the position index of
        // the first slice is modified to simulate shifting.
        let mut logical_slice = self.base_index;
        let mut slice_bit_offset = u64::from(logical_slice).wrapping_mul(self.bits_per_slice);
        let (hash1, hash2) = siphash128(self.key0, self.key1, data);
        let (mut derived_idx, mut acc) = derive_index(logical_slice, hash1, hash2);
        let mut i = 0u8;
        while i < self.k {
            self.set_bit(
                slice_bit_offset.wrapping_add(fast_reduce(derived_idx, self.bits_per_slice)),
            );
            i = i.wrapping_add(1);

            // Move to the next logical slice while wrapping around
            // the ring buffer if needed.
            logical_slice = logical_slice.wrapping_add(1);
            if logical_slice == self.k_plus_l {
                logical_slice = 0;
                slice_bit_offset = 0;

                // Reset the derived bit index using enhanced double
                // hashing accordingly.
                derived_idx = hash1;
                acc = hash2;
                continue;
            }
            slice_bit_offset = slice_bit_offset.wrapping_add(self.bits_per_slice);

            // Derive the next bit index using enhanced double
            // hashing.
            derived_idx = derived_idx.wrapping_add(acc);
            acc = acc.wrapping_add(u64::from(logical_slice));
        }
    }

    /// Whether or not the bit at the provided absolute index in the
    /// underlying filter data is set (dcrd `isBitSet`).
    fn is_bit_set(&self, bit: u64) -> bool {
        self.data[(bit >> 3) as usize] & (1 << (bit & 7)) != 0
    }

    /// The result of a probabilistic membership test of the provided
    /// data (dcrd `Contains`): the most recent max capacity number of
    /// items added to the filter will always return true while items
    /// that were never added or have been expired will only report
    /// true with the false positive rate of the filter.
    pub fn contains(&self, data: &[u8]) -> bool {
        // Attempt to find the required 'k' consecutive matches using
        // an algorithm that reduces the average number of tests
        // required: choose the starting position such that it leaves
        // exactly 'k' consecutive slices to be tested, accumulate the
        // matching sub sequences, and jump backwards 'k' slices when
        // a match fails.
        let mut prev_matches = 0u8;
        let mut cur_matches = 0u8;
        let mut physical_slice = u16::from(self.l);
        let mut logical_slice = (self.base_index.wrapping_add(physical_slice)) % self.k_plus_l;
        let mut slice_bit_offset = u64::from(logical_slice).wrapping_mul(self.bits_per_slice);
        let (hash1, hash2) = siphash128(self.key0, self.key1, data);
        let (mut derived_idx, mut acc) = derive_index(logical_slice, hash1, hash2);
        loop {
            if self.is_bit_set(
                slice_bit_offset.wrapping_add(fast_reduce(derived_idx, self.bits_per_slice)),
            ) {
                // Successful query when the required number of
                // consecutive matches is achieved.
                cur_matches = cur_matches.wrapping_add(1);
                if prev_matches.wrapping_add(cur_matches) == self.k {
                    return true;
                }

                // Move to the next logical slice while wrapping
                // around the ring buffer if needed.
                physical_slice = physical_slice.wrapping_add(1);
                logical_slice = logical_slice.wrapping_add(1);
                if logical_slice == self.k_plus_l {
                    logical_slice = 0;
                    slice_bit_offset = 0;

                    // Reset the derived bit index using enhanced
                    // double hashing accordingly.
                    derived_idx = hash1;
                    acc = hash2;
                    continue;
                }
                slice_bit_offset = slice_bit_offset.wrapping_add(self.bits_per_slice);

                // Derive the next bit index using enhanced double
                // hashing.
                derived_idx = derived_idx.wrapping_add(acc);
                acc = acc.wrapping_add(u64::from(logical_slice));
                continue;
            }

            // Nothing more to do when there are not enough slices
            // left to achieve the required number of consecutive
            // matches.
            if u16::from(self.k) > physical_slice {
                return false;
            }

            // Skip back the required number of matches while
            // accumulating any matching sub sequence.
            physical_slice -= u16::from(self.k);
            prev_matches = cur_matches;
            cur_matches = 0;

            // Reset logical slice and derive the associated bit index
            // using enhanced double hashing.
            logical_slice = (self.base_index.wrapping_add(physical_slice)) % self.k_plus_l;
            slice_bit_offset = u64::from(logical_slice).wrapping_mul(self.bits_per_slice);
            let (idx, a) = derive_index(logical_slice, hash1, hash2);
            derived_idx = idx;
            acc = a;
        }
    }

    /// Clear the filter and change the key used in the internal
    /// hashing logic to ensure a unique set of false positives versus
    /// those prior to the reset (dcrd `Reset`).
    pub fn reset(&mut self) {
        let (key0, key1) = siphash128(self.key0, self.key1, b"reset");
        self.key0 = key0;
        self.key1 = key1;
        self.base_index = 0;
        self.items_in_cur_generation = 0;
        for b in self.data.iter_mut() {
            *b = 0;
        }
    }

    /// Override the internal hash keys; exposed so tests can pin the
    /// filter contents deterministically.
    #[doc(hidden)]
    pub fn set_keys(&mut self, key0: u64, key1: u64) {
        self.key0 = key0;
        self.key1 = key1;
    }

    /// The internal hash keys; exposed for tests.
    #[doc(hidden)]
    pub fn keys(&self) -> (u64, u64) {
        (self.key0, self.key1)
    }

    /// The internal filter state; exposed so tests can compare the
    /// packed ring buffer byte for byte.
    #[doc(hidden)]
    pub fn internal_state(&self) -> (u16, u32, &[u8]) {
        (self.base_index, self.items_in_cur_generation, &self.data)
    }

    /// The derived internal parameters; exposed for tests.
    #[doc(hidden)]
    pub fn internal_params(&self) -> (u32, u64) {
        (self.items_per_generation, self.bits_per_slice)
    }
}

/// Use enhanced double hashing to calculate a unique index for the
/// given logical slice number using the closed formula, also
/// returning the intermediate accumulator for interleaved iteration
/// (dcrd `deriveIndex`).
///
/// It is defined as "f(i) = hash1 + i*hash2 + (i^3 - i)/6 (mod m)",
/// where m is the number of bits to index; the modular reduction is
/// left to the caller.
fn derive_index(slice: u16, hash1: u64, hash2: u64) -> (u64, u64) {
    let s = u64::from(slice);
    let z = s.wrapping_mul(s).wrapping_add(s) / 2;
    let derived_idx = hash1
        .wrapping_add(s.wrapping_mul(hash2))
        .wrapping_add(z.wrapping_mul(s.wrapping_sub(1)) / 3);
    (derived_idx, hash2.wrapping_add(z))
}

/// A mapping that is more or less equivalent to x mod N via Lemire's
/// multiply-and-shift trick (dcrd `fastReduce`).
fn fast_reduce(x: u64, n: u64) -> u64 {
    // The high 64 bits in a 128-bit product is the same as shifting
    // the entire product right by 64 bits.
    ((u128::from(x) * u128::from(n)) >> 64) as u64
}

/// Return an APBF using the given tuning parameters: the number of
/// most-recently added items that must always return true, the number
/// of slices which need consecutive matches, k, and the number of
/// additional slices, l (dcrd `NewFilterKL`).
///
/// Every new filter uses a unique key for the internal hashing logic
/// so that each one will have a unique set of false positives.  The
/// key is also automatically changed by [`Filter::reset`].
///
/// Note that, due to rounding, the actual max number of items that
/// can be added to the filter before old entries are expired might be
/// slightly higher than the specified target and can be obtained via
/// [`Filter::capacity`].
pub fn new_filter_kl(min_capacity: u32, k: u8, l: u8) -> Filter {
    // Calculate the number of items per generation such that the
    // maximum capacity (aka sliding window size) is at least the
    // specified number of items.
    //    w = g*(l+1)
    // => g = ceil(w/(l+1))
    let g = (f64::from(min_capacity) / (f64::from(l) + 1.0)).ceil() as u32;

    // Calculate the number of bits needed per slice based on the
    // number of items per generation and number of slices used for
    // filter insertions; optimal partitioned bloom filter usage is
    // asymptotically at a fill ratio of 1/2, yielding
    // bitsPerSlice = k*g / ln(2).
    let bits_per_slice = ((f64::from(k) * f64::from(g)) / core::f64::consts::LN_2).ceil() as u64;

    // The total filter size in bits is thus the total number of
    // slices multiplied by the number of bits per slice.
    let k_plus_l = u16::from(k).wrapping_add(u16::from(l));
    let filter_bytes = bits_per_slice
        .wrapping_mul(u64::from(k_plus_l))
        .wrapping_add(7)
        / 8;

    // The key does not need to be cryptographically secure since its
    // purpose is only to ensure filters created at different times
    // produce a different set of false positives.
    let s0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    let s1 = s0 ^ 0xa5a5a5a5a5a5a5a5;
    let seed = (s0 ^ 0x5a5a5a5a5a5a5a5a).to_be_bytes();
    let (key0, key1) = siphash128(s0, s1, &seed);
    Filter {
        key0,
        key1,
        k,
        l,
        k_plus_l,
        bits_per_slice,
        items_per_generation: g,
        items_in_cur_generation: 0,
        base_index: 0,
        data: vec![0u8; filter_bytes as usize],
    }
}

/// Calculate a near optimal number of hash functions to use based on
/// the desired false positive rate (dcrd `nearOptimalK`).
fn near_optimal_k(fp_rate: f64) -> u8 {
    (-fp_rate.log2()).ceil() as u8
}

/// Calculate a near optimal number of additional slices to use for a
/// given number of hash functions in order to maintain the desired
/// false positive rate (dcrd `nearOptimalL`).
fn near_optimal_l(k: u8, fp_rate: f64) -> u8 {
    // There is not currently a closed formula for calculating the
    // false positive rate of an APBF, so just brute force it since it
    // is only done once when the filter is created.
    const MAX_L: u8 = 100;
    let mut l = 1u8;
    while l <= MAX_L {
        let result = calc_fp_rate(k, l);
        if result > fp_rate {
            return l.wrapping_sub(1);
        }
        l = l.wrapping_add(1);
    }

    MAX_L
}

/// Return an APBF for the given number of most-recently added items
/// that must always return true and the target false positive rate to
/// maintain (dcrd `NewFilter`).
///
/// Both parameters are treated as lower bounds so that the returned
/// filter has at least the requested target values; the actual values
/// can be obtained via [`Filter::capacity`] and [`Filter::fp_rate`].
/// Applications that desire greater control over the tuning can make
/// use of [`new_filter_kl`] instead.
pub fn new_filter(min_capacity: u32, fp_rate: f64) -> Filter {
    let k = near_optimal_k(fp_rate);
    let l = near_optimal_l(k, fp_rate);
    new_filter_kl(min_capacity, k, l)
}
