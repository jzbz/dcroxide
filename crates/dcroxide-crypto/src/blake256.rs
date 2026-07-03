// SPDX-License-Identifier: ISC
// Vendored from dcr-rs (https://github.com/jzbz/dcr-rs) at commit fd32c1a,
// ISC licensed. Known-answer vectors regenerated against dcrd
// `crypto/blake256` v1.1.0 (the version pinned by dcrd release-v2.1.5) via
// `tools/oracle`; see also `tests/oracle_differential.rs`.
//! BLAKE-256 (the SHA-3 finalist, 14 rounds) — NOT BLAKE2/BLAKE3.
//!
//! Decred hashes *everything* with this: transaction IDs, block hashes
//! (pre-BLAKE3-PoW), sighashes, address Hash160 (`ripemd160(blake256(x))`)
//! and the base58check checksum (`blake256(blake256(x))[..4]`). It is the
//! single most load-bearing primitive in the project, so it is vendored here
//! and pinned by known-answer vectors generated from dcrd's `crypto/blake256`
//! Go package for every padding path (see the test module), plus a live
//! differential test against the dcrd oracle in `tools/oracle`.
//!
//! Reference: dcrd `crypto/blake256` (Go), original BLAKE spec.

// Hash-core arithmetic: loop indices are bounded by fixed block/state sizes,
// the bit counter cannot overflow u64 for any physical message, and wrapping
// ops are already explicit where the algorithm calls for them.
#![allow(clippy::arithmetic_side_effects)]

/// Digest length in bytes.
pub const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;

#[rustfmt::skip]
const IV: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

// Fractional bits of pi — the BLAKE round constants.
#[rustfmt::skip]
const C: [u32; 16] = [
    0x243f_6a88, 0x85a3_08d3, 0x1319_8a2e, 0x0370_7344,
    0xa409_3822, 0x299f_31d0, 0x082e_fa98, 0xec4e_6c89,
    0x4528_21e6, 0x38d0_1377, 0xbe54_66cf, 0x34e9_0c6c,
    0xc0ac_29b7, 0xc97c_50dd, 0x3f84_d5b5, 0xb547_0917,
];

#[rustfmt::skip]
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Incremental BLAKE-256 hasher.
///
/// ```
/// let mut h = dcroxide_crypto::blake256::Blake256::new();
/// h.update(b"hello ");
/// h.update(b"world");
/// assert_eq!(h.finalize(), dcroxide_crypto::blake256::sum256(b"hello world"));
/// ```
#[derive(Clone)]
pub struct Blake256 {
    h: [u32; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Message bits compressed so far (full blocks only).
    compressed_bits: u64,
}

impl Default for Blake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake256 {
    /// Fresh hasher state.
    pub fn new() -> Self {
        Blake256 {
            h: IV,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            compressed_bits: 0,
        }
    }

    /// Compress one 64-byte block. `counter` is the total message bit length
    /// this block commits to (0 for a padding-only final block — the BLAKE
    /// edge case).
    fn compress(&mut self, block: &[u8; BLOCK_LEN], counter: u64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let t0 = counter as u32;
        let t1 = (counter >> 32) as u32;

        // salt is always zero in Decred's usage.
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8] = C[0];
        v[9] = C[1];
        v[10] = C[2];
        v[11] = C[3];
        v[12] = C[4] ^ t0;
        v[13] = C[5] ^ t0;
        v[14] = C[6] ^ t1;
        v[15] = C[7] ^ t1;

        #[inline(always)]
        fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }

        #[rustfmt::skip]
        fn rounds(v: &mut [u32; 16], m: &[u32; 16]) {
            for r in 0..14 {
                let s = &SIGMA[r % 10];
                // Each G mixes in m[s[2i]] ^ C[s[2i+1]] then m[s[2i+1]] ^ C[s[2i]].
                g(v, 0, 4,  8, 12, m[s[0]]  ^ C[s[1]],  m[s[1]]  ^ C[s[0]]);
                g(v, 1, 5,  9, 13, m[s[2]]  ^ C[s[3]],  m[s[3]]  ^ C[s[2]]);
                g(v, 2, 6, 10, 14, m[s[4]]  ^ C[s[5]],  m[s[5]]  ^ C[s[4]]);
                g(v, 3, 7, 11, 15, m[s[6]]  ^ C[s[7]],  m[s[7]]  ^ C[s[6]]);
                g(v, 0, 5, 10, 15, m[s[8]]  ^ C[s[9]],  m[s[9]]  ^ C[s[8]]);
                g(v, 1, 6, 11, 12, m[s[10]] ^ C[s[11]], m[s[11]] ^ C[s[10]]);
                g(v, 2, 7,  8, 13, m[s[12]] ^ C[s[13]], m[s[13]] ^ C[s[12]]);
                g(v, 3, 4,  9, 14, m[s[14]] ^ C[s[15]], m[s[15]] ^ C[s[14]]);
            }
        }
        rounds(&mut v, &m);

        for i in 0..8 {
            // salt == 0, so the salt XOR terms vanish.
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Absorb message bytes. May be called any number of times.
    pub fn update(&mut self, mut data: &[u8]) {
        // Top up a partially filled buffer first.
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                self.compressed_bits += (BLOCK_LEN as u64) * 8;
                let block = self.buf;
                self.compress(&block, self.compressed_bits);
                self.buf_len = 0;
            }
            if data.is_empty() {
                // Everything fit in the buffer; don't let the remainder logic
                // below clobber buf_len.
                return;
            }
        }

        // Full blocks straight from the input.
        let mut chunks = data.chunks_exact(BLOCK_LEN);
        for blk in &mut chunks {
            self.compressed_bits += (BLOCK_LEN as u64) * 8;
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(blk);
            self.compress(&b, self.compressed_bits);
        }

        let rem = chunks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    /// Consume the hasher and return the 32-byte digest.
    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        let rem = self.buf_len;
        let total_bits = self.compressed_bits + (rem as u64) * 8;

        // Padding: 0x80, zeros, a 0x01 terminator bit before the 64-bit BE
        // length. If the remainder leaves no room for the 9 trailing bytes,
        // emit two blocks.
        let mut last = [0u8; BLOCK_LEN];
        last[..rem].copy_from_slice(&self.buf[..rem]);
        last[rem] = 0x80;

        if rem <= 55 {
            // Single final block holds data bits + length.
            last[55] |= 0x01;
            last[56..].copy_from_slice(&total_bits.to_be_bytes());
            // The counter must reflect the message bits in THIS block: zero
            // for a padding-only block (message was a multiple of 64 bytes).
            let counter = if rem == 0 && total_bits != 0 {
                0
            } else {
                total_bits
            };
            self.compress(&last, counter);
        } else {
            // First padding block carries the remaining data bits (counter =
            // total), second block is length-only (counter = 0).
            self.compress(&last, total_bits);
            let mut tail = [0u8; BLOCK_LEN];
            tail[55] |= 0x01;
            tail[56..].copy_from_slice(&total_bits.to_be_bytes());
            self.compress(&tail, 0);
        }

        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// One-shot BLAKE-256.
pub fn sum256(data: &[u8]) -> [u8; OUT_LEN] {
    let mut st = Blake256::new();
    st.update(data);
    st.finalize()
}

/// `blake256(blake256(x))` — used by the base58check checksum and TxHash.
pub fn sum256d(data: &[u8]) -> [u8; OUT_LEN] {
    sum256(&sum256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Known-answer vectors generated from dcrd's `crypto/blake256` Go package
    /// over the pattern `data[i] = i as u8`. Lengths chosen to hit every
    /// padding path: empty, short, the 55/56 single-vs-double padding-block
    /// boundary, exact block multiples, and multi-block messages.
    const DCRD_KATS: &[(usize, &str)] = &[
        (
            0,
            "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
        ),
        (
            1,
            "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87",
        ),
        (
            32,
            "7b436b39de7d670e0cfe96d08f3c7651897d2502d71b37f031566e2bacbf4d16",
        ),
        (
            54,
            "6df0b232d9b4e86db83389705549c7f562b0700f7832d8a45062c7a87f550b59",
        ),
        (
            55,
            "d7ec78bc615d99e41d371cf6401449969144b5f789bde014a9aeafd8987257f2",
        ),
        (
            56,
            "26ca422697c9fabc642129b1a5669be07fb0a3c31f14f1c7859e048ad5958e44",
        ),
        (
            57,
            "dc195afd20d35ee995b7ccc090ff139b6ca0782ff7188acfb08c9420ad71daa3",
        ),
        (
            63,
            "cfce445066d35322557b432540bd2f0af4caf9f426568236d9944426a5df792a",
        ),
        (
            64,
            "4432b2c1e983b0c326583516920f3949c2acf5d85a99353601228cab40c867bc",
        ),
        (
            65,
            "106cdd00dc14e257b1130d026b9fcc2c5ecbaae08fec13af0002ad6054c7bbd5",
        ),
        (
            119,
            "7271691baf3f4ea7795006522897316eccd614816fa4fe10c546c11e882ac016",
        ),
        (
            120,
            "6b4831d9c2ab2403b17ce7063f804ce559db6951563678294acd9a0a418bab35",
        ),
        (
            121,
            "bf3937b82aa6021d6dc77a967f5ded0387ab11a1b325325c1eb098260655c76c",
        ),
        (
            127,
            "1446de0b1bc379c8b05fef5b9af281f322904af57c217351057cc955fd89d58a",
        ),
        (
            128,
            "70a7b33d6d251c06757362fa717d0b19ceb0ebdccf48300a98156b5bb6b8c9a5",
        ),
        (
            129,
            "e382768b94ee0f9e7539b78c6252dbd3dcf54bc53de9670a02d85b6fc92d7e76",
        ),
        (
            200,
            "c4d944c2b1c00a8ee627726b35d4cd7fe018de090bc637553cc782e25f974cba",
        ),
    ];

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    #[test]
    fn dcrd_generated_kats() {
        for &(n, want) in DCRD_KATS {
            assert_eq!(hex(&sum256(&pattern(n))), want, "one-shot, len {n}");
        }
    }

    #[test]
    fn incremental_matches_one_shot_for_every_split() {
        // Feed each KAT message in two pieces at every possible split point:
        // the buffered/full-block/remainder paths in update() all get hit.
        for &(n, want) in DCRD_KATS {
            let data = pattern(n);
            for split in 0..=n {
                let mut h = Blake256::new();
                h.update(&data[..split]);
                h.update(&data[split..]);
                assert_eq!(hex(&h.finalize()), want, "len {n}, split {split}");
            }
        }
    }

    #[test]
    fn incremental_byte_at_a_time() {
        let data = pattern(200);
        let mut h = Blake256::new();
        for b in &data {
            h.update(core::slice::from_ref(b));
        }
        assert_eq!(h.finalize(), sum256(&data));
    }

    #[test]
    fn empty_string_kat() {
        // Canonical BLAKE-256 known-answer test.
        assert_eq!(
            hex(&sum256(b"")),
            "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
        );
    }

    #[test]
    fn single_zero_byte_kat() {
        assert_eq!(
            hex(&sum256(&[0u8])),
            "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87"
        );
    }

    #[test]
    fn double_hash_kat() {
        // blake256d("") == blake256(blake256("")).
        assert_eq!(sum256d(b""), sum256(&sum256(b"")));
    }
}
