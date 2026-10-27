// SPDX-License-Identifier: ISC
//! Where the provider's random bytes come from: the kernel, through
//! [`kernel_fill`], for every byte rustls asks its `SecureRandom` for (the
//! handshake randoms, a client's legacy session id and extension-order
//! seed) and for every ephemeral key the key exchanges draw.
//!
//! Go's `crypto/tls` reads its standard library's `crypto/rand` for all of
//! these (`Config.rand`, `crypto/tls/common.go:1167-1173`; the ephemeral
//! keys at `handshake_server_tls13.go:254` and `key_agreement.go:173`,
//! `:312`), not dcrd's package generator, and ring's provider read the
//! kernel for them too (`rustls-0.23.46/src/crypto/ring/mod.rs:37`).
//! Not the process-wide generator of `dcroxide_crypto::rand` either, for a
//! reason of its own: an ephemeral scalar is the session's whole secret,
//! and that generator keeps its ChaCha20 key for up to 4 MiB of draws, so
//! a later read of the process's memory would recover every scalar drawn
//! since it was last keyed, where the kernel's generator erases its key as
//! it goes.
//!
//! A failed read is rustls's `GetRandomFailed`, which fails the one
//! handshake that asked, as a failed read fails ring's, and cannot abort
//! the process.
//!
//! One draw goes to the process-wide generator of `dcroxide_crypto::rand`
//! instead, through [`ProcessRng`]: the additional data an ECDSA
//! handshake signature mixes into its RFC 6979 nonce.  RFC 6979 derives
//! the nonce from the key and the message, so the signature is safe
//! should that draw be weak, and the draw only makes two signatures of
//! the same transcript differ, as Go's and ring's hedged nonces do.  A
//! handshake is paced by a peer, and that generator, seeded once at
//! startup, cannot fail after it, where a kernel read can (the node's
//! `tests/entropy_policy.rs` gives the reasons for its draws).
//!
//! `tests/entropy_policy.rs` holds the crate to the one kernel read and
//! the one draw from the process generator, and each to its place.

use rustls::crypto::{GetRandomFailed, SecureRandom};

/// Fill `buf` from the kernel's generator, through the `getrandom` crate:
/// the crate's only kernel read.
pub(crate) fn kernel_fill(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    checked_fill(getrandom::fill, buf)
}

/// Fill `buf` with `read`, a failed read returned as `GetRandomFailed` for
/// the one handshake that asked: [`kernel_fill`] with its kernel read
/// passed in, so that a test can make the read fail, which the kernel's
/// cannot be made to do.
fn checked_fill<E>(
    read: impl FnOnce(&mut [u8]) -> Result<(), E>,
    buf: &mut [u8],
) -> Result<(), GetRandomFailed> {
    read(buf).map_err(|_| GetRandomFailed)
}

/// The provider's `SecureRandom`: each call one [`kernel_fill`].
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the provider value takes it once verification is in as well \
                  (ADR-0015, step 1); until then only its tests do"
    )
)]
pub(crate) struct KernelRandom;

impl SecureRandom for KernelRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        kernel_fill(buf)
    }
}

/// The process-wide generator ([`dcroxide_crypto::rand`]) as the source
/// of an ECDSA signature's hedge, which `sign.rs` draws for each
/// handshake it signs.
///
/// The generator produces keystream by XOR, so the buffer is zeroed
/// before the draw.  It cannot fail once seeded, which the daemon does at
/// startup (`dcroxide_crypto::rand::init`), so the draw has no error.
#[derive(Debug)]
pub(crate) struct ProcessRng;

impl ProcessRng {
    /// Fill `buf` from the process-wide generator.
    pub(crate) fn fill(&self, buf: &mut [u8]) {
        buf.fill(0);
        dcroxide_crypto::rand::read(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every length rustls and the key exchanges ask for reads, none at
    /// all included, through [`kernel_fill`] and through the
    /// `SecureRandom`, and each read writes every byte of its buffer: the
    /// OR of 64 reads into zeroed buffers has every bit set, where a byte
    /// a read leaves alone stays zero.  A bit is left clear by chance with
    /// odds of 2^-64, under 2^-52 for the test's 2,448 bits.  Two 32-byte
    /// reads differ, as fresh reads do but for odds of 2^-256.
    #[test]
    fn each_read_fills_its_buffer() {
        type Read = fn(&mut [u8]) -> Result<(), GetRandomFailed>;
        let reads: [(&str, Read); 2] = [
            ("kernel_fill", kernel_fill),
            ("KernelRandom", |buf| KernelRandom.fill(buf)),
        ];
        for (name, read) in reads {
            for len in [0, 1, 2, 4, 32, 48, 66] {
                let mut written = vec![0u8; len];
                for _ in 0..64 {
                    let mut buf = vec![0; len];
                    read(&mut buf).unwrap_or_else(|_| panic!("{name}: a read of {len}"));
                    for (seen, byte) in written.iter_mut().zip(&buf) {
                        *seen |= byte;
                    }
                }
                assert!(
                    written.iter().all(|&byte| byte == 0xff),
                    "{name}: a read of {len} left bits unwritten: {written:02x?}"
                );
            }
        }
        let (mut first, mut second) = ([0; 32], [0; 32]);
        KernelRandom.fill(&mut first).expect("the first read");
        kernel_fill(&mut second).expect("the second read");
        assert_ne!(first, second, "fresh bytes each read");
    }

    /// Every length an ECDSA hedge takes, the three curves' field
    /// lengths, is written in full by the process generator, as the
    /// kernel reads are above, and two draws differ.
    #[test]
    fn each_process_draw_fills_its_buffer() {
        for len in [32, 48, 66] {
            let mut written = vec![0u8; len];
            for _ in 0..64 {
                let mut buf = vec![0xa5; len];
                ProcessRng.fill(&mut buf);
                for (seen, byte) in written.iter_mut().zip(&buf) {
                    *seen |= byte;
                }
            }
            assert!(
                written.iter().all(|&byte| byte == 0xff),
                "a draw of {len} left bits unwritten: {written:02x?}"
            );
        }
        let (mut first, mut second) = ([0; 32], [0; 32]);
        ProcessRng.fill(&mut first);
        ProcessRng.fill(&mut second);
        assert_ne!(first, second, "fresh bytes each draw");
    }

    /// A read that fails is `GetRandomFailed`, for the handshake to fail
    /// on, never a buffer passed on as though it had been written; one
    /// that succeeds leaves what it wrote.
    #[test]
    fn a_failed_read_is_get_random_failed() {
        let mut buf = [0; 32];
        assert!(matches!(
            checked_fill(|_| Err(()), &mut buf),
            Err(GetRandomFailed)
        ));
        let written = checked_fill(
            |buf: &mut [u8]| {
                buf.fill(1);
                Ok::<_, ()>(())
            },
            &mut buf,
        );
        assert!(written.is_ok());
        assert_eq!(buf, [1; 32]);
    }
}
