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
//! the process.  `tests/entropy_policy.rs` holds the crate to this one
//! read.

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
        reason = "the provider value takes it once signing and verification are in \
                  (ADR-0015, step 1); until then only its tests do"
    )
)]
pub(crate) struct KernelRandom;

impl SecureRandom for KernelRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        kernel_fill(buf)
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
