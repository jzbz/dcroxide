// SPDX-License-Identifier: ISC
//! SHA-256 and SHA-384 as rustls's `Hash`, the transcript hash of the
//! suites built on each (ring's `rustls-0.23.46/src/crypto/ring/hash.rs`).

use core::marker::PhantomData;

use rustls::crypto::hash::{self, HashAlgorithm};
use sha2::Digest;

/// SHA-256, for the suites named `_SHA256`.
pub(crate) static SHA256: Sha<sha2::Sha256> = Sha::new(HashAlgorithm::SHA256);
/// SHA-384, for the suites named `_SHA384`.
pub(crate) static SHA384: Sha<sha2::Sha384> = Sha::new(HashAlgorithm::SHA384);

/// The SHA-2 function `D` as a rustls hash.
pub(crate) struct Sha<D> {
    /// How rustls names the function.
    algorithm: HashAlgorithm,
    /// The function.
    digest: PhantomData<fn() -> D>,
}

impl<D> Sha<D> {
    /// The hash `D`, which rustls knows as `algorithm`.
    const fn new(algorithm: HashAlgorithm) -> Self {
        Sha {
            algorithm,
            digest: PhantomData,
        }
    }
}

impl<D: Digest + Clone + Send + Sync + 'static> hash::Hash for Sha<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Context(D::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

/// A hash computation in progress; forking clones it.
struct Context<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> hash::Context for Context<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
}
