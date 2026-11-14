// SPDX-License-Identifier: ISC
//! RPC client-certificate fuzz target: what the RPC listener does with a
//! client's certificates and its handshake signature under
//! `--authtype=clientcert`, before the client is authenticated, never
//! panics.
//!
//! Anyone who can reach the RPC port in that mode reaches this: the reader
//! every certificate the client sends goes through, the replay of Go's
//! chain search, webpki's search over the client CA pool, and the
//! handshake signature checks, which since the listener takes ML-DSA
//! client certificates run ML-DSA keys and signatures the client chooses
//! through the `ml-dsa` crate.  So under `panic = "abort"` a panic in any
//! of them would be a pre-authentication abort.  The input is a client's
//! whole certificate list, or one of three chains under an ML-DSA-44 root,
//! one for each ML-DSA set, with the input laid over the leaf's signature,
//! over the authority's key, or as a handshake signature by the leaf
//! (`rpcrun::fuzz_client_cert`); every key in those chains is a valid key
//! of zero bytes and every signature one that decodes, so the input
//! reaches the lattice arithmetic as well as the decoders.  A key of zero
//! bytes is one anyone can sign for, so an input that is accepted is no
//! failure.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcroxide_node::rpcrun::fuzz_client_cert(data);
});
