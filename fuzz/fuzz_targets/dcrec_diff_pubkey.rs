// SPDX-License-Identifier: ISC
//! Differential fuzz target for secp256k1 public key parsing, in both the
//! ECDSA and the Schnorr parser: the first input byte picks one of
//! dcroxide-sigdiff's public key classes (`fuzz::Target::Pubkey`), the next
//! eight the case index, and the rest is the class generator's entropy.
//! Every request of the case is answered by dcroxide-dcrec and, through
//! tools/oracle, by dcrd's own code, and any difference panics with the
//! case, the requests and both answers; `sigsoak fuzz-replay` replays a
//! crash input without libFuzzer.  It needs the oracle, as the
//! differential tests do (DCROXIDE_ORACLE_BIN, or Go on PATH to build
//! tools/oracle), and stops before fuzzing without one.

#![no_main]

use dcroxide_sigdiff::fuzz::{self, Target};
use dcroxide_sigdiff::run::ours_answerer;
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(
    init: fuzz::init_oracle_target(),
    |data: &[u8]| -> Corpus {
        if fuzz::fuzz_one(Target::Pubkey, data, &ours_answerer(None)) {
            Corpus::Keep
        } else {
            Corpus::Reject
        }
    }
);
