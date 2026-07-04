// SPDX-License-Identifier: ISC
//! The Decred script engine, mirroring dcrd's `txscript` package (module
//! v4.1.2, as pinned by dcrd release-v2.1.5): tokenizer, script numbers,
//! the full 256-opcode set including Decred's stake and treasury opcodes,
//! the execution engine with all flag combinations, strict-encoding
//! checks, signature hashing, and the script builder.
//!
//! Parity notes (see PARITY.md for the full ledger):
//! - Error identity: every failure carries an [`ErrorKind`] whose
//!   [`ErrorKind::kind_name`] matches dcrd's `ErrorKind` string; the
//!   differential tests compare verdicts *and* kinds against dcrd through
//!   the oracle.
//! - dcrd's `SigCache` is not reproduced: it is a concurrency optimization
//!   that cannot change results; the engine here verifies directly.
//! - dcrd's `optimizeSigVerification` prefix-hash cache is permanently
//!   disabled dead code at the parity tag and is likewise not reproduced.
//!
//! The `stdaddr`/`stdscript`/`sign` subpackages are a separate crate phase.

#![cfg_attr(not(test), no_std)]
// The engine's arithmetic mirrors dcrd's Go semantics; every operation that
// can wrap does so deliberately via wrapping/checked forms, and index
// arithmetic is bounds-checked by construction (Rust panics would surface
// as test failures rather than silent divergence).
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

mod builder;
mod consensus;
mod engine;
mod error;
mod opcode_table;
mod opcodes;
mod script;
mod scriptnum;
mod sighash;
mod stack;
mod tokenizer;

pub use builder::{NotCanonicalError, ScriptBuilder, canonical_data_size};
pub use consensus::{
    LOCK_TIME_THRESHOLD, check_hash_type_encoding, check_pub_key_encoding,
    check_signature_encoding, is_strict_compressed_pub_key_encoding, is_strict_null_data,
    is_strict_signature_encoding,
};
pub use engine::{Engine, ScriptFlags};
pub use error::{ErrorKind, ScriptError};
pub use opcode_table::*;
pub use opcodes::{opcode_by_name, opcode_name};
pub use script::{
    as_small_int, contains_stake_op_codes, disasm_string, extract_script_hash,
    generate_ssgen_block_ref, generate_ssgen_votes, get_precise_sig_op_count, get_sig_op_count,
    is_pay_to_script_hash, is_push_only_script, is_small_int, is_unspendable,
};
pub use scriptnum::{
    CLTV_MAX_SCRIPT_NUM_LEN, CSV_MAX_SCRIPT_NUM_LEN, MATH_OP_CODE_MAX_SCRIPT_NUM_LEN, ScriptNum,
    make_script_num,
};
pub use sighash::{
    SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SERIALIZE_PREFIX,
    SIG_HASH_SERIALIZE_WITNESS, SIG_HASH_SINGLE, SigHashType, calc_signature_hash_as_hash,
    calc_signature_hash_checked,
};
pub use tokenizer::ScriptTokenizer;

/// Max number of non-push operations per script (dcrd `MaxOpsPerScript`).
pub const MAX_OPS_PER_SCRIPT: i32 = 255;

/// Max number of public keys per multisig (dcrd `MaxPubKeysPerMultiSig`).
pub const MAX_PUB_KEYS_PER_MULTI_SIG: usize = 20;

/// Max bytes pushable to the stack (dcrd `MaxScriptElementSize`).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 2048;

/// Max combined stack and alt stack height during execution (dcrd
/// `MaxStackSize`).
pub const MAX_STACK_SIZE: i32 = 1024;

/// Max allowed length of a raw script (dcrd `MaxScriptSize`).
pub const MAX_SCRIPT_SIZE: usize = 16384;
