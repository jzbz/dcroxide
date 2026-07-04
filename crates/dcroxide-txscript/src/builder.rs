// SPDX-License-Identifier: ISC
//! Script builder (dcrd `scriptbuilder.go`) with canonical push selection
//! and dcrd's exact size-limit error behavior.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::opcode_table::{
    OP_0, OP_1, OP_1NEGATE, OP_DATA_1, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
};
use crate::scriptnum::ScriptNum;
use crate::{MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE};

/// The default initial allocation for a script being built (dcrd
/// `defaultScriptAlloc`).
const DEFAULT_SCRIPT_ALLOC: usize = 500;

/// Identifies a non-canonical script (dcrd `ErrScriptNotCanonical`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCanonicalError(pub String);

impl fmt::Display for NotCanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for NotCanonicalError {}

/// A facility for building custom scripts (dcrd `ScriptBuilder`): pushes
/// opcodes, ints, and data while respecting canonical encoding. Pushes that
/// would exceed the engine limits leave the script unmodified and surface
/// as an error from [`Self::script`].
pub struct ScriptBuilder {
    script: Vec<u8>,
    err: Option<NotCanonicalError>,
}

impl Default for ScriptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptBuilder {
    /// A new script builder (dcrd `NewScriptBuilder`).
    pub fn new() -> ScriptBuilder {
        ScriptBuilder {
            script: Vec::with_capacity(DEFAULT_SCRIPT_ALLOC),
            err: None,
        }
    }

    /// Push opcodes with no size checks (dcrd `AddOpsUnchecked`); intended
    /// for tests that intentionally exceed limits.
    pub fn add_ops_unchecked(mut self, opcodes: &[u8]) -> Self {
        if self.err.is_some() {
            return self;
        }
        self.script.extend_from_slice(opcodes);
        self
    }

    /// Push an opcode to the end of the script (dcrd `AddOp`).
    pub fn add_op(mut self, opcode: u8) -> Self {
        if self.err.is_some() {
            return self;
        }

        if self.script.len() + 1 > MAX_SCRIPT_SIZE {
            self.err = Some(NotCanonicalError(format!(
                "adding an opcode would exceed the maximum allowed canonical script \
                 length of {MAX_SCRIPT_SIZE}"
            )));
            return self;
        }

        self.script.push(opcode);
        self
    }

    /// Push opcodes to the end of the script (dcrd `AddOps`).
    pub fn add_ops(mut self, opcodes: &[u8]) -> Self {
        if self.err.is_some() {
            return self;
        }

        if self.script.len() + opcodes.len() > MAX_SCRIPT_SIZE {
            self.err = Some(NotCanonicalError(format!(
                "adding opcodes would exceed the maximum allowed canonical script \
                 length of {MAX_SCRIPT_SIZE}"
            )));
            return self;
        }

        self.script.extend_from_slice(opcodes);
        self
    }

    /// Push data with the canonical opcode for its length; internal, no
    /// limits (dcrd `addData`).
    fn add_data_internal(mut self, data: &[u8]) -> Self {
        let data_len = data.len();

        // When the data consists of a single number representable by a
        // "small integer" opcode, use that opcode.
        if data_len == 0 || (data_len == 1 && data[0] == 0) {
            self.script.push(OP_0);
            return self;
        }
        if data_len == 1 && data[0] <= 16 {
            self.script.push(OP_1 - 1 + data[0]);
            return self;
        }
        if data_len == 1 && data[0] == 0x81 {
            self.script.push(OP_1NEGATE);
            return self;
        }

        // Use one of the OP_DATA_# opcodes when the data is small enough,
        // otherwise the smallest possible OP_PUSHDATA#.
        if data_len < usize::from(OP_PUSHDATA1) {
            self.script.push(OP_DATA_1 - 1 + data_len as u8);
        } else if data_len <= 0xff {
            self.script.push(OP_PUSHDATA1);
            self.script.push(data_len as u8);
        } else if data_len <= 0xffff {
            self.script.push(OP_PUSHDATA2);
            self.script
                .extend_from_slice(&(data_len as u16).to_le_bytes());
        } else {
            self.script.push(OP_PUSHDATA4);
            self.script
                .extend_from_slice(&(data_len as u32).to_le_bytes());
        }

        self.script.extend_from_slice(data);
        self
    }

    /// Push data with no size checks (dcrd `AddDataUnchecked`); intended
    /// for tests that intentionally exceed limits.
    pub fn add_data_unchecked(self, data: &[u8]) -> Self {
        if self.err.is_some() {
            return self;
        }
        self.add_data_internal(data)
    }

    /// Push data with the canonical opcode for its length (dcrd
    /// `AddData`), enforcing both the maximum script size and the maximum
    /// element size.
    pub fn add_data(mut self, data: &[u8]) -> Self {
        if self.err.is_some() {
            return self;
        }

        let data_size = canonical_data_size(data);
        if self.script.len() + data_size > MAX_SCRIPT_SIZE {
            self.err = Some(NotCanonicalError(format!(
                "adding {data_size} bytes of data would exceed the maximum allowed \
                 canonical script length of {MAX_SCRIPT_SIZE}"
            )));
            return self;
        }

        let data_len = data.len();
        if data_len > MAX_SCRIPT_ELEMENT_SIZE {
            self.err = Some(NotCanonicalError(format!(
                "adding a data element of {data_len} bytes would exceed the maximum \
                 allowed script element size of {MAX_SCRIPT_ELEMENT_SIZE}"
            )));
            return self;
        }

        self.add_data_internal(data)
    }

    /// Push an integer to the end of the script (dcrd `AddInt64`).
    pub fn add_int64(mut self, val: i64) -> Self {
        if self.err.is_some() {
            return self;
        }

        if self.script.len() + 1 > MAX_SCRIPT_SIZE {
            self.err = Some(NotCanonicalError(format!(
                "adding an integer would exceed the maximum allow canonical script \
                 length of {MAX_SCRIPT_SIZE}"
            )));
            return self;
        }

        // Fast path for small integers and OP_1NEGATE.
        if val == 0 {
            self.script.push(OP_0);
            return self;
        }
        if val == -1 || (1..=16).contains(&val) {
            self.script.push(((i64::from(OP_1) - 1) + val) as u8);
            return self;
        }

        self.add_data(&ScriptNum(val).bytes())
    }

    /// Reset the script to no content (dcrd `Reset`).
    pub fn reset(mut self) -> Self {
        self.script.clear();
        self.err = None;
        self
    }

    /// The currently built script, or the first error encountered while
    /// building it (dcrd `Script`).
    pub fn script(self) -> Result<Vec<u8>, NotCanonicalError> {
        match self.err {
            Some(err) => Err(err),
            None => Ok(self.script),
        }
    }

    /// The currently built script regardless of any error, containing
    /// everything appended before the first failure. This matches the dcrd
    /// call sites that discard the error from `Script()` (e.g. the signing
    /// merge paths).
    pub fn unchecked_script(self) -> Vec<u8> {
        self.script
    }
}

/// The number of bytes the canonical encoding of the data will take (dcrd
/// `CanonicalDataSize`).
pub fn canonical_data_size(data: &[u8]) -> usize {
    let data_len = data.len();

    // Data representable by a "small integer" opcode is a single byte.
    if data_len == 0 || (data_len == 1 && (data[0] <= 16 || data[0] == 0x81)) {
        return 1;
    }

    if data_len < usize::from(OP_PUSHDATA1) {
        1 + data_len
    } else if data_len <= 0xff {
        2 + data_len
    } else if data_len <= 0xffff {
        3 + data_len
    } else {
        5 + data_len
    }
}
