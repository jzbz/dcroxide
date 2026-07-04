// SPDX-License-Identifier: ISC
//! Script tokenizer mirroring dcrd's `ScriptTokenizer` semantics, including
//! its exact `ErrMalformedPush` conditions and unsupported-version handling.

use alloc::format;
use core::ops::Range;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::opcodes::{opcode_length, opcode_name};

/// One successfully parsed opcode: its value, the range of its associated
/// data within the script, and the offset of the next opcode.
pub(crate) struct ParsedOpcode {
    pub op: u8,
    pub data: Range<usize>,
    pub next_offset: usize,
}

/// Parse the opcode at `offset`, mirroring dcrd `ScriptTokenizer.Next`.
/// Returns `Ok(None)` at end of script.
pub(crate) fn parse_opcode(
    script: &[u8],
    offset: usize,
) -> Result<Option<ParsedOpcode>, ScriptError> {
    if offset >= script.len() {
        return Ok(None);
    }

    let op = script[offset];
    let length = opcode_length(op);
    match length {
        // No additional data. Note that some opcodes, notably OP_1NEGATE,
        // OP_0, and OP_[1-16], represent the data themselves.
        1 => Ok(Some(ParsedOpcode {
            op,
            data: 0..0,
            next_offset: offset + 1,
        })),

        // Data pushes of specific lengths -- OP_DATA_[1-75].
        l if l > 1 => {
            let l = l as usize;
            let remaining = script.len() - offset;
            if remaining < l {
                return Err(script_error(
                    ErrorKind::MalformedPush,
                    format!(
                        "opcode {} requires {} bytes, but script only has {} remaining",
                        opcode_name(op),
                        l,
                        remaining
                    ),
                ));
            }
            Ok(Some(ParsedOpcode {
                op,
                data: offset + 1..offset + l,
                next_offset: offset + l,
            }))
        }

        // Data pushes with parsed lengths -- OP_PUSHDATA{1,2,4}.
        l => {
            let len_bytes = (-l) as usize;
            let script_after = &script[offset + 1..];
            if script_after.len() < len_bytes {
                return Err(script_error(
                    ErrorKind::MalformedPush,
                    format!(
                        "opcode {} requires {} bytes, but script only has {} remaining",
                        opcode_name(op),
                        len_bytes,
                        script_after.len()
                    ),
                ));
            }

            // The next len_bytes bytes are the little-endian length of the
            // data. dcrd reads these into an int32, so a 4-byte length with
            // the high bit set goes negative and is rejected below.
            let data_len: i32 = match len_bytes {
                1 => i32::from(script_after[0]),
                2 => i32::from(u16::from_le_bytes([script_after[0], script_after[1]])),
                4 => u32::from_le_bytes([
                    script_after[0],
                    script_after[1],
                    script_after[2],
                    script_after[3],
                ]) as i32,
                _ => unreachable!("opcode lengths are only -1, -2, or -4"),
            };

            let data_start = offset + 1 + len_bytes;
            let remaining = script.len() - data_start;

            // Disallow entries that do not fit the script or were sign
            // extended.
            if data_len < 0 || data_len as usize > remaining {
                return Err(script_error(
                    ErrorKind::MalformedPush,
                    format!(
                        "opcode {} pushes {} bytes, but script only has {} remaining",
                        opcode_name(op),
                        data_len,
                        remaining
                    ),
                ));
            }

            let data_len = data_len as usize;
            Ok(Some(ParsedOpcode {
                op,
                data: data_start..data_start + data_len,
                next_offset: data_start + data_len,
            }))
        }
    }
}

/// A facility for tokenizing transaction scripts without allocations (dcrd
/// `ScriptTokenizer`). Each successive opcode is parsed with [`Self::next`],
/// which returns false when iteration is complete, either due to reaching
/// the end of the script or a parse error, distinguishable via
/// [`Self::err`].
pub struct ScriptTokenizer<'a> {
    script: &'a [u8],
    offset: usize,
    op: u8,
    data: Range<usize>,
    err: Option<ScriptError>,
}

impl<'a> ScriptTokenizer<'a> {
    /// Create a tokenizer (dcrd `MakeScriptTokenizer`). Passing an
    /// unsupported script version results in the tokenizer immediately
    /// having an error set accordingly.
    pub fn new(script_version: u16, script: &'a [u8]) -> ScriptTokenizer<'a> {
        // Only version 0 scripts are currently supported.
        let err = if script_version != 0 {
            Some(script_error(
                ErrorKind::UnsupportedScriptVersion,
                format!("script version {script_version} is not supported"),
            ))
        } else {
            None
        };
        ScriptTokenizer {
            script,
            offset: 0,
            op: 0,
            data: 0..0,
            err,
        }
    }

    /// True when all opcodes are exhausted or a failure was encountered.
    pub fn done(&self) -> bool {
        self.err.is_some() || self.offset >= self.script.len()
    }

    /// Attempt to parse the next opcode, returning whether it succeeded.
    #[allow(clippy::should_implement_trait)] // Mirrors dcrd's Next, not Iterator.
    pub fn next(&mut self) -> bool {
        if self.done() {
            return false;
        }

        match parse_opcode(self.script, self.offset) {
            Ok(Some(parsed)) => {
                self.op = parsed.op;
                self.data = parsed.data;
                self.offset = parsed.next_offset;
                true
            }
            Ok(None) => false,
            Err(err) => {
                self.err = Some(err);
                false
            }
        }
    }

    /// The full script associated with the tokenizer.
    pub fn script(&self) -> &'a [u8] {
        self.script
    }

    /// The current offset into the full script that will be parsed next.
    pub fn byte_index(&self) -> usize {
        self.offset
    }

    /// The current opcode.
    pub fn opcode(&self) -> u8 {
        self.op
    }

    /// The data associated with the most recently parsed opcode.
    pub fn data(&self) -> &'a [u8] {
        &self.script[self.data.clone()]
    }

    /// Any error associated with the tokenizer.
    pub fn err(&self) -> Option<&ScriptError> {
        self.err.as_ref()
    }

    /// Consume the tokenizer and return its error, if any.
    pub fn into_err(self) -> Option<ScriptError> {
        self.err
    }
}
