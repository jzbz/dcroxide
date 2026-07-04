// SPDX-License-Identifier: ISC
//! Script numbers with dcrd's exact consensus semantics (`scriptnum.go`).

use alloc::format;
use alloc::vec::Vec;

use crate::error::{ErrorKind, ScriptError, script_error};

/// The maximum number of bytes data being interpreted as an integer may be
/// for the majority of opcodes (dcrd `MathOpCodeMaxScriptNumLen`).
pub const MATH_OP_CODE_MAX_SCRIPT_NUM_LEN: usize = 4;

/// The maximum script number length for OP_CHECKLOCKTIMEVERIFY (dcrd
/// `CltvMaxScriptNumLen`): 5 bytes to cover the full u32 locktime range.
pub const CLTV_MAX_SCRIPT_NUM_LEN: usize = 5;

/// The maximum script number length for OP_CHECKSEQUENCEVERIFY (dcrd
/// `CsvMaxScriptNumLen`): 5 bytes to cover the full u32 sequence range.
pub const CSV_MAX_SCRIPT_NUM_LEN: usize = 5;

/// The maximum number of bytes for an alternative-signature-suite type
/// (dcrd `altSigSuitesMaxscriptNumLen`).
pub(crate) const ALT_SIG_SUITES_MAX_SCRIPT_NUM_LEN: usize = 1;

/// A numeric value used in the scripting engine (dcrd `ScriptNum`).
///
/// Numbers are stored on the stacks encoded as little endian with a sign
/// bit. Numeric opcode results are held as i64 so overflow past the 4-byte
/// input range remains representable (and re-encodable) exactly like dcrd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ScriptNum(pub i64);

/// Returns an error if the passed encoding is not minimal (dcrd
/// `checkMinimalDataEncoding`); also rejects negative zero `[0x80]`.
pub(crate) fn check_minimal_data_encoding(v: &[u8]) -> Result<(), ScriptError> {
    if v.is_empty() {
        return Ok(());
    }

    // If the most-significant-byte - excluding the sign bit - is zero the
    // encoding is not minimal, except when the sign bit would otherwise
    // conflict with the second-most-significant byte (e.g. +-255 encode to
    // 0xff00/0xff80).
    if v[v.len() - 1] & 0x7f == 0 && (v.len() == 1 || v[v.len() - 2] & 0x80 == 0) {
        let hex: alloc::string::String = v.iter().map(|b| format!("{b:02x}")).collect();
        return Err(script_error(
            ErrorKind::MinimalData,
            format!("numeric value encoded as {hex} is not minimally encoded"),
        ));
    }

    Ok(())
}

impl ScriptNum {
    /// The number serialized as little endian with a sign bit (dcrd
    /// `ScriptNum.Bytes`); zero encodes as an empty vector.
    pub fn bytes(self) -> Vec<u8> {
        let n = self.0;
        if n == 0 {
            return Vec::new();
        }

        let is_negative = n < 0;
        let mut nu64 = n.unsigned_abs();

        let mut result = Vec::with_capacity(9);
        while nu64 > 0 {
            result.push((nu64 & 0xff) as u8);
            nu64 >>= 8;
        }

        // When the most significant byte already has the high bit set, an
        // additional high byte is required to hold the sign; otherwise the
        // high bit of the most significant byte denotes the sign directly.
        let last = result.len() - 1;
        if result[last] & 0x80 != 0 {
            result.push(if is_negative { 0x80 } else { 0x00 });
        } else if is_negative {
            result[last] |= 0x80;
        }

        result
    }

    /// The number clamped to a valid i32 (dcrd `ScriptNum.Int32`): values
    /// out of range saturate rather than truncate, per consensus.
    pub fn int32(self) -> i32 {
        if self.0 > i64::from(i32::MAX) {
            return i32::MAX;
        }
        if self.0 < i64::from(i32::MIN) {
            return i32::MIN;
        }
        self.0 as i32
    }
}

/// Interpret the passed serialized bytes as an encoded integer (dcrd
/// `MakeScriptNum`), enforcing the maximum encoded length and minimal
/// encoding.
pub fn make_script_num(v: &[u8], script_num_len: usize) -> Result<ScriptNum, ScriptError> {
    if v.len() > script_num_len {
        let hex: alloc::string::String = v.iter().map(|b| format!("{b:02x}")).collect();
        return Err(script_error(
            ErrorKind::NumOutOfRange,
            format!(
                "numeric value encoded as {hex} is {} bytes which exceeds the max allowed of {}",
                v.len(),
                script_num_len
            ),
        ));
    }

    check_minimal_data_encoding(v)?;

    // Zero is encoded as an empty byte slice.
    if v.is_empty() {
        return Ok(ScriptNum(0));
    }

    // Decode from little endian.
    let mut result: i64 = 0;
    for (i, val) in v.iter().enumerate() {
        result |= i64::from(*val) << (8 * i as u32);
    }

    // When the most significant byte of the input has the sign bit set,
    // remove it from the result and negate.
    if v[v.len() - 1] & 0x80 != 0 {
        result &= !(0x80i64 << (8 * (v.len() - 1) as u32));
        return Ok(ScriptNum(-result));
    }

    Ok(ScriptNum(result))
}
