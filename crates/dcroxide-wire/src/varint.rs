// SPDX-License-Identifier: ISC
//! Bitcoin-style variable-length integers with dcrd's canonical-encoding
//! enforcement (`ReadVarInt`/`WriteVarInt`/`VarIntSerializeSize`).

use alloc::vec::Vec;

use crate::cursor::Cursor;
use crate::error::WireError;

/// Read a variable-length integer, rejecting non-canonical encodings exactly
/// like dcrd's `ReadVarInt`.
pub fn read_var_int(r: &mut Cursor<'_>) -> Result<u64, WireError> {
    let discriminant = r.read_u8()?;
    match discriminant {
        0xff => {
            let rv = r.read_u64()?;
            // The encoding is not canonical if the value could have been
            // encoded using fewer bytes.
            let min = 0x1_0000_0000;
            if rv < min {
                return Err(WireError::NonCanonicalVarInt { value: rv, min });
            }
            Ok(rv)
        }
        0xfe => {
            let rv = u64::from(r.read_u32()?);
            let min = 0x1_0000;
            if rv < min {
                return Err(WireError::NonCanonicalVarInt { value: rv, min });
            }
            Ok(rv)
        }
        0xfd => {
            let rv = u64::from(r.read_u16()?);
            let min = 0xfd;
            if rv < min {
                return Err(WireError::NonCanonicalVarInt { value: rv, min });
            }
            Ok(rv)
        }
        _ => Ok(u64::from(discriminant)),
    }
}

/// Append the canonical variable-length encoding of `val`.
pub fn write_var_int(w: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        w.push(val as u8);
    } else if val <= u64::from(u16::MAX) {
        w.push(0xfd);
        w.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= u64::from(u32::MAX) {
        w.push(0xfe);
        w.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        w.push(0xff);
        w.extend_from_slice(&val.to_le_bytes());
    }
}

/// The number of bytes the canonical encoding of `val` occupies.
pub fn var_int_serialize_size(val: u64) -> usize {
    if val < 0xfd {
        1
    } else if val <= u64::from(u16::MAX) {
        3
    } else if val <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

/// Read a variable-length byte array bounded by `max_allowed`, mirroring
/// dcrd's `readScript`/`ReadVarBytes` limit behavior.
pub(crate) fn read_var_bytes(r: &mut Cursor<'_>, max_allowed: u64) -> Result<Vec<u8>, WireError> {
    let count = read_var_int(r)?;
    if count > max_allowed {
        return Err(WireError::VarBytesTooLong {
            count,
            max: max_allowed,
        });
    }
    Ok(r.take(count as usize)?.to_vec())
}

/// Append a variable-length byte array (varint length then the bytes).
pub(crate) fn write_var_bytes(w: &mut Vec<u8>, bytes: &[u8]) {
    write_var_int(w, bytes.len() as u64);
    w.extend_from_slice(bytes);
}

/// Read a variable-length string's raw bytes, limited to the maximum
/// message payload (dcrd `ReadVarString`; the bytes are returned so callers
/// can apply dcrd's strict-ASCII validation before conversion).
pub(crate) fn read_var_string_bytes(r: &mut Cursor<'_>) -> Result<Vec<u8>, WireError> {
    let count = read_var_int(r)?;
    if count > crate::MAX_MESSAGE_PAYLOAD {
        return Err(WireError::VarStringTooLong {
            count,
            max: crate::MAX_MESSAGE_PAYLOAD,
        });
    }
    Ok(r.take(count as usize)?.to_vec())
}

/// Read a strict-ASCII variable-length string limited to `max_allowed`
/// (dcrd `ReadAsciiVarString`).
pub(crate) fn read_ascii_var_string(
    r: &mut Cursor<'_>,
    max_allowed: u64,
) -> Result<alloc::string::String, WireError> {
    let count = read_var_int(r)?;
    let max = max_allowed.min(crate::MAX_MESSAGE_PAYLOAD);
    if count > max {
        return Err(WireError::VarStringTooLong { count, max });
    }
    let bytes = r.take(count as usize)?;
    if !crate::protocol::is_strict_ascii(bytes) {
        return Err(WireError::MalformedStrictString);
    }
    Ok(alloc::string::String::from_utf8(bytes.to_vec()).expect("strict ASCII is UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical encodings, ported from dcrd's TestVarIntWire.
    const CASES: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (0xfc, &[0xfc]),
        (0xfd, &[0xfd, 0xfd, 0x00]),
        (0xffff, &[0xfd, 0xff, 0xff]),
        (0x10000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
        (0xffffffff, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
        (
            0x100000000,
            &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        ),
        (
            u64::MAX,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];

    #[test]
    fn round_trips() {
        for &(val, bytes) in CASES {
            let mut buf = Vec::new();
            write_var_int(&mut buf, val);
            assert_eq!(buf, bytes, "encode {val:#x}");
            assert_eq!(var_int_serialize_size(val), bytes.len(), "size {val:#x}");

            let mut r = Cursor::new(bytes);
            assert_eq!(read_var_int(&mut r), Ok(val), "decode {val:#x}");
            assert_eq!(r.position(), bytes.len());
        }
    }

    /// Non-canonical encodings must be rejected, ported from dcrd's
    /// TestVarIntNonCanonical.
    #[test]
    fn non_canonical_rejected() {
        let cases: &[&[u8]] = &[
            &[0xfd, 0x00, 0x00],                                     // 0 as 3 bytes
            &[0xfd, 0xfc, 0x00],                                     // 0xfc as 3 bytes
            &[0xfe, 0xff, 0xff, 0x00, 0x00],                         // 0xffff as 5 bytes
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00], // 0xffffffff as 9
        ];
        for bytes in cases {
            let mut r = Cursor::new(bytes);
            assert!(
                matches!(
                    read_var_int(&mut r),
                    Err(WireError::NonCanonicalVarInt { .. })
                ),
                "{bytes:x?}"
            );
        }
    }

    #[test]
    fn truncated_is_eof() {
        for bytes in [&[0xfd, 0x01][..], &[0xfe, 0x01, 0x02][..], &[0xff][..]] {
            let mut r = Cursor::new(bytes);
            assert_eq!(read_var_int(&mut r), Err(WireError::UnexpectedEof));
        }
    }
}
