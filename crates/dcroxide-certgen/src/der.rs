// SPDX-License-Identifier: ISC
//! A minimal DER writer producing the exact encodings Go's
//! `crypto/x509` and `encoding/asn1` emit for the certificate shapes
//! dcrd generates.

// Bounded length arithmetic over small buffers.
#![allow(clippy::arithmetic_side_effects)]

/// Wrap content in a tag-length-value triple.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE.
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// A SET.
pub fn set(content: &[u8]) -> Vec<u8> {
    tlv(0x31, content)
}

/// A context-specific constructed element.
pub fn context(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// An ASN.1 INTEGER from unsigned big-endian magnitude bytes,
/// applying minimal encoding with a leading zero when the high bit is
/// set (Go `encoding/asn1` big.Int marshaling).
pub fn integer_from_unsigned(mag: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = mag.iter().copied().skip_while(|b| *b == 0).collect();
    if bytes.is_empty() {
        bytes.push(0);
    } else if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

/// A small non-negative INTEGER.
pub fn integer_u64(v: u64) -> Vec<u8> {
    integer_from_unsigned(&v.to_be_bytes())
}

/// A BOOLEAN.
pub fn boolean(v: bool) -> Vec<u8> {
    tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

/// An OCTET STRING.
pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

/// A BIT STRING with no unused bits.
pub fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut inner = vec![0u8];
    inner.extend_from_slice(content);
    tlv(0x03, &inner)
}

/// A BIT STRING from named bits, trimming trailing zero bits exactly
/// as Go's `asn1.BitString` marshaling does.
pub fn bit_string_named(bits: &[bool]) -> Vec<u8> {
    let bit_length = bits.iter().rposition(|b| *b).map(|i| i + 1).unwrap_or(0);
    let num_bytes = bit_length.div_ceil(8);
    let mut data = vec![0u8; num_bytes];
    for (i, set) in bits.iter().enumerate().take(bit_length) {
        if *set {
            data[i / 8] |= 0x80 >> (i % 8);
        }
    }
    let unused = (num_bytes * 8 - bit_length) as u8;
    let mut inner = vec![unused];
    inner.extend_from_slice(&data);
    tlv(0x03, &inner)
}

/// An OBJECT IDENTIFIER from its arc components.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    content.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        let mut tmp = Vec::new();
        let mut n = arc;
        tmp.push((n & 0x7f) as u8);
        n >>= 7;
        while n > 0 {
            tmp.push(0x80 | (n & 0x7f) as u8);
            n >>= 7;
        }
        tmp.reverse();
        content.extend_from_slice(&tmp);
    }
    tlv(0x06, &content)
}

/// Whether a string fits ASN.1 PrintableString, using Go
/// `encoding/asn1`'s acceptance (which additionally allows `*` and
/// `&` for legacy compatibility).
fn is_printable(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_uppercase()
            || b.is_ascii_digit()
            || matches!(
                b,
                b'\''
                    | b'('
                    | b')'
                    | b'+'
                    | b','
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b'='
                    | b'?'
                    | b' '
                    | b'*'
                    | b'&'
            )
    })
}

/// A directory string encoded the way Go's pkix.Name marshaling picks
/// the type: PrintableString when the characters allow, otherwise
/// UTF8String.
pub fn directory_string(s: &str) -> Vec<u8> {
    if is_printable(s) {
        tlv(0x13, s.as_bytes())
    } else {
        tlv(0x0c, s.as_bytes())
    }
}

/// A UTCTime for a unix timestamp (valid for years 1950–2049, the
/// range Go encodes as UTCTime).
pub fn utc_time(unix: i64) -> Vec<u8> {
    let (year, month, day, hour, min, sec) = civil_from_unix(unix);
    let s = format!(
        "{:02}{month:02}{day:02}{hour:02}{min:02}{sec:02}Z",
        year % 100
    );
    tlv(0x17, s.as_bytes())
}

/// Convert a unix timestamp to UTC civil fields.
pub fn civil_from_unix(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let hour = (secs / 3600) as u32;
    let min = ((secs % 3600) / 60) as u32;
    let sec = (secs % 60) as u32;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}
