// SPDX-License-Identifier: ISC
//! Go's reading of PEM: `encoding/pem`'s `Decode`, and the blocks
//! `crypto/tls`'s `X509KeyPair` takes from a certificate file and a key
//! file, with Go's texts when there is none.
//!
//! Both dcrd (`tls.LoadX509KeyPair` in `newTLSConfig`, `server.go:3680`)
//! and dcrwallet (`tls.LoadX509KeyPair` in `openRPCKeyPair`,
//! `rpcserver.go:63`) read `rpc.cert` and `rpc.key` this way, and both
//! read a client CA file through `CertPool.AppendCertsFromPEM`, which
//! decodes with the same `pem.Decode` ([`crate::ClientCaPool`]).

/// One PEM block as Go's `pem.Decode` returns it: the type, whether the
/// block carried headers, and the decoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoPemBlock {
    /// The type on the block's BEGIN line, `CERTIFICATE` say.
    pub block_type: Vec<u8>,
    /// Whether the block carried `key: value` headers, which Go keeps in
    /// `Block.Headers`; only whether there were any is kept here.
    pub has_headers: bool,
    /// The block's body, base64-decoded.
    pub bytes: Vec<u8>,
}

/// Go's `getLine` (`encoding/pem/pem.go`): the first `\n`- or
/// `\r\n`-delimited line without its trailing spaces and tabs, the
/// rest after the newline, and how many bytes that consumed.
// Offsets bounded by the input length.
#[allow(clippy::arithmetic_side_effects)]
fn go_pem_get_line(data: &[u8]) -> (&[u8], &[u8], usize) {
    let (mut i, j) = match data.iter().position(|&b| b == b'\n') {
        None => (data.len(), data.len()),
        Some(i) => (i, i + 1),
    };
    if j > i && i > 0 && data[i - 1] == b'\r' {
        i -= 1;
    }
    let mut line = &data[..i];
    while let [head @ .., b' ' | b'\t'] = line {
        line = head;
    }
    (line, &data[j..], j)
}

/// Go's `base64.StdEncoding.Decode` (non-strict, padded) over PEM body
/// text with its spaces and tabs already removed: carriage returns and
/// newlines are skipped, `=` may only pad the final quantum, and
/// nothing but newlines may follow it (`decodeQuantum`,
/// `encoding/base64/base64.go`).  `None` is Go's `CorruptInputError`.
// Sextet and offset arithmetic bounded by the input length.
#[allow(clippy::arithmetic_side_effects)]
fn go_base64_std_decode(src: &[u8]) -> Option<Vec<u8>> {
    let chars: Vec<u8> = src
        .iter()
        .copied()
        .filter(|&c| c != b'\r' && c != b'\n')
        .collect();
    if !chars.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let quanta = chars.len() / 4;
    let mut out = Vec::with_capacity(quanta * 3);
    for (index, quad) in chars.chunks(4).enumerate() {
        let mut dlen = 4;
        let mut acc = 0u32;
        for (j, &c) in quad.iter().enumerate() {
            if c == b'=' {
                // Padding is only valid at the third or fourth position
                // of the last quantum, and a third-position `=` needs a
                // second one after it.
                if j < 2 || index + 1 != quanta || (j == 2 && quad[3] != b'=') {
                    return None;
                }
                dlen = j;
                break;
            }
            acc |= value(c)? << (18 - 6 * j);
        }
        out.push((acc >> 16) as u8);
        if dlen >= 3 {
            out.push((acc >> 8) as u8);
        }
        if dlen == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Go's `pem.Decode` (`encoding/pem/pem.go`): find the first END line,
/// take the last BEGIN line before it, and decode that block, skipping
/// to the next END line whenever the block is malformed -- a bad type
/// line, a mismatched or unterminated END line, or a body that is not
/// base64.  `None` when no further block decodes, which is also Go's
/// answer for input that ends inside a block's headers.
// Go's signed offset bookkeeping, bounded by the input length.
#[allow(clippy::arithmetic_side_effects)]
pub fn go_pem_decode(data: &[u8]) -> Option<(GoPemBlock, &[u8])> {
    const PEM_START: &[u8] = b"\n-----BEGIN ";
    const PEM_END: &[u8] = b"\n-----END ";
    const PEM_END_OF_LINE: &[u8] = b"-----";
    let find = |haystack: &[u8], needle: &[u8]| {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    };
    let rfind = |haystack: &[u8], needle: &[u8]| {
        haystack
            .windows(needle.len())
            .rposition(|window| window == needle)
    };

    let mut rest = data;
    // Offsets relative to `rest`, signed as in Go: consuming the type
    // line of an empty block leaves `end_index` at -1.
    let mut end_trailer_index: isize = 0;
    loop {
        // Skip past the END line already tried.
        if end_trailer_index < 0 || end_trailer_index as usize > rest.len() {
            return None;
        }
        rest = &rest[end_trailer_index as usize..];

        // The first END line, then the last BEGIN line before it, so
        // repeated BEGIN lines without a matching END are skipped.
        let found_end = find(rest, PEM_END)?;
        let mut end_index = found_end as isize;
        end_trailer_index = (found_end + PEM_END.len()) as isize;
        let Some(begin_index) = rfind(&rest[..found_end], &PEM_START[1..]) else {
            continue;
        };
        if begin_index > 0 && rest[begin_index - 1] != b'\n' {
            continue;
        }
        let skip = begin_index + PEM_START.len() - 1;
        rest = &rest[skip..];
        end_index -= skip as isize;
        end_trailer_index -= skip as isize;

        let (type_line, after_type, consumed) = go_pem_get_line(rest);
        rest = after_type;
        end_index -= consumed as isize;
        end_trailer_index -= consumed as isize;
        let Some(block_type) = type_line.strip_suffix(PEM_END_OF_LINE) else {
            continue;
        };

        let mut has_headers = false;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next, consumed) = go_pem_get_line(rest);
            // Go keeps each `key: value` line in the block's header map;
            // only whether there were any matters to the callers here.
            if !line.contains(&b':') {
                break;
            }
            has_headers = true;
            rest = next;
            end_index -= consumed as isize;
            end_trailer_index -= consumed as isize;
        }

        // Headers must be followed by a newline before the END line.
        if has_headers && end_index < 0 {
            continue;
        }

        // The END line repeats the type and closes with five dashes,
        // then only whitespace.
        let Some(end_trailer) = usize::try_from(end_trailer_index)
            .ok()
            .and_then(|index| rest.get(index..))
        else {
            continue;
        };
        let end_trailer_len = block_type.len() + PEM_END_OF_LINE.len();
        if end_trailer.len() < end_trailer_len {
            continue;
        }
        let (end_trailer, rest_of_end_line) = end_trailer.split_at(end_trailer_len);
        if !end_trailer.starts_with(block_type) || !end_trailer.ends_with(PEM_END_OF_LINE) {
            continue;
        }
        if !go_pem_get_line(rest_of_end_line).0.is_empty() {
            continue;
        }

        let mut bytes = Vec::new();
        if end_index > 0 {
            let base64_data: Vec<u8> = rest[..end_index as usize]
                .iter()
                .copied()
                .filter(|&b| b != b' ' && b != b'\t')
                .collect();
            let Some(decoded) = go_base64_std_decode(&base64_data) else {
                continue;
            };
            bytes = decoded;
        }

        // The -1 is because an empty block matched the END marker
        // without its leading newline.
        let after_end = (end_index + PEM_END.len() as isize - 1) as usize;
        let (_, rest, _) = go_pem_get_line(&rest[after_end..]);
        return Some((
            GoPemBlock {
                block_type: block_type.to_vec(),
                has_headers,
                bytes,
            },
            rest,
        ));
    }
}

/// The certificate chain of a certificate file as `tls.X509KeyPair`
/// collects it (`crypto/tls/tls.go`): every `CERTIFICATE` block Go's
/// `pem.Decode` finds, in order, skipping blocks of other types and
/// malformed ones, or Go's text for a file with none.  The certificates
/// are not parsed here; Go parses only the first, the leaf, which
/// [`crate::KeyPair::from_pem`] checks against the key.
pub fn go_certificate_blocks(
    cert_pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let mut certs = Vec::new();
    let mut skipped_block_types = Vec::new();
    let mut rest = cert_pem;
    while let Some((block, next)) = go_pem_decode(rest) {
        rest = next;
        if block.block_type == b"CERTIFICATE" {
            certs.push(rustls::pki_types::CertificateDer::from(block.bytes));
        } else {
            skipped_block_types.push(String::from_utf8_lossy(&block.block_type).into_owned());
        }
    }
    if certs.is_empty() {
        return Err(match skipped_block_types.as_slice() {
            [] => "tls: failed to find any PEM data in certificate input".to_string(),
            [only] if only.ends_with("PRIVATE KEY") => {
                "tls: failed to find certificate PEM data in certificate input, but did find \
                 a private key; PEM inputs may have been switched"
                    .to_string()
            }
            types => format!(
                "tls: failed to find \"CERTIFICATE\" PEM block in certificate input after \
                 skipping PEM blocks of the following types: [{}]",
                types.join(" ")
            ),
        });
    }
    Ok(certs)
}

/// The key block of an `rpc.key` as `tls.X509KeyPair` chooses it
/// (`crypto/tls/tls.go:286-303`): the first block Go's `pem.Decode` finds
/// whose type is `PRIVATE KEY` or ends in ` PRIVATE KEY`, whatever its
/// headers, or Go's text for a file with none (`:290-297`).  So a key
/// under a label of its own ending so is read, one under a label that
/// runs into `PRIVATE KEY` with no space is skipped, and a first such
/// block that does not parse, an `ENCRYPTED PRIVATE KEY` among them, is
/// the one refused, though a readable key follows it.  The block's DER is
/// wiped when it is dropped, as ring's loader wiped the DER it was
/// handed; the PEM text it is decoded from, the file as read and the
/// decoder's copies of the block's base64 body, is not, and was not
/// before the switch.
pub fn go_key_block(key_pem: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let mut skipped_block_types = Vec::new();
    let mut rest = key_pem;
    while let Some((block, next)) = go_pem_decode(rest) {
        rest = next;
        if block.block_type == b"PRIVATE KEY" || block.block_type.ends_with(b" PRIVATE KEY") {
            return Ok(zeroize::Zeroizing::new(block.bytes));
        }
        skipped_block_types.push(String::from_utf8_lossy(&block.block_type).into_owned());
    }
    Err(match skipped_block_types.as_slice() {
        [] => "tls: failed to find any PEM data in key input".to_string(),
        [only] if only == "CERTIFICATE" => {
            "tls: found a certificate rather than a key in the PEM for the private key".to_string()
        }
        types => format!(
            "tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input \
             after skipping PEM blocks of the following types: [{}]",
            types.join(" ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's `pem.Decode` over the malformed shapes a client CA file or
    /// rpc.cert can hold, with the blocks Go 1.27 returns for each, whose
    /// `encoding/pem` go1.27.3, the reference Go, keeps, as go1.26.2
    /// returns them too (review finding GAP06#3): each entry is the input
    /// and, for every block decoded in turn, its
    /// `type|has headers|hex bytes`.
    #[test]
    fn go_pem_decode_matches_go() {
        let good = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let g = |extra: &str| format!("{good}{extra}");
        let cases: Vec<(String, &str)> = vec![
            (good.to_string(), "CERTIFICATE|false|010203"),
            (
                g("-----BEGIN CERTIFICATE-----\nAQID\n"),
                "CERTIFICATE|false|010203",
            ),
            (
                g(&format!(
                    "-----BEGIN CERTIFICATE-----\nAQ!D\n-----END CERTIFICATE-----\n{good}"
                )),
                "CERTIFICATE|false|010203,CERTIFICATE|false|010203",
            ),
            (
                "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAQID\n-----END CERTIFICATE-----\n"
                    .to_string(),
                "CERTIFICATE|true|010203",
            ),
            (
                format!("-----BEGIN CERTIFICATE----- x\nAQID\n-----END CERTIFICATE-----\n{good}"),
                "CERTIFICATE|false|010203",
            ),
            ("-----BEGIN X-----\n-----END X-----\n".to_string(), "X|false|"),
            (
                "-----BEGIN A-----\n-----BEGIN B-----\nAQID\n-----END B-----\n".to_string(),
                "B|false|010203",
            ),
            (
                format!("-----BEGIN A-----\nAQID\n-----END B-----\n{good}"),
                "CERTIFICATE|false|010203",
            ),
            (
                "-----BEGIN A-----\r\nAQID\r\nBAUG\r\n-----END A-----\r\n".to_string(),
                "A|false|010203040506",
            ),
            (
                format!("-----BEGIN A-----\nAQID\n-----END A----- junk\n{good}"),
                "CERTIFICATE|false|010203",
            ),
            (
                "-----BEGIN A-----\nK: V\nAQID\n-----END A-----\n".to_string(),
                "A|true|010203",
            ),
            ("-----BEGIN A-----\nK: V\n-----END A-----\n".to_string(), ""),
            ("-----BEGIN A-----\nAQ==\n-----END A-----\n".to_string(), "A|false|01"),
            ("-----BEGIN A-----\nAQI=\n-----END A-----\n".to_string(), "A|false|0102"),
            ("-----BEGIN A-----\nAQ=A\n-----END A-----\n".to_string(), ""),
            ("-----BEGIN A-----\nA===\n-----END A-----\n".to_string(), ""),
            (
                "-----BEGIN A-----\nAQID\nAQ==\n-----END A-----\n".to_string(),
                "A|false|01020301",
            ),
            ("-----BEGIN A-----\nAQ==\nAQID\n-----END A-----\n".to_string(), ""),
            (
                "-----BEGIN A-----\nAQ ID\t\n-----END A-----\n".to_string(),
                "A|false|010203",
            ),
            ("x-----BEGIN A-----\nAQID\n-----END A-----\n".to_string(), ""),
            (
                format!("junk\n{good}between\n{good}trailer"),
                "CERTIFICATE|false|010203,CERTIFICATE|false|010203",
            ),
            ("-----BEGIN A-----\nAQID\n-----END A-----".to_string(), "A|false|010203"),
            ("-----BEGIN A-----\nAQID\n-----END A-----  \n".to_string(), "A|false|010203"),
            ("-----BEGIN A-----\nAQI\n-----END A-----\n".to_string(), ""),
            ("-----BEGIN A-----\n\n-----END A-----\n".to_string(), "A|false|"),
            ("-----BEGIN A-----\nK: V\n\n-----END A-----\n".to_string(), "A|true|"),
            (
                format!("-----BEGIN A-----\nAQID\n-----END A-----\n-----END A-----\n{good}"),
                "A|false|010203,CERTIFICATE|false|010203",
            ),
            ("-----BEGIN A-----\nAQID==\n-----END A-----\n".to_string(), ""),
            ("-----BEGIN -----\nAQID\n-----END -----\n".to_string(), "|false|010203"),
            ("-----BEGIN A-----\nAQIDBA\n-----END A-----\n".to_string(), ""),
            ("-----BEGIN A-----\nAQIDBA==\n-----END A-----\n".to_string(), "A|false|01020304"),
            ("-----BEGIN A-----\nAQIDBAU=\n-----END A-----\n".to_string(), "A|false|0102030405"),
            ("-----BEGIN A-----\nAB==\n-----END A-----\n".to_string(), "A|false|00"),
        ];
        for (input, want) in &cases {
            let mut rest = input.as_bytes();
            let mut got = Vec::new();
            while let Some((block, next)) = go_pem_decode(rest) {
                rest = next;
                let hex: String = block.bytes.iter().map(|b| format!("{b:02x}")).collect();
                got.push(format!(
                    "{}|{}|{hex}",
                    String::from_utf8_lossy(&block.block_type),
                    block.has_headers
                ));
            }
            assert_eq!(got.join(","), *want, "{input:?}");
        }
    }
}
