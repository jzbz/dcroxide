// SPDX-License-Identifier: ISC
//! Base64 decoding for `[]byte` targets.  Go's `encoding/json` decodes
//! JSON strings into `[]byte` via `base64.StdEncoding`, which ignores
//! newlines anywhere in the input, rejects over-padded quanta (`====`,
//! `A===`), and requires padding to terminate the input.  The
//! accept/reject table below was pinned against a real
//! `base64.StdEncoding.DecodeString` run.

use dcroxide_dcrjson::{GoType, GoValue, gojson};

fn decode_bytes(json_doc: &str) -> Result<Vec<u8>, String> {
    match gojson::decode(&GoType::Uint8.slice(), json_doc) {
        Ok(GoValue::Array(items)) => Ok(items
            .into_iter()
            .map(|v| match v {
                GoValue::Uint(b) => b as u8,
                other => panic!("expected a byte, got {other:?}"),
            })
            .collect()),
        Ok(other) => panic!("expected an array, got {other:?}"),
        Err(e) => Err(e.go_message()),
    }
}

/// Inputs Go's StdEncoding accepts decode to the same bytes, including
/// the embedded and trailing newlines it ignores.
#[test]
fn accepts_what_go_std_encoding_accepts() {
    let cases: &[(&str, &[u8])] = &[
        (r#""""#, b""),
        (r#""QUJD""#, b"ABC"),
        (r#""QQ==""#, b"A"),
        (r#""QUI=""#, b"AB"),
        (r#""QUJDQQ==""#, b"ABCA"),
        // Newlines are ignored anywhere: mid-quantum, between the
        // padding characters, and after the padding.
        ("\"QU\\nJD\"", b"ABC"),
        ("\"QQ==\\n\"", b"A"),
        ("\"QQ=\\n=\"", b"A"),
        ("\"\\n\\n\"", b""),
    ];
    for (doc, want) in cases {
        assert_eq!(
            decode_bytes(doc).unwrap_or_else(|e| panic!("{doc}: {e}")),
            *want,
            "{doc}"
        );
    }
}

/// Inputs Go's StdEncoding rejects fail with the unmarshal type error,
/// notably the over-padded quanta and data after padding the previous
/// decoder accepted.
#[test]
fn rejects_what_go_std_encoding_rejects() {
    for doc in [
        r#""====""#,      // no data characters in the quantum
        r#""A===""#,      // one data character needs three pad bytes
        r#""QQ==QUJD""#,  // padding must terminate the input
        r#""QQ==x""#,     // trailing garbage after padding
        ("\"QQ==\\nx\""), // trailing garbage after ignored newline
        r#""QQ=""#,       // incomplete quantum
        r#""Q""#,         // incomplete quantum
    ] {
        assert_eq!(
            decode_bytes(doc).expect_err(&format!("{doc} must be rejected")),
            "json: cannot unmarshal string into Go value of type []uint8",
            "{doc}"
        );
    }
}
