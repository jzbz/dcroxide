// SPDX-License-Identifier: ISC
//! The JSON string reader decodes non-ASCII text in one forward pass.
//!
//! Go's `encoding/json` `unquoteBytes` walks a quoted string once,
//! calling `utf8.DecodeRune` with a four-byte lookahead per character.
//! The Rust reader used to hand `str::from_utf8` the *entire* unread
//! remainder for every multi-byte character, revalidating it from
//! scratch each time — quadratic in the string's length.  With the
//! authenticated body budgets (8 MiB over HTTP, 16 MiB over the
//! websocket) a single request full of two-byte characters was hours of
//! CPU spent under the server lock, denying every other client.  These
//! checks pin the linear cost and pin that the decoded text is
//! unchanged.

use std::time::{Duration, Instant};

use dcroxide_dcrjson::{GoType, GoValue, gojson};

/// Wrap raw text in JSON quotes.
fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

/// The decoded string of a JSON document, or a panic with the error.
fn decode_string(doc: &str) -> String {
    match gojson::decode(&GoType::String, doc).expect("valid document") {
        GoValue::String(s) => s,
        other => panic!("expected a string, got {other:?}"),
    }
}

/// A megabyte of two-byte characters decodes in one pass.  The
/// quadratic reader spent roughly `n^2/2` bytes of UTF-8 validation on
/// this input — minutes, not milliseconds — so the bound below is a
/// timeout in all but name.  It is set far above the linear cost (which
/// is a few milliseconds) so it cannot flake on a loaded machine.
#[test]
fn a_large_non_ascii_string_decodes_in_linear_time() {
    // 'é' is two bytes in UTF-8; 512 Ki of them is 1 MiB of payload.
    const CHARS: usize = 512 * 1024;
    let payload: String = "é".repeat(CHARS);
    let doc = quoted(&payload);
    assert_eq!(doc.len(), CHARS * 2 + 2, "the payload is 1 MiB of text");

    let start = Instant::now();
    let decoded = decode_string(&doc);
    let elapsed = start.elapsed();

    assert_eq!(decoded.chars().count(), CHARS);
    assert_eq!(decoded, payload);
    assert!(
        elapsed < Duration::from_secs(2),
        "decoding 1 MiB of two-byte characters took {elapsed:?}; the reader is rescanning the \
         remainder per character"
    );
}

/// The same for three- and four-byte characters, whose per-character
/// rescans were even more expensive.
#[test]
fn a_large_four_byte_string_decodes_in_linear_time() {
    // A four-byte emoji; 256 Ki of them is 1 MiB of payload.
    const CHARS: usize = 256 * 1024;
    let payload: String = "🦀".repeat(CHARS);
    let doc = quoted(&payload);
    assert_eq!(doc.len(), CHARS * 4 + 2);

    let start = Instant::now();
    let decoded = decode_string(&doc);
    let elapsed = start.elapsed();

    assert_eq!(decoded.chars().count(), CHARS);
    assert!(
        elapsed < Duration::from_secs(2),
        "decoding 1 MiB of four-byte characters took {elapsed:?}"
    );
}

/// Decoding is byte-for-byte unchanged across the sequence lengths,
/// mixed with ASCII, escapes and surrogate pairs.
#[test]
fn mixed_width_characters_decode_unchanged() {
    // One, two, three and four byte sequences interleaved with ASCII.
    let payload = "a\u{e9}b\u{20ac}c\u{1f980}d\u{7f}e\u{80}f\u{7ff}g\u{800}h\u{ffff}i\u{10ffff}";
    assert_eq!(decode_string(&quoted(payload)), payload);

    // Escapes keep working alongside the raw sequences.
    assert_eq!(
        decode_string(r#""é € 🦀 \t\n\\\/""#),
        "\u{e9} \u{20ac} \u{1f980} \t\n\\/"
    );

    // A repeated mixed run, long enough that a per-character rescan
    // would show up, still round-trips exactly.
    let long: String = "aé€🦀".repeat(50_000);
    assert_eq!(decode_string(&quoted(&long)), long);

    // Inside a larger document the characters land in the right fields.
    let typ = GoType::Slice(Box::new(GoType::String));
    let decoded = gojson::decode(&typ, r#"["é","€","🦀",""]"#).expect("valid array");
    assert_eq!(
        decoded,
        GoValue::Array(vec![
            GoValue::String("é".to_string()),
            GoValue::String("€".to_string()),
            GoValue::String("🦀".to_string()),
            GoValue::String(String::new()),
        ])
    );
}

/// Malformed content cannot panic the reader.
///
/// Bytes that are not UTF-8 never reach it: every entry point
/// (`validate`, `decode`, `encode`) takes a `&str`, so the conversion
/// fails at the caller — the websocket and HTTP paths both answer a
/// parse error for a non-UTF-8 body.  What *can* reach the reader is a
/// malformed escape, and there Go's `unquoteBytes` coerces to
/// well-formed UTF-8 with U+FFFD rather than failing; the reader does
/// the same.
#[test]
fn malformed_escapes_coerce_to_the_replacement_character() {
    // A lone high surrogate, a lone low surrogate, and a high surrogate
    // followed by a non-surrogate.
    assert_eq!(decode_string(r#""\ud800""#), "\u{fffd}");
    assert_eq!(decode_string(r#""\udc00""#), "\u{fffd}");
    assert_eq!(decode_string(r#""\ud800A""#), "\u{fffd}A");
    assert_eq!(decode_string(r#""x\ud83ey""#), "x\u{fffd}y");

    // A well-formed pair still combines.
    assert_eq!(decode_string(r#""🦀""#), "🦀");

    // A raw control character is a scanner-level syntax error, not a
    // panic.
    let err = gojson::decode(&GoType::String, "\"a\u{1}b\"")
        .expect_err("a raw control character is invalid JSON");
    assert!(
        err.go_message().starts_with("invalid character"),
        "{}",
        err.go_message()
    );
}
