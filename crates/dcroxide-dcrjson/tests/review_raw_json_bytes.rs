// SPDX-License-Identifier: ISC
//! Go's `encoding/json` over a request's raw bytes, which need not be
//! UTF-8: dcrd hands a websocket frame or an HTTP body to
//! `json.Unmarshal` as it arrived.
//!
//! Go's scanner takes any byte from 0x20 up inside a string literal and
//! coerces invalid UTF-8 to U+FFFD, one per byte, when it unquotes the
//! string; a stray byte outside a string is a syntax error that names
//! the byte by `quoteChar`, which quotes it as the rune of the same
//! value.  The expected texts are Go 1.26's (`encoding/json` v1, the
//! package dcrd's toolchain builds).

use std::borrow::Cow;

use dcroxide_dcrjson::gojson::{coerce_utf8, unmarshal_input, validate, validate_bytes};

/// The syntax error Go's `checkValid` reports for the document.
fn syntax_error(doc: &[u8]) -> String {
    validate_bytes(doc)
        .expect_err("the document is invalid")
        .go_message()
}

/// `quoteChar` runs `strconv.Quote(string(c))`, which converts the byte
/// as an integer: a high byte is the Latin-1 rune of that value, quoted
/// as `strconv.IsPrint` decides, and the C escapes keep their names.
#[test]
fn a_stray_byte_is_named_as_go_names_it() {
    for (byte, quoted) in [
        (0x01u8, r"'\x01'"),
        (0x07, r"'\a'"),
        (0x08, r"'\b'"),
        (0x0b, r"'\v'"),
        (0x0c, r"'\f'"),
        (0x27, r"'\''"),
        (0x5c, r"'\\'"),
        (0x7f, r"'\x7f'"),
        (0x80, r"'\u0080'"),
        (0x9f, r"'\u009f'"),
        (0xa0, r"'\u00a0'"),
        (0xa1, "'¡'"),
        (0xad, r"'\u00ad'"),
        (0xc3, "'Ã'"),
        (0xff, "'ÿ'"),
    ] {
        assert_eq!(
            syntax_error(&[byte]),
            format!("invalid character {quoted} looking for beginning of value"),
            "byte {byte:#04x}"
        );
    }
}

/// The same naming reaches every scanner message, including the control
/// characters a string literal refuses.
#[test]
fn every_scanner_message_uses_gos_naming() {
    assert_eq!(
        validate("\"a\nb\"").expect_err("invalid").go_message(),
        r"invalid character '\n' in string literal"
    );
    assert_eq!(
        validate("\"a\tb\"").expect_err("invalid").go_message(),
        r"invalid character '\t' in string literal"
    );
    assert!(validate("\"a\x7fb\"").is_ok(), "DEL is fine in a string");
    assert_eq!(
        syntax_error(b"tru\xe9"),
        "invalid character 'é' in literal true (expecting 'e')"
    );
    assert_eq!(
        syntax_error(b"{\xa0"),
        r"invalid character '\u00a0' looking for beginning of object key string"
    );
    assert_eq!(
        syntax_error(b"{\"jsonrpc\":\"1.0\",\"id\":1\xff}"),
        "invalid character 'ÿ' after object key:value pair"
    );
    assert_eq!(
        syntax_error(b"[{\"a\":1}\xc3]"),
        "invalid character 'Ã' after array element"
    );
}

/// Each byte that begins no valid encoding is one U+FFFD, as
/// `utf8.DecodeRune` reports it -- not one per maximal invalid subpart,
/// as `String::from_utf8_lossy` would.
#[test]
fn invalid_utf8_is_coerced_one_byte_at_a_time() {
    assert_eq!(
        coerce_utf8(b"a\xe2\x82b\xff\xed\xa0\x80c"),
        "a\u{FFFD}\u{FFFD}b\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}c"
    );
    assert_eq!(coerce_utf8(b"\xc3"), "\u{FFFD}");
    assert_eq!(coerce_utf8(b"\xf0\x9f\x98"), "\u{FFFD}\u{FFFD}\u{FFFD}");
    assert!(matches!(
        coerce_utf8("é\u{FFFD}".as_bytes()),
        Cow::Borrowed(_)
    ));
}

/// Invalid UTF-8 inside a string is accepted and coerced; outside one
/// it is Go's syntax error, which only the raw bytes can produce.
#[test]
fn a_request_is_read_from_its_raw_bytes() {
    let served = unmarshal_input(
        b"{\"jsonrpc\":\"1.0\",\"id\":\"a\xffb\",\"method\":\"getblockcount\",\"params\":[],\"x\":\"\xe2\x82\"}",
    )
    .expect("invalid UTF-8 inside strings is accepted");
    assert_eq!(
        served,
        "{\"jsonrpc\":\"1.0\",\"id\":\"a\u{FFFD}b\",\"method\":\"getblockcount\",\"params\":[],\"x\":\"\u{FFFD}\u{FFFD}\"}"
    );

    let refused = unmarshal_input(b"\xff").expect_err("a stray byte is a syntax error");
    assert_eq!(
        refused.go_message(),
        "invalid character 'ÿ' looking for beginning of value"
    );

    // A valid document is handed back untouched, for the caller's own
    // decoding to judge.
    assert!(matches!(unmarshal_input(b"[1,"), Ok(Cow::Borrowed("[1,"))));
}
