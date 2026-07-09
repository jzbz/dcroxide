// SPDX-License-Identifier: ISC
//! Nesting-depth limit for the JSON scanner.  Go's `encoding/json`
//! rejects documents nested deeper than `maxNestingDepth` (10000) in
//! `checkValid` before decoding, so a hostile deeply nested RPC payload
//! returns a syntax error instead of overflowing the stack.  These
//! checks pin the boundary and the sibling-pop behaviour so the guard
//! matches Go rather than firing on wide-but-shallow documents.

use dcroxide_dcrjson::{GoType, gojson};

/// A document nested exactly at the limit validates; one level deeper is
/// rejected with Go's scanner message.
#[test]
fn object_nesting_is_capped_at_the_go_limit() {
    let at_limit = format!("{}1{}", "{\"a\":".repeat(10000), "}".repeat(10000));
    gojson::validate(&at_limit).expect("10000 levels of objects are within Go's limit");

    let too_deep = format!("{}1{}", "{\"a\":".repeat(10001), "}".repeat(10001));
    let err = gojson::validate(&too_deep).expect_err("10001 levels must exceed Go's max depth");
    assert_eq!(
        err.go_message(),
        "invalid character '{' exceeded max depth",
        "the message must match Go's scanner"
    );
}

/// Arrays are capped on the same counter, and the opening bracket is the
/// byte Go reports.
#[test]
fn array_nesting_is_capped_at_the_go_limit() {
    let at_limit = format!("{}{}", "[".repeat(10000), "]".repeat(10000));
    gojson::validate(&at_limit).expect("10000 levels of arrays are within Go's limit");

    let too_deep = format!("{}{}", "[".repeat(10001), "]".repeat(10001));
    let err = gojson::validate(&too_deep).expect_err("10001 levels must exceed Go's max depth");
    assert_eq!(err.go_message(), "invalid character '[' exceeded max depth");
}

/// Closing a nested value pops the depth counter, so a wide document
/// with tens of thousands of siblings at shallow depth validates — the
/// guard counts live nesting, not total brackets.
#[test]
fn sibling_nesting_does_not_accumulate_depth() {
    let wide = format!("[{}[]]", "[],".repeat(20000));
    gojson::validate(&wide).expect("20001 shallow siblings must not trip the depth guard");
}

/// `decode` runs the same validation first, so an over-deep document is
/// rejected before the decoder can recurse.
#[test]
fn decode_rejects_over_deep_documents() {
    let too_deep = format!("{}{}", "[".repeat(20000), "]".repeat(20000));
    let err = gojson::decode(&GoType::Int.slice(), &too_deep)
        .expect_err("decode must reject an over-deep document during validation");
    assert_eq!(err.go_message(), "invalid character '[' exceeded max depth");
}
