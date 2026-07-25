// SPDX-License-Identifier: ISC
//! Total float formatting.  Go renders every `float64` it is handed:
//! `strconv.FormatFloat` spells the non-finite ones `+Inf`, `-Inf` and
//! `NaN`, and `encoding/json` refuses them outright rather than
//! crashing.  The Rust formatters decompose a value's shortest
//! round-trip digits, and `format!("{:e}")` gives the non-finite floats
//! no exponent at all — so without an explicit guard every one of them
//! panics.  That was remotely reachable: an RPC id of `1e999` parses to
//! `f64::INFINITY` in Rust, and marshalling the reply's id ran straight
//! into the formatter.  These checks pin totality for `NaN` and `±Inf`
//! and pin that finite formatting is untouched.

use dcroxide_dcrjson::gojson::{
    format_float_f, format_float_g, format_float_g32, format_float_json, format_float_json32,
};
use dcroxide_dcrjson::{GoType, GoValue, gojson};

/// `strconv.FormatFloat(v, 'f', -1, 64)` spells the non-finite values
/// `+Inf`, `-Inf` and `NaN`; none of them may panic.
#[test]
fn format_float_f_matches_go_for_non_finite_values() {
    assert_eq!(format_float_f(f64::INFINITY), "+Inf");
    assert_eq!(format_float_f(f64::NEG_INFINITY), "-Inf");
    assert_eq!(format_float_f(f64::NAN), "NaN");
    assert_eq!(format_float_f(-f64::NAN), "NaN");
}

/// Go's `%v` verb (shortest `%g`) uses the same spellings.
#[test]
fn format_float_g_matches_go_for_non_finite_values() {
    assert_eq!(format_float_g(f64::INFINITY), "+Inf");
    assert_eq!(format_float_g(f64::NEG_INFINITY), "-Inf");
    assert_eq!(format_float_g(f64::NAN), "NaN");

    assert_eq!(format_float_g32(f32::INFINITY), "+Inf");
    assert_eq!(format_float_g32(f32::NEG_INFINITY), "-Inf");
    assert_eq!(format_float_g32(f32::NAN), "NaN");
}

/// Go's `encoding/json` has no rendering for a non-finite float: it
/// aborts the marshal with `json: unsupported value`.  The Rust
/// formatter cannot report failure through its signature, so it emits
/// the JSON `null` literal — still a parseable document, and never a
/// panic or a bare `+Inf` that no JSON reader would accept.
#[test]
fn format_float_json_emits_null_for_non_finite_values() {
    assert_eq!(format_float_json(f64::INFINITY), "null");
    assert_eq!(format_float_json(f64::NEG_INFINITY), "null");
    assert_eq!(format_float_json(f64::NAN), "null");

    assert_eq!(format_float_json32(f32::INFINITY), "null");
    assert_eq!(format_float_json32(f32::NEG_INFINITY), "null");
    assert_eq!(format_float_json32(f32::NAN), "null");

    // The same holds through the encoder, the path a marshalled reply
    // takes.
    assert_eq!(
        gojson::encode(&GoType::Float64, &GoValue::Float64(f64::INFINITY)),
        "null"
    );
    assert_eq!(
        gojson::encode(&GoType::Float32, &GoValue::Float32(f32::NAN)),
        "null"
    );
}

/// Guarding the non-finite values must not disturb the finite ones,
/// whose renderings are pinned to Go byte for byte elsewhere.
#[test]
fn finite_formatting_is_unchanged() {
    assert_eq!(format_float_json(0.0), "0");
    assert_eq!(format_float_json(-0.0), "-0");
    assert_eq!(format_float_json(1.5), "1.5");
    assert_eq!(format_float_json(1e21), "1e+21");
    assert_eq!(format_float_json(1e-7), "1e-7");
    assert_eq!(format_float_json(f64::MAX), "1.7976931348623157e+308");
    assert_eq!(
        format_float_json(f64::MIN_POSITIVE),
        "2.2250738585072014e-308"
    );

    assert_eq!(format_float_f(1e21), "1000000000000000000000");
    assert_eq!(format_float_f(0.5), "0.5");
    assert_eq!(format_float_f(-0.0), "-0");

    assert_eq!(format_float_g(1e21), "1e+21");
    assert_eq!(format_float_g(100000.0), "100000");
    assert_eq!(format_float_g(1000000.0), "1e+06");
    assert_eq!(format_float_g(0.0001), "0.0001");
    assert_eq!(format_float_g(0.00001), "1e-05");
}

/// The decoder already refuses a non-finite number, exactly as Go's
/// `convertNumber` does when `strconv.ParseFloat` reports `ErrRange`,
/// so no decoded document can ever carry one into the formatters.
/// Underflow to zero is accepted, as in Go.
#[test]
fn the_decoder_still_refuses_out_of_range_numbers() {
    let err = gojson::decode(&GoType::Float64, "1e999")
        .expect_err("a magnitude past float64 is out of range");
    assert_eq!(
        err.go_message(),
        "json: cannot unmarshal number 1e999 into Go value of type float64"
    );

    // Go's ParseFloat reports no error for underflow; the value is 0.
    assert_eq!(
        gojson::decode(&GoType::Float64, "1e-999").expect("underflow is not an error"),
        GoValue::Float64(0.0)
    );
}
