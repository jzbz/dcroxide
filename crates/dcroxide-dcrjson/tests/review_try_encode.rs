// SPDX-License-Identifier: ISC
//! `gojson::try_encode` fails where Go's `json.Marshal` fails.
//!
//! Go's `floatEncoder` refuses `NaN` and `±Inf` with
//! `json: unsupported value: <FormatFloat(f, 'g', -1, bits)>`, aborting
//! the whole marshal.  A handler can compute such a value (getvoteinfo's
//! `0/0` choice progress), and dcrd's reply path then drops the reply;
//! the port's reply path marshals through `try_encode` to do the same.
//! Only a float the encoder actually reaches counts: fields Go skips
//! (`json:"-"`, unexported) never fail it.

use dcroxide_dcrjson::gojson::{UnsupportedValueError, encode, try_encode};
use dcroxide_dcrjson::{GoType, GoValue, StructField};

fn unsupported(text: &str) -> Result<String, UnsupportedValueError> {
    Err(UnsupportedValueError {
        str: text.to_string(),
    })
}

fn choice() -> GoType {
    GoType::strukt(
        "types",
        "Choice",
        vec![
            StructField::new("ID", GoType::String).with_json_tag("id"),
            StructField::new("Progress", GoType::Float64).with_json_tag("progress"),
        ],
    )
}

#[test]
fn a_non_finite_float_fails_with_gos_text() {
    assert_eq!(
        try_encode(&GoType::Float64, &GoValue::Float64(f64::NAN)),
        unsupported("NaN")
    );
    assert_eq!(
        try_encode(&GoType::Float64, &GoValue::Float64(f64::INFINITY)),
        unsupported("+Inf")
    );
    assert_eq!(
        try_encode(&GoType::Float64, &GoValue::Float64(f64::NEG_INFINITY)),
        unsupported("-Inf")
    );
    assert_eq!(
        try_encode(&GoType::Float32, &GoValue::Float32(f32::NAN)),
        unsupported("NaN")
    );
    assert_eq!(
        UnsupportedValueError {
            str: "NaN".to_string()
        }
        .to_string(),
        "json: unsupported value: NaN"
    );
}

#[test]
fn a_nested_non_finite_float_fails_the_whole_marshal() {
    let typ = choice().slice();
    let val = GoValue::Array(vec![
        GoValue::Struct(vec![
            GoValue::String("yes".to_string()),
            GoValue::Float64(0.5),
        ]),
        GoValue::Struct(vec![
            GoValue::String("no".to_string()),
            GoValue::Float64(f64::NAN),
        ]),
    ]);
    assert_eq!(try_encode(&typ, &val), unsupported("NaN"));

    // The first one the encoder reaches is the one reported.
    let map = GoType::Map(Box::new(GoType::String), Box::new(GoType::Float64));
    let val = GoValue::Map(vec![
        ("b".to_string(), GoValue::Float64(f64::NAN)),
        ("a".to_string(), GoValue::Float64(f64::NEG_INFINITY)),
    ]);
    assert_eq!(try_encode(&map, &val), unsupported("-Inf"));

    // omitempty does not skip it: NaN is not Go's empty value.
    let typ = GoType::strukt(
        "types",
        "T",
        vec![StructField::new("F", GoType::Float64).with_json_tag("f,omitempty")],
    );
    let val = GoValue::Struct(vec![GoValue::Float64(f64::NAN)]);
    assert_eq!(try_encode(&typ, &val), unsupported("NaN"));
}

#[test]
fn a_field_go_skips_cannot_fail_the_marshal() {
    let typ = GoType::strukt(
        "types",
        "T",
        vec![
            StructField::new("Skipped", GoType::Float64).with_json_tag("-"),
            StructField::new("hidden", GoType::Float64).private(),
            StructField::new("Shown", GoType::Float64).with_json_tag("shown"),
        ],
    );
    let val = GoValue::Struct(vec![
        GoValue::Float64(f64::NAN),
        GoValue::Float64(f64::INFINITY),
        GoValue::Float64(1.5),
    ]);
    assert_eq!(try_encode(&typ, &val), Ok(r#"{"shown":1.5}"#.to_string()));
}

#[test]
fn finite_values_encode_as_encode_does() {
    let typ = choice().slice();
    let val = GoValue::Array(vec![GoValue::Struct(vec![
        GoValue::String("yes".to_string()),
        GoValue::Float64(0.25),
    ])]);
    assert_eq!(try_encode(&typ, &val), Ok(encode(&typ, &val)));
    assert_eq!(encode(&typ, &val), r#"[{"id":"yes","progress":0.25}]"#);

    // The infallible encoder keeps its null rendering.
    assert_eq!(
        encode(&GoType::Float64, &GoValue::Float64(f64::NAN)),
        "null"
    );
}
