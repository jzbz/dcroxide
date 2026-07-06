// SPDX-License-Identifier: ISC
//! Command marshalling and parameter parsing (dcrd dcrjson
//! `cmdparse.go`).

use crate::gojson::{
    self, JsonError, go_parse_bool, go_parse_float, go_parse_int, go_parse_uint, overflow_int,
    overflow_uint,
};
use crate::gotype::{GoType, GoValue, Kind};
use crate::jsonrpc::{RpcId, marshal_request, new_request};
use crate::registry::{Method, MethodInfo, Registry};
use crate::{DcrjsonError, ErrorKind, make_error};

/// An instance of a registered command: the registered pointer type
/// together with the parameter struct's field values.  Pointer-typed
/// fields store the pointee directly with [`GoValue::Null`] for nil.
#[derive(Clone, Debug, PartialEq)]
pub struct CmdInstance {
    /// The registered command type (a pointer to a struct type).
    pub cmd_type: GoType,
    /// Whether this is a nil instance of the type (Go `(*T)(nil)`).
    pub nil: bool,
    /// The field values, parallel to the struct's fields.
    pub fields: Vec<GoValue>,
}

impl CmdInstance {
    /// A non-nil instance with the given field values.
    pub fn new(cmd_type: GoType, fields: Vec<GoValue>) -> CmdInstance {
        CmdInstance {
            cmd_type,
            nil: false,
            fields,
        }
    }

    /// A nil instance of the given command type.
    pub fn nil_of(cmd_type: GoType) -> CmdInstance {
        CmdInstance {
            cmd_type,
            nil: true,
            fields: Vec::new(),
        }
    }
}

/// A dynamically-typed argument to [`new_cmd`], mirroring the Go
/// values dcrd callers pass through `interface{}`.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg {
    /// The Go type of the argument.
    pub typ: GoType,
    /// The argument value.  For pointer types this is the pointee.
    pub val: GoValue,
}

impl Arg {
    /// A Go `int` argument.
    pub fn int(v: i64) -> Arg {
        Arg {
            typ: GoType::Int,
            val: GoValue::Int(v),
        }
    }

    /// A Go `string` argument.
    pub fn str(v: &str) -> Arg {
        Arg {
            typ: GoType::String,
            val: GoValue::String(v.to_string()),
        }
    }

    /// A Go `bool` argument.
    pub fn bool(v: bool) -> Arg {
        Arg {
            typ: GoType::Bool,
            val: GoValue::Bool(v),
        }
    }

    /// A Go `float64` argument.
    pub fn f64(v: f64) -> Arg {
        Arg {
            typ: GoType::Float64,
            val: GoValue::Float64(v),
        }
    }

    /// An argument of an arbitrary type.
    pub fn typed(typ: GoType, val: GoValue) -> Arg {
        Arg { typ, val }
    }
}

/// Create a slice of raw parameter values for the given command
/// instance (dcrd `makeParams`), marshalling each populated field and
/// stopping at the first nil optional field.
fn make_params(cmd: &CmdInstance) -> Vec<String> {
    let fields = cmd.cmd_type.elem().fields();
    let mut params = Vec::with_capacity(fields.len());
    for (f, v) in fields.iter().zip(cmd.fields.iter()) {
        if f.typ.kind() == Kind::Ptr && matches!(v, GoValue::Null) {
            break;
        }
        params.push(gojson::encode(&f.typ, v));
    }
    params
}

/// Marshal the passed command to a JSON-RPC request byte slice that is
/// suitable for transmission to an RPC server (dcrd `MarshalCmd`).
pub fn marshal_cmd(
    registry: &Registry,
    rpc_version: &str,
    id: &RpcId,
    cmd: &CmdInstance,
) -> Result<String, DcrjsonError> {
    // Look up the cmd type and error out if not registered.
    let Some(method) = registry.type_to_method.get(&cmd.cmd_type) else {
        let str = format!("{} is not registered", cmd.cmd_type.display());
        return Err(make_error(ErrorKind::UnregisteredMethod, str));
    };

    // The provided command must not be nil.
    if cmd.nil {
        return Err(make_error(
            ErrorKind::InvalidType,
            "the specified command is nil".to_string(),
        ));
    }

    // Create a slice of raw values in the order of the struct fields
    // while respecting pointer fields as optional params and only
    // adding them if they are non-nil.
    let params = make_params(cmd);

    // Generate and marshal the final JSON-RPC request.
    let raw_cmd = new_request(rpc_version, id, params)?;
    Ok(marshal_request(&raw_cmd, &method.name))
}

/// Ensure the supplied number of params is at least the minimum
/// required number for the command and less than the maximum allowed
/// (dcrd `checkNumParams`).
fn check_num_params(num_params: usize, info: &MethodInfo) -> Result<(), DcrjsonError> {
    if num_params < info.num_req_params || num_params > info.max_params {
        if info.num_req_params == info.max_params {
            let str = format!(
                "wrong number of params (expected {}, received {num_params})",
                info.num_req_params,
            );
            return Err(make_error(ErrorKind::NumParams, str));
        }
        let str = format!(
            "wrong number of params (expected between {} and {}, received {num_params})",
            info.num_req_params, info.max_params,
        );
        return Err(make_error(ErrorKind::NumParams, str));
    }
    Ok(())
}

/// Populate default values into any remaining optional struct fields
/// that did not have parameters explicitly provided (dcrd
/// `populateDefaults`).
fn populate_defaults(num_params: usize, info: &MethodInfo, fields: &mut [GoValue]) {
    for (i, field) in fields
        .iter_mut()
        .enumerate()
        .take(info.max_params)
        .skip(num_params)
    {
        if let Some(default) = info.defaults.get(&i) {
            *field = default.clone();
        }
    }
}

/// Unmarshal and parse the parameters for a JSON-RPC request based on
/// the registered method (dcrd `ParseParams`).
pub fn parse_params(
    registry: &Registry,
    method: &Method,
    params: &[&str],
) -> Result<CmdInstance, DcrjsonError> {
    let Some(rtp) = registry.method_to_type.get(method) else {
        let str = format!("{} is not registered", gojson::go_quote(&method.name));
        return Err(make_error(ErrorKind::UnregisteredMethod, str));
    };
    let info = &registry.method_to_info[method];
    let fields = rtp.elem().fields();
    let mut values: Vec<GoValue> = fields.iter().map(|f| GoValue::zero(&f.typ)).collect();

    // Ensure the number of parameters are correct.
    let num_params = params.len();
    check_num_params(num_params, info)?;

    // Loop through each of the struct fields and unmarshal the
    // associated parameter into them.
    for (i, raw) in params.iter().enumerate() {
        let field = &fields[i];
        if let Err(err) = decode_field(&field.typ, raw, &mut values[i]) {
            // The most common error is the wrong type, so explicitly
            // detect that error and make it nicer.
            let field_name = field.name.to_lowercase();
            match err {
                JsonError::Type {
                    value,
                    type_display,
                } => {
                    let str = format!(
                        "parameter #{} '{field_name}' must be type {type_display} (got {value})",
                        i.saturating_add(1),
                    );
                    return Err(make_error(ErrorKind::InvalidType, str));
                }
                JsonError::Syntax(msg) => {
                    let str = format!(
                        "parameter #{} '{field_name}' failed to unmarshal: {msg}",
                        i.saturating_add(1),
                    );
                    return Err(make_error(ErrorKind::InvalidType, str));
                }
            }
        }
    }

    // When there are less supplied parameters than the total number of
    // params, any remaining struct fields must be optional.  Thus,
    // populate them with their associated default value as needed.
    if num_params < info.max_params {
        populate_defaults(num_params, info, &mut values);
    }

    Ok(CmdInstance::new(rtp.clone(), values))
}

/// Decode one raw parameter into a field slot, treating the field's
/// pointer indirection the way Go's unmarshal-through-`Addr` does.
fn decode_field(typ: &GoType, raw: &str, out: &mut GoValue) -> Result<(), JsonError> {
    *out = gojson::decode(typ, raw)?;
    Ok(())
}

/// Whether the source type can possibly be assigned to the destination
/// type (dcrd `typesMaybeCompatible`).
fn types_maybe_compatible(dest: &GoType, src: &GoType) -> bool {
    if dest == src {
        return true;
    }
    let src_kind = src.kind();
    let dest_kind = dest.kind();
    if dest_kind.is_numeric() && src_kind.is_numeric() {
        return true;
    }
    if src_kind == Kind::String {
        if dest_kind.is_numeric() {
            return true;
        }
        match dest_kind {
            Kind::Bool | Kind::String | Kind::Array | Kind::Slice | Kind::Struct | Kind::Map => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn invalid_type(param_num: usize, field_name: &str, dest: &GoType, src: &GoType) -> DcrjsonError {
    let str = format!(
        "parameter #{param_num} '{field_name}' must be type {} (got {})",
        dest.display(),
        src.display(),
    );
    make_error(ErrorKind::InvalidType, str)
}

fn overflow_error(param_num: usize, field_name: &str, dest: &GoType) -> DcrjsonError {
    let str = format!(
        "parameter #{param_num} '{field_name}' overflows destination type {}",
        dest.display(),
    );
    make_error(ErrorKind::InvalidType, str)
}

fn parse_error(param_num: usize, field_name: &str, dest: &GoType) -> DcrjsonError {
    let str = format!(
        "parameter #{param_num} '{field_name}' must parse to a {}",
        dest.display(),
    );
    make_error(ErrorKind::InvalidType, str)
}

/// The numeric value of a signed-integer [`GoValue`].
fn int_of(val: &GoValue) -> i64 {
    match val {
        GoValue::Int(i) => *i,
        _ => 0,
    }
}

/// The numeric value of an unsigned-integer [`GoValue`].
fn uint_of(val: &GoValue) -> u64 {
    match val {
        GoValue::Uint(u) => *u,
        _ => 0,
    }
}

/// The numeric value of a float [`GoValue`].
fn float_of(val: &GoValue) -> f64 {
    match val {
        GoValue::Float32(f) => *f as f64,
        GoValue::Float64(f) => *f,
        _ => 0.0,
    }
}

fn is_int_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64
    )
}

fn is_uint_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64
    )
}

fn store_float(kind: Kind, f: f64) -> GoValue {
    if kind == Kind::Float32 {
        GoValue::Float32(f as f32)
    } else {
        GoValue::Float64(f)
    }
}

/// Go `reflect.Value.OverflowFloat` for a `float32` destination.
fn overflow_float32(x: f64) -> bool {
    let ax = x.abs();
    (f32::MAX as f64) < ax && ax <= f64::MAX
}

/// Assign the provided source argument to the destination field (dcrd
/// `assignField`): direct assignments, indirection, conversion of
/// numeric types, and unmarshalling of strings into arrays, slices,
/// structs, and maps.
fn assign_field(
    param_num: usize,
    field_name: &str,
    dest: &GoType,
    src: &Arg,
) -> Result<GoValue, DcrjsonError> {
    // Just error now when the types have no chance of being
    // compatible.
    let (dest_base, dest_indirects) = dest.base_type();
    let (src_base, src_indirects) = src.typ.base_type();
    if !types_maybe_compatible(dest_base, src_base) {
        return Err(invalid_type(param_num, field_name, dest_base, src_base));
    }

    // Check if it's possible to simply set the dest to the provided
    // source.  Values carry no pointer wrappers here, so matching base
    // types with sufficient source indirection are a direct copy.
    if dest_base == src_base && src_indirects >= dest_indirects {
        return Ok(src.val.clone());
    }
    if dest_base == src_base {
        // Destination has more indirects than the source; the missing
        // pointers are created, then the value is set directly.
        return Ok(src.val.clone());
    }

    // Perform supported type conversions.
    let src_kind = src_base.kind();
    let dest_kind = dest_base.kind();
    if is_int_kind(src_kind) {
        let src_int = int_of(&src.val);
        if is_int_kind(dest_kind) {
            if overflow_int(dest_kind, src_int) {
                return Err(overflow_error(param_num, field_name, dest_base));
            }
            return Ok(GoValue::Int(src_int));
        }
        if is_uint_kind(dest_kind) {
            if src_int < 0 || overflow_uint(dest_kind, src_int as u64) {
                return Err(overflow_error(param_num, field_name, dest_base));
            }
            return Ok(GoValue::Uint(src_int as u64));
        }
        return Err(invalid_type(param_num, field_name, dest_base, src_base));
    }
    if is_uint_kind(src_kind) {
        let src_uint = uint_of(&src.val);
        if is_int_kind(dest_kind) {
            if src_uint > (1u64 << 63).wrapping_sub(1) {
                return Err(overflow_error(param_num, field_name, dest_base));
            }
            if overflow_int(dest_kind, src_uint as i64) {
                return Err(overflow_error(param_num, field_name, dest_base));
            }
            return Ok(GoValue::Int(src_uint as i64));
        }
        if is_uint_kind(dest_kind) {
            if overflow_uint(dest_kind, src_uint) {
                return Err(overflow_error(param_num, field_name, dest_base));
            }
            return Ok(GoValue::Uint(src_uint));
        }
        return Err(invalid_type(param_num, field_name, dest_base, src_base));
    }
    if matches!(src_kind, Kind::Float32 | Kind::Float64) {
        if !matches!(dest_kind, Kind::Float32 | Kind::Float64) {
            return Err(invalid_type(param_num, field_name, dest_base, src_base));
        }
        let src_float = float_of(&src.val);
        if dest_kind == Kind::Float32 && overflow_float32(src_float) {
            return Err(overflow_error(param_num, field_name, dest_base));
        }
        return Ok(store_float(dest_kind, src_float));
    }
    if src_kind == Kind::String {
        let s = match &src.val {
            GoValue::String(s) => s.clone(),
            _ => String::new(),
        };
        match dest_kind {
            // String -> bool.
            Kind::Bool => match go_parse_bool(&s) {
                Ok(b) => return Ok(GoValue::Bool(b)),
                Err(()) => return Err(parse_error(param_num, field_name, dest_base)),
            },
            // String -> signed integer of varying size.
            k if is_int_kind(k) => match go_parse_int(&s) {
                Ok(n) => {
                    if overflow_int(k, n) {
                        return Err(overflow_error(param_num, field_name, dest_base));
                    }
                    return Ok(GoValue::Int(n));
                }
                Err(()) => return Err(parse_error(param_num, field_name, dest_base)),
            },
            // String -> unsigned integer of varying size.
            k if is_uint_kind(k) => match go_parse_uint(&s) {
                Ok(n) => {
                    if overflow_uint(k, n) {
                        return Err(overflow_error(param_num, field_name, dest_base));
                    }
                    return Ok(GoValue::Uint(n));
                }
                Err(()) => return Err(parse_error(param_num, field_name, dest_base)),
            },
            // String -> float of varying size.
            Kind::Float32 | Kind::Float64 => match go_parse_float(&s) {
                Ok(f) => {
                    if dest_kind == Kind::Float32 && overflow_float32(f) {
                        return Err(overflow_error(param_num, field_name, dest_base));
                    }
                    return Ok(store_float(dest_kind, f));
                }
                Err(()) => return Err(parse_error(param_num, field_name, dest_base)),
            },
            // String -> string (typecast).
            Kind::String => return Ok(GoValue::String(s)),
            // String -> arrays, slices, structs, and maps via
            // json.Unmarshal.
            Kind::Array | Kind::Slice | Kind::Struct | Kind::Map => {
                match gojson::decode(dest_base, &s) {
                    Ok(v) => return Ok(v),
                    Err(_) => {
                        let str = format!(
                            "parameter #{param_num} '{field_name}' must be valid JSON \
                             which unmarshals to a {}",
                            dest_base.display(),
                        );
                        return Err(make_error(ErrorKind::InvalidType, str));
                    }
                }
            }
            _ => {}
        }
    }

    // Mirrors Go's fall-through, which leaves the destination at its
    // zero value without error for source kinds not covered by the
    // conversion switch (unreachable through the compatibility check).
    Ok(GoValue::zero(dest_base))
}

/// Create a new command that can marshal to a JSON-RPC request while
/// respecting the requirements of the provided method (dcrd `NewCmd`).
pub fn new_cmd(
    registry: &Registry,
    method: &Method,
    args: &[Arg],
) -> Result<CmdInstance, DcrjsonError> {
    // Look up details about the provided method.  Any methods that
    // aren't registered are an error.
    let Some(rtp) = registry.method_to_type.get(method) else {
        let str = format!("{} is not registered", gojson::go_quote(&method.name));
        return Err(make_error(ErrorKind::UnregisteredMethod, str));
    };
    let info = &registry.method_to_info[method];

    // Ensure the number of parameters are correct.
    let num_params = args.len();
    check_num_params(num_params, info)?;

    // Create the appropriate command type for the method and assign
    // each argument to the according struct field after checking its
    // type validity.
    let fields = rtp.elem().fields();
    let mut values: Vec<GoValue> = fields.iter().map(|f| GoValue::zero(&f.typ)).collect();
    for (i, arg) in args.iter().enumerate() {
        let field_name = fields[i].name.to_lowercase();
        values[i] = assign_field(i.saturating_add(1), &field_name, &fields[i].typ, arg)?;
    }

    Ok(CmdInstance::new(rtp.clone(), values))
}
