// SPDX-License-Identifier: ISC
//! One-line method usage text (the usage half of dcrd dcrjson
//! `cmdinfo.go`).

use crate::gojson::go_quote;
use crate::gotype::{GoType, GoValue, Kind};
use crate::registry::{Method, MethodInfo, Registry};
use crate::{DcrjsonError, ErrorKind, make_error};

/// A string for use in the one-line usage for the given sub struct
/// (dcrd `subStructUsage`).
fn sub_struct_usage(struct_type: &GoType) -> String {
    let fields = struct_type.fields();
    let mut field_usages = Vec::with_capacity(fields.len());
    for rtf in fields {
        // When the field has a jsonrpcusage struct tag specified, use
        // that instead of automatically generating it.
        if let Some(tag) = &rtf.usage_tag
            && !tag.is_empty()
        {
            field_usages.push(tag.clone());
            continue;
        }

        // Create the name/value entry for the field while considering
        // the type of the field.
        let field_name = rtf.name.to_lowercase();
        let field_kind = rtf.typ.kind();
        let field_value = if field_kind.is_numeric() {
            if matches!(field_kind, Kind::Float32 | Kind::Float64) {
                "n.nnn".to_string()
            } else {
                "n".to_string()
            }
        } else {
            match field_kind {
                Kind::String => "\"value\"".to_string(),
                Kind::Struct => sub_struct_usage(&rtf.typ),
                Kind::Array | Kind::Slice => sub_array_usage(&rtf.typ, &field_name),
                _ => field_name.clone(),
            }
        };

        field_usages.push(format!("{}:{field_value}", go_quote(&field_name)));
    }

    format!("{{{}}}", field_usages.join(","))
}

/// A string for use in the one-line usage for the given array or slice
/// (dcrd `subArrayUsage`), converting plural field names to singular.
fn sub_array_usage(array_type: &GoType, field_name: &str) -> String {
    // Convert plural field names to singular.  Only works for English.
    let singular = if let Some(prefix) = field_name.strip_suffix("ies") {
        format!("{prefix}y")
    } else if let Some(prefix) = field_name.strip_suffix("es") {
        prefix.to_string()
    } else if let Some(prefix) = field_name.strip_suffix('s') {
        prefix.to_string()
    } else {
        field_name.to_string()
    };

    match array_type.elem().kind() {
        Kind::String => format!("[{},...]", go_quote(&singular)),
        Kind::Struct => format!("[{},...]", sub_struct_usage(array_type.elem())),
        _ => format!("[{singular},...]"),
    }
}

/// A string for use in the one-line usage for the struct field of a
/// command (dcrd `fieldUsage`).
fn field_usage(field: &crate::gotype::StructField, default_val: Option<&GoValue>) -> String {
    // When the field has a jsonrpcusage struct tag specified, use that
    // instead of automatically generating it.
    if let Some(tag) = &field.usage_tag
        && !tag.is_empty()
    {
        return tag.clone();
    }

    // Indirect the pointer if needed.
    let field_type = if field.typ.kind() == Kind::Ptr {
        field.typ.elem()
    } else {
        &field.typ
    };

    // Handle certain types uniquely to provide nicer usage.
    let field_name = field.name.to_lowercase();
    match field_type.kind() {
        Kind::String => {
            if let Some(dv) = default_val {
                return format!("{field_name}={}", go_quote(&dv.go_display()));
            }
            go_quote(&field_name)
        }
        Kind::Array | Kind::Slice => sub_array_usage(field_type, &field_name),
        Kind::Struct => sub_struct_usage(field_type),
        _ => match default_val {
            Some(dv) => format!("{field_name}={}", dv.go_display()),
            None => field_name,
        },
    }
}

/// A one-line usage string for the provided command type and method
/// (dcrd `methodUsageText`, the unexported work horse).
pub(crate) fn method_usage_text(rtp: &GoType, info: &MethodInfo, method: &str) -> String {
    // Generate the individual usage for each field in the command.
    let fields = rtp.elem().fields();
    let mut req_field_usages = Vec::with_capacity(fields.len());
    let mut opt_field_usages = Vec::with_capacity(fields.len());
    for (i, rtf) in fields.iter().enumerate() {
        let is_optional = rtf.typ.kind() == Kind::Ptr;
        let default_val = info.defaults.get(&i);
        let usage = field_usage(rtf, default_val);
        if is_optional {
            opt_field_usages.push(usage);
        } else {
            req_field_usages.push(usage);
        }
    }

    // Generate and return the one-line usage string.
    let mut usage_str = method.to_string();
    if !req_field_usages.is_empty() {
        usage_str.push(' ');
        usage_str.push_str(&req_field_usages.join(" "));
    }
    if !opt_field_usages.is_empty() {
        usage_str.push_str(&format!(" ({})", opt_field_usages.join(" ")));
    }
    usage_str
}

impl Registry {
    /// A one-line usage string for the provided method (dcrd
    /// `MethodUsageText`).
    pub fn method_usage_text(&self, method: &Method) -> Result<String, DcrjsonError> {
        let Some(rtp) = self.method_to_type.get(method) else {
            let str = format!("{} is not registered", go_quote(&method.name));
            return Err(make_error(ErrorKind::UnregisteredMethod, str));
        };
        let info = &self.method_to_info[method];
        Ok(method_usage_text(rtp, info, &method.name))
    }
}
