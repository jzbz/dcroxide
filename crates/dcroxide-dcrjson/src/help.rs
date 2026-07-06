// SPDX-License-Identifier: ISC
//! Help text generation (dcrd dcrjson `help.go`).

use std::collections::HashMap;

use crate::gojson::go_quote;
use crate::gotype::{GoType, GoValue, Kind};
use crate::registry::{Method, MethodInfo, Registry};
use crate::tabwriter::TabWriter;
use crate::usage::method_usage_text;
use crate::{DcrjsonError, ErrorKind, make_error};

/// The various help labels, types, and example values used when
/// generating help (dcrd `baseHelpDescs`).
fn base_help_desc(key: &str) -> Option<&'static str> {
    Some(match key {
        // Misc help labels and output.
        "help-arguments" => "Arguments",
        "help-arguments-none" => "None",
        "help-result" => "Result",
        "help-result-nothing" => "Nothing",
        "help-default" => "default",
        "help-optional" => "optional",
        "help-required" => "required",
        // JSON types.
        "json-type-numeric" => "numeric",
        "json-type-string" => "string",
        "json-type-bool" => "boolean",
        "json-type-array" => "array of ",
        "json-type-object" => "object",
        "json-type-value" => "value",
        // JSON examples.
        "json-example-string" => "value",
        "json-example-bool" => "true|false",
        "json-example-map-data" => "data",
        "json-example-unknown" => "unknown",
        _ => return None,
    })
}

/// The description lookup used during help generation, which falls
/// back to the base help descriptions map for unrecognized keys and
/// tracks the last missing key (dcrd's `xT` closure).
struct DescLookup<'a> {
    descs: &'a HashMap<String, String>,
    missing_key: Option<String>,
}

impl DescLookup<'_> {
    fn xt(&mut self, key: &str) -> String {
        if let Some(desc) = self.descs.get(key) {
            return desc.clone();
        }
        if let Some(desc) = base_help_desc(key) {
            return desc.to_string();
        }
        self.missing_key = Some(key.to_string());
        key.to_string()
    }
}

/// A string that represents the JSON type associated with the provided
/// Go type (dcrd `reflectTypeToJSONType`).
fn type_to_json_type(xt: &mut DescLookup<'_>, rt: &GoType) -> String {
    let kind = rt.kind();
    if kind.is_numeric() {
        return xt.xt("json-type-numeric");
    }
    match kind {
        Kind::String => xt.xt("json-type-string"),
        Kind::Bool => xt.xt("json-type-bool"),
        Kind::Array | Kind::Slice => {
            let inner = type_to_json_type(xt, rt.elem());
            format!("{}{inner}", xt.xt("json-type-array"))
        }
        Kind::Struct | Kind::Map => xt.xt("json-type-object"),
        _ => xt.xt("json-type-value"),
    }
}

/// The result help lines for a struct (dcrd `resultStructHelp`).  Each
/// line uses tabs so a tabwriter can align everything later.
fn result_struct_help(xt: &mut DescLookup<'_>, rt: &GoType, indent_level: usize) -> Vec<String> {
    let indent = " ".repeat(indent_level);
    let type_name = rt.name().to_lowercase();

    let fields = rt.fields();
    let mut results = Vec::with_capacity(fields.len());
    for rtf in fields {
        // The field name to display is the json name when it's
        // available, otherwise the lowercase field name.
        let field_name = match &rtf.json_tag {
            Some(tag) if !tag.is_empty() => tag.split(',').next().unwrap_or("").to_string(),
            _ => rtf.name.to_lowercase(),
        };

        // Dereference the pointer if needed.
        let rtf_type = if rtf.typ.kind() == Kind::Ptr {
            rtf.typ.elem()
        } else {
            &rtf.typ
        };

        // Generate the JSON example for the result type of this struct
        // field.  When it is a complex type, examine the type and
        // adjust the opening bracket and brace combination accordingly.
        let field_type = type_to_json_type(xt, rtf_type);
        let field_desc_key = format!("{type_name}-{field_name}");
        let (field_examples, is_complex) =
            type_to_json_example(xt, rtf_type, indent_level, &field_desc_key);
        if is_complex {
            let brace = match rtf_type.kind() {
                Kind::Array | Kind::Slice => "[{",
                _ => "{",
            };
            results.push(format!(
                "{indent}\"{field_name}\": {brace}\t({field_type})\t{}",
                xt.xt(&field_desc_key),
            ));
            results.extend(field_examples);
        } else {
            results.push(format!(
                "{indent}\"{field_name}\": {},\t({field_type})\t{}",
                field_examples[0],
                xt.xt(&field_desc_key),
            ));
        }
    }

    results
}

/// Example usage lines in the format used by the help output (dcrd
/// `reflectTypeToJSONExample`).  The second return value reports
/// whether the type results in a complex JSON object.
fn type_to_json_example(
    xt: &mut DescLookup<'_>,
    rt: &GoType,
    indent_level: usize,
    field_desc_key: &str,
) -> (Vec<String>, bool) {
    // Indirect the pointer if needed.
    let rt = if rt.kind() == Kind::Ptr {
        rt.elem()
    } else {
        rt
    };
    let kind = rt.kind();
    if kind.is_numeric() {
        if matches!(kind, Kind::Float32 | Kind::Float64) {
            return (vec!["n.nnn".to_string()], false);
        }
        return (vec!["n".to_string()], false);
    }

    match kind {
        Kind::String => (vec![format!("\"{}\"", xt.xt("json-example-string"))], false),
        Kind::Bool => (vec![xt.xt("json-example-bool")], false),
        Kind::Struct => {
            let indent = " ".repeat(indent_level);
            let mut results = result_struct_help(xt, rt, indent_level.saturating_add(1));

            // An opening brace is needed for the first indent level.
            // For all others, it is included as part of the previous
            // field.
            if indent_level == 0 {
                results.insert(0, "{".to_string());
            }

            // The closing brace has a comma after it except for the
            // first indent level.  The final tabs are necessary so the
            // tab writer lines things up properly.
            let mut closing_brace = format!("{indent}}}");
            if indent_level > 0 {
                closing_brace.push(',');
            }
            results.push(format!("{closing_brace}\t\t"));
            (results, true)
        }
        Kind::Array | Kind::Slice => {
            let (mut results, is_complex) =
                type_to_json_example(xt, rt.elem(), indent_level, field_desc_key);

            // When the result is complex, it is because this is an
            // array of objects.
            if is_complex {
                let indent = " ".repeat(indent_level);
                if indent_level == 0 {
                    results[0] = format!("{indent}[{{");
                    let last = results.len().saturating_sub(1);
                    results[last] = format!("{indent}}},...]");
                    return (results, true);
                }

                // The opening array bracket and object brace are
                // already part of the previous field; replace the
                // closing entry with the variadic array closing
                // syntax.
                let last = results.len().saturating_sub(1);
                results[last] = format!("{indent}}},...],\t\t");
                return (results, true);
            }

            // It's an array of primitives.
            (vec![format!("[{},...]", results[0])], false)
        }
        Kind::Map => {
            let indent = " ".repeat(indent_level);
            let mut results = Vec::with_capacity(3);

            if indent_level == 0 {
                results.push(format!("{indent}{{"));
            }

            // Maps need the key, value, and description of the object
            // entry specifically called out.
            let inner_indent = " ".repeat(indent_level.saturating_add(1));
            let json_type = type_to_json_type(xt, rt);
            let result = format!(
                "{inner_indent}{}: {}, ({json_type}) {}",
                go_quote(&xt.xt(&format!("{field_desc_key}--key"))),
                xt.xt(&format!("{field_desc_key}--value")),
                xt.xt(&format!("{field_desc_key}--desc")),
            );
            results.push(result);
            results.push(format!("{inner_indent}..."));

            results.push(format!("{indent}}}"));
            (results, true)
        }
        _ => (vec![xt.xt("json-example-unknown")], false),
    }
}

/// Formatted help for the provided result type (dcrd `resultTypeHelp`).
fn result_type_help(xt: &mut DescLookup<'_>, rt: &GoType, field_desc_key: &str) -> String {
    // Generate the JSON example for the result type.
    let (results, is_complex) = type_to_json_example(xt, rt, 0, field_desc_key);

    // When this is a primitive type, add the associated JSON type and
    // result description into the final string.
    if !is_complex {
        return format!(
            "{} ({}) {}",
            results[0],
            type_to_json_type(xt, rt),
            xt.xt(field_desc_key),
        );
    }

    // Complex types already have the JSON types and descriptions in
    // the results; align the help text with a tab writer.
    let mut w = TabWriter::new();
    for (i, text) in results.iter().enumerate() {
        if i == results.len().saturating_sub(1) {
            w.write(text);
        } else {
            w.write(text);
            w.write("\n");
        }
    }
    w.flush()
}

/// The type of a command argument as a string in the format used by
/// the help output (dcrd `argTypeHelp`).
fn arg_type_help(
    xt: &mut DescLookup<'_>,
    field: &crate::gotype::StructField,
    default_val: Option<&GoValue>,
) -> String {
    // Indirect the pointer if needed and track whether the field is
    // optional.
    let (field_type, is_optional) = if field.typ.kind() == Kind::Ptr {
        (field.typ.elem(), true)
    } else {
        (&field.typ, false)
    };

    // Convert the field type to a JSON type.
    let mut details = Vec::with_capacity(3);
    details.push(type_to_json_type(xt, field_type));

    // Add optional and default value to the details if needed.
    if is_optional {
        details.push(xt.xt("help-optional"));

        // Add the default value if there is one.
        if let Some(dv) = default_val {
            let val = match dv {
                GoValue::String(s) => format!("\"{s}\""),
                other => other.go_display(),
            };
            details.push(format!("{}={val}", xt.xt("help-default")));
        }
    } else {
        details.push(xt.xt("help-required"));
    }

    details.join(", ")
}

/// Formatted help for the arguments of the provided command (dcrd
/// `argHelp`).
fn arg_help(xt: &mut DescLookup<'_>, rtp: &GoType, info: &MethodInfo, method: &str) -> String {
    // Return now if the command has no arguments.
    let fields = rtp.elem().fields();
    if fields.is_empty() {
        return String::new();
    }

    // Generate the help for each argument in the command.
    let mut args = Vec::with_capacity(fields.len());
    for (i, rtf) in fields.iter().enumerate() {
        let default_val = info.defaults.get(&i);
        let field_name = rtf.name.to_lowercase();
        args.push(format!(
            "{}.\t{field_name}\t({})\t{}",
            i.saturating_add(1),
            arg_type_help(xt, rtf, default_val),
            xt.xt(&format!("{method}-{field_name}")),
        ));

        // For types which require a JSON object, or an array of JSON
        // objects, generate the full syntax for the argument.
        let field_type = if rtf.typ.kind() == Kind::Ptr {
            rtf.typ.elem()
        } else {
            &rtf.typ
        };
        match field_type.kind() {
            Kind::Struct | Kind::Map => {
                let field_desc_key = format!("{method}-{field_name}");
                args.push(result_type_help(xt, field_type, &field_desc_key));
            }
            Kind::Array | Kind::Slice => {
                let field_desc_key = format!("{method}-{field_name}");
                // Mirrors Go, which inspects the element of the
                // original (possibly pointer) field type here.
                if rtf.typ.elem().kind() == Kind::Struct {
                    args.push(result_type_help(xt, field_type, &field_desc_key));
                }
            }
            _ => {}
        }
    }

    // Align the help text with a tab writer.
    let mut w = TabWriter::new();
    for text in &args {
        w.write(text);
        w.write("\n");
    }
    w.flush()
}

/// The help output for the provided command and method info (dcrd
/// `methodHelp`, the unexported work horse).
fn method_help(
    xt: &mut DescLookup<'_>,
    rtp: &GoType,
    info: &MethodInfo,
    method: &str,
    result_types: &[Option<GoType>],
) -> String {
    // Start off with the method usage and help synopsis.
    let mut help = format!(
        "{}\n\n{}\n",
        method_usage_text(rtp, info, method),
        xt.xt(&format!("{method}--synopsis")),
    );

    // Generate the help for each argument in the command.
    let arg_text = arg_help(xt, rtp, info, method);
    if !arg_text.is_empty() {
        help.push_str(&format!("\n{}:\n{arg_text}", xt.xt("help-arguments")));
    } else {
        help.push_str(&format!(
            "\n{}:\n{}\n",
            xt.xt("help-arguments"),
            xt.xt("help-arguments-none"),
        ));
    }

    // Generate the help text for each result type.
    let mut result_texts = Vec::with_capacity(result_types.len());
    for (i, result_type) in result_types.iter().enumerate() {
        let field_desc_key = format!("{method}--result{i}");
        match result_type {
            None => result_texts.push(xt.xt("help-result-nothing")),
            Some(rtp) => {
                result_texts.push(result_type_help(xt, rtp.elem(), &field_desc_key));
            }
        }
    }

    // Add result types and descriptions.  When there is more than one
    // result type, also add the condition which triggers it.
    if result_texts.len() > 1 {
        for (i, result_text) in result_texts.iter().enumerate() {
            let cond_key = format!("{method}--condition{i}");
            help.push_str(&format!(
                "\n{} ({}):\n{result_text}\n",
                xt.xt("help-result"),
                xt.xt(&cond_key),
            ));
        }
    } else if let Some(result_text) = result_texts.first() {
        help.push_str(&format!("\n{}:\n{result_text}\n", xt.xt("help-result")));
    } else {
        help.push_str(&format!(
            "\n{}:\n{}\n",
            xt.xt("help-result"),
            xt.xt("help-result-nothing"),
        ));
    }
    help
}

/// Whether the passed kind is one of the acceptable types for results
/// (dcrd `isValidResultType`).
fn is_valid_result_type(kind: Kind) -> bool {
    if kind.is_numeric() {
        return true;
    }
    matches!(
        kind,
        Kind::String | Kind::Struct | Kind::Array | Kind::Slice | Kind::Bool | Kind::Map
    )
}

impl Registry {
    /// Generate help output for the provided method and result types
    /// given a map of description keys (dcrd `GenerateHelp`).
    ///
    /// The result types are pointer-to-types describing the values the
    /// command returns, with `None` standing for Go's nil (a command
    /// that returns nothing).  When a description key is missing, the
    /// generated help uses the key in place of the description and an
    /// `ErrMissingDescription` error naming the final missing key is
    /// returned along with the help text.
    pub fn generate_help(
        &self,
        method: &Method,
        descs: &HashMap<String, String>,
        result_types: &[Option<GoType>],
    ) -> (String, Option<DcrjsonError>) {
        // Look up details about the provided method and error out if
        // not registered.
        let Some(rtp) = self.method_to_type.get(method) else {
            let str = format!(
                "{} is not registered",
                crate::gojson::go_quote(&method.name)
            );
            return (
                String::new(),
                Some(make_error(ErrorKind::UnregisteredMethod, str)),
            );
        };
        let info = &self.method_to_info[method];

        // Validate each result type is a pointer to a supported type
        // (or nil).
        for (i, result_type) in result_types.iter().enumerate() {
            let Some(rt) = result_type else { continue };
            let GoType::Ptr(elem) = rt else {
                let str = format!("result #{i} ({}) is not a pointer", rt.kind());
                return (String::new(), Some(make_error(ErrorKind::InvalidType, str)));
            };
            let elem_kind = elem.kind();
            if !is_valid_result_type(elem_kind) {
                let str = format!("result #{i} ({elem_kind}) is not an allowed type");
                return (String::new(), Some(make_error(ErrorKind::InvalidType, str)));
            }
        }

        let mut xt = DescLookup {
            descs,
            missing_key: None,
        };

        // Generate and return the help for the method.
        let help = method_help(&mut xt, rtp, info, &method.name, result_types);
        match xt.missing_key {
            Some(key) => (help, Some(make_error(ErrorKind::MissingDescription, key))),
            None => (help, None),
        }
    }
}
