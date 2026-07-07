// SPDX-License-Identifier: ISC
//! Command registration (dcrd dcrjson `register.go` and the lookup
//! half of `cmdinfo.go`).

use std::collections::HashMap;

use crate::gojson;
use crate::gotype::{GoType, GoValue, Kind};
use crate::{DcrjsonError, ErrorKind, make_error};

/// Flags that specify additional properties about the circumstances
/// under which a command can be used (dcrd `UsageFlag`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsageFlag(pub u32);

/// The command can only be used when communicating with an RPC server
/// over websockets (dcrd `UFWebsocketOnly`).
pub const UF_WEBSOCKET_ONLY: UsageFlag = UsageFlag(1 << 1);

/// The command is actually a notification and must be marshalled with
/// a nil id (dcrd `UFNotification`).
pub const UF_NOTIFICATION: UsageFlag = UsageFlag(1 << 2);

/// The maximum usage flag bit (dcrd `highestUsageFlagBit`).
const HIGHEST_USAGE_FLAG_BIT: u32 = 1 << 3;

impl core::fmt::Display for UsageFlag {
    /// The flag in human-readable form (dcrd `UsageFlag.String`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Mask off the deprecated WalletOnly bit.
        let mut fl = self.0 & !0x01;
        if fl == 0 {
            return f.write_str("0x0");
        }
        let mut s = String::new();
        let mut flag = 1u32;
        while flag < HIGHEST_USAGE_FLAG_BIT {
            let name = match UsageFlag(fl & flag) {
                x if x == UF_WEBSOCKET_ONLY => Some("UFWebsocketOnly"),
                x if x == UF_NOTIFICATION => Some("UFNotification"),
                _ => None,
            };
            if let Some(name) = name {
                s.push_str(name);
                s.push('|');
                fl = fl.wrapping_sub(flag);
            }
            flag = flag.wrapping_shl(1);
        }
        let mut s = s.trim_end_matches('|').to_string();
        if fl != 0 {
            s.push_str(&format!("|0x{fl:x}"));
        }
        let s = s.trim_start_matches('|');
        f.write_str(s)
    }
}

/// A method key.  Go's dcrjson keys its registry on an `interface{}`
/// holding a string-kinded value, so both the dynamic type and the
/// string value participate in lookups; `type_name` carries the Go
/// display name of that dynamic type (e.g. `types.Method` or plain
/// `string`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Method {
    /// The Go display name of the method's dynamic type.
    pub type_name: String,
    /// The method string itself.
    pub name: String,
}

impl Method {
    /// A method keyed by a plain Go `string`.
    pub fn plain(name: &str) -> Method {
        Method {
            type_name: "string".to_string(),
            name: name.to_string(),
        }
    }

    /// A method keyed by a defined string type with the given Go
    /// display name.
    pub fn typed(type_name: &str, name: &str) -> Method {
        Method {
            type_name: type_name.to_string(),
            name: name.to_string(),
        }
    }
}

/// Information about a registered method (dcrd `methodInfo`).
#[derive(Clone, Debug)]
pub(crate) struct MethodInfo {
    pub max_params: usize,
    pub num_req_params: usize,
    // Stored but never read, exactly like dcrd's methodInfo field.
    #[allow(dead_code)]
    pub num_opt_params: usize,
    pub defaults: HashMap<usize, GoValue>,
    pub flags: UsageFlag,
}

/// The command registry (the explicit form of dcrd's package-global
/// registration maps; dcrd's mutex is daemon-phase concurrency).
#[derive(Default)]
pub struct Registry {
    pub(crate) method_to_type: HashMap<Method, GoType>,
    pub(crate) method_to_info: HashMap<Method, MethodInfo>,
    pub(crate) type_to_method: HashMap<GoType, Method>,
}

/// Whether the passed field kind is a supported type (dcrd
/// `isAcceptableKind`).  It is called after the first pointer
/// indirection, so further pointers are not supported.
fn is_acceptable_kind(kind: Kind) -> bool {
    !matches!(
        kind,
        Kind::Chan | Kind::Complex64 | Kind::Complex128 | Kind::Func | Kind::Ptr | Kind::Interface
    )
}

impl Registry {
    /// A new, empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Register a method with its parameter struct type and usage
    /// flags (dcrd `Register`).
    ///
    /// The params type must be a pointer to a struct whose fields obey
    /// dcrjson's layout rules; violations produce the same errors dcrd
    /// produces.  Go's additional check that the method itself is a
    /// string-kinded value is unrepresentable here because [`Method`]
    /// is a string by construction.
    pub fn register(
        &mut self,
        method: &Method,
        params: &GoType,
        flags: UsageFlag,
    ) -> Result<(), DcrjsonError> {
        if self.method_to_type.contains_key(method) {
            let str = format!(
                "method {} is already registered for type {}",
                gojson::go_quote(&method.name),
                method.type_name,
            );
            return Err(make_error(ErrorKind::DuplicateMethod, str));
        }

        if let Some(registered) = self.type_to_method.get(params) {
            let str = format!(
                "param type {} is already registered for method {}",
                params.display(),
                gojson::go_quote(&registered.name),
            );
            return Err(make_error(ErrorKind::DuplicateMethod, str));
        }

        // Ensure that no unrecognized flag bits were specified.
        if !HIGHEST_USAGE_FLAG_BIT.wrapping_sub(1) & flags.0 != 0 {
            let str = format!(
                "invalid usage flags specified for method {}: {}",
                method.name, flags,
            );
            return Err(make_error(ErrorKind::InvalidUsageFlags, str));
        }

        let GoType::Ptr(rt) = params else {
            let str = format!(
                "type must be *struct not '{} ({})'",
                params.display(),
                params.kind(),
            );
            return Err(make_error(ErrorKind::InvalidType, str));
        };
        if rt.kind() != Kind::Struct {
            let str = format!(
                "type must be *struct not '{} (*{})'",
                params.display(),
                rt.kind(),
            );
            return Err(make_error(ErrorKind::InvalidType, str));
        }

        // Enumerate the struct fields to validate them and gather
        // parameter information.
        let fields = rt.fields();
        let num_fields = fields.len();
        let mut num_opt_fields = 0usize;
        let mut defaults: HashMap<usize, GoValue> = HashMap::new();
        for (i, rtf) in fields.iter().enumerate() {
            if rtf.anonymous {
                let str = format!(
                    "embedded fields are not supported (field name: {})",
                    gojson::go_quote(&rtf.name),
                );
                return Err(make_error(ErrorKind::EmbeddedType, str));
            }
            if rtf.unexported {
                let str = format!(
                    "unexported fields are not supported (field name: {})",
                    gojson::go_quote(&rtf.name),
                );
                return Err(make_error(ErrorKind::UnexportedField, str));
            }

            // Disallow types that can't be JSON encoded.  Also,
            // determine if the field is optional based on it being a
            // pointer.
            let mut is_optional = false;
            let mut kind = rtf.typ.kind();
            if kind == Kind::Ptr {
                is_optional = true;
                kind = rtf.typ.elem().kind();
            }
            if !is_acceptable_kind(kind) {
                let str = format!(
                    "unsupported field type '{} ({})' (field name {})",
                    rtf.typ.display(),
                    rtf.typ.base_kind_string(),
                    gojson::go_quote(&rtf.name),
                );
                return Err(make_error(ErrorKind::UnsupportedFieldType, str));
            }

            // Count the optional fields and ensure all fields after
            // the first optional field are also optional.
            if is_optional {
                num_opt_fields = num_opt_fields.saturating_add(1);
            } else if num_opt_fields > 0 {
                let str = format!(
                    "all fields after the first optional field must also be optional \
                     (field name {})",
                    gojson::go_quote(&rtf.name),
                );
                return Err(make_error(ErrorKind::NonOptionalField, str));
            }

            // Ensure the default value can be unmarshalled into the
            // type and that defaults are only specified for optional
            // fields.
            if let Some(tag) = &rtf.default_tag
                && !tag.is_empty()
            {
                if !is_optional {
                    let str = format!(
                        "required fields must not have a default specified \
                             (field name {})",
                        gojson::go_quote(&rtf.name),
                    );
                    return Err(make_error(ErrorKind::NonOptionalDefault, str));
                }

                match gojson::decode(rtf.typ.elem(), tag) {
                    Ok(val) => {
                        defaults.insert(i, val);
                    }
                    Err(_) => {
                        let str = format!(
                            "default value of {} is the wrong type (field name {})",
                            gojson::go_quote(tag),
                            gojson::go_quote(&rtf.name),
                        );
                        return Err(make_error(ErrorKind::MismatchedDefault, str));
                    }
                }
            }
        }

        // Update the registration maps.
        self.method_to_type.insert(method.clone(), params.clone());
        self.method_to_info.insert(
            method.clone(),
            MethodInfo {
                max_params: num_fields,
                num_req_params: num_fields.saturating_sub(num_opt_fields),
                num_opt_params: num_opt_fields,
                defaults,
                flags,
            },
        );
        self.type_to_method.insert(params.clone(), method.clone());
        Ok(())
    }

    /// Register a method, panicking on error (dcrd `MustRegister`).
    /// This should only be called while wiring up static command sets.
    pub fn must_register(&mut self, method: &Method, params: &GoType, flags: UsageFlag) {
        if let Err(e) = self.register(method, params, flags) {
            panic!("{}", e.description);
        }
    }

    /// A sorted list of registered methods whose method key has the
    /// given dynamic type name (dcrd `RegisteredMethods`).
    pub fn registered_methods(&self, method_type_name: &str) -> Vec<String> {
        let mut methods: Vec<String> = self
            .method_to_info
            .keys()
            .filter(|m| m.type_name == method_type_name)
            .map(|m| m.name.clone())
            .collect();
        methods.sort();
        methods
    }

    /// The method for the passed command type (dcrd `CmdMethod`).
    pub fn cmd_method(&self, cmd_type: &GoType) -> Result<String, DcrjsonError> {
        match self.type_to_method.get(cmd_type) {
            Some(method) => Ok(method.name.clone()),
            None => {
                let str = format!("{} is not registered", cmd_type.display());
                Err(make_error(ErrorKind::UnregisteredMethod, str))
            }
        }
    }

    /// The usage flags for the passed method (dcrd `MethodUsageFlags`).
    pub fn method_usage_flags(&self, method: &Method) -> Result<UsageFlag, DcrjsonError> {
        match self.method_to_info.get(method) {
            Some(info) => Ok(info.flags),
            None => {
                let str = format!("{} is not registered", gojson::go_quote(&method.name));
                Err(make_error(ErrorKind::UnregisteredMethod, str))
            }
        }
    }
}
