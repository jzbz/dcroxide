// SPDX-License-Identifier: ISC
//! A miniature model of Go's `reflect` type and value system covering
//! the shapes dcrd's dcrjson package operates on.
//!
//! dcrjson drives command registration, marshalling, parameter
//! parsing, usage generation, and help generation entirely through
//! reflection over Go struct types.  Rust has no reflection, so the
//! port makes the type information explicit: a [`GoType`] describes a
//! Go type tree (including struct tags), and a [`GoValue`] holds a
//! value of such a type.  All observable behavior — JSON bytes, error
//! strings, usage and help text — matches what dcrd computes through
//! `reflect`.

/// The reflection kind of a type (Go `reflect.Kind`), after resolving
/// named types to their underlying type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Go `int` (64-bit on the supported targets).
    Int,
    /// Go `int8`.
    Int8,
    /// Go `int16`.
    Int16,
    /// Go `int32`.
    Int32,
    /// Go `int64`.
    Int64,
    /// Go `uint` (64-bit on the supported targets).
    Uint,
    /// Go `uint8`.
    Uint8,
    /// Go `uint16`.
    Uint16,
    /// Go `uint32`.
    Uint32,
    /// Go `uint64`.
    Uint64,
    /// Go `float32`.
    Float32,
    /// Go `float64`.
    Float64,
    /// Go `bool`.
    Bool,
    /// Go `string`.
    String,
    /// A pointer.
    Ptr,
    /// A slice.
    Slice,
    /// A fixed-size array.
    Array,
    /// A map.
    Map,
    /// A struct.
    Struct,
    /// An interface.
    Interface,
    /// A channel.
    Chan,
    /// A function.
    Func,
    /// Go `complex64`.
    Complex64,
    /// Go `complex128`.
    Complex128,
}

impl Kind {
    /// The lower-case kind name as printed by Go's `reflect.Kind`
    /// `String` method.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Int => "int",
            Kind::Int8 => "int8",
            Kind::Int16 => "int16",
            Kind::Int32 => "int32",
            Kind::Int64 => "int64",
            Kind::Uint => "uint",
            Kind::Uint8 => "uint8",
            Kind::Uint16 => "uint16",
            Kind::Uint32 => "uint32",
            Kind::Uint64 => "uint64",
            Kind::Float32 => "float32",
            Kind::Float64 => "float64",
            Kind::Bool => "bool",
            Kind::String => "string",
            Kind::Ptr => "ptr",
            Kind::Slice => "slice",
            Kind::Array => "array",
            Kind::Map => "map",
            Kind::Struct => "struct",
            Kind::Interface => "interface",
            Kind::Chan => "chan",
            Kind::Func => "func",
            Kind::Complex64 => "complex64",
            Kind::Complex128 => "complex128",
        }
    }

    /// Whether the kind is a signed or unsigned integer of any
    /// magnitude or a float of any magnitude (dcrd `isNumeric`).
    pub fn is_numeric(self) -> bool {
        matches!(
            self,
            Kind::Int
                | Kind::Int8
                | Kind::Int16
                | Kind::Int32
                | Kind::Int64
                | Kind::Uint
                | Kind::Uint8
                | Kind::Uint16
                | Kind::Uint32
                | Kind::Uint64
                | Kind::Float32
                | Kind::Float64
        )
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A field of a Go struct type, including the struct tags dcrjson
/// inspects.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StructField {
    /// The Go field name (exported names start with an upper-case
    /// letter).
    pub name: String,
    /// The field type.
    pub typ: GoType,
    /// The `json` struct tag value, if any.
    pub json_tag: Option<String>,
    /// The `jsonrpcdefault` struct tag value, if any.
    pub default_tag: Option<String>,
    /// The `jsonrpcusage` struct tag value, if any.
    pub usage_tag: Option<String>,
    /// Whether the field is embedded (Go anonymous field).
    pub anonymous: bool,
    /// Whether the field is unexported (Go `PkgPath != ""`).
    pub unexported: bool,
}

impl StructField {
    /// A plain exported field with no struct tags.
    pub fn new(name: &str, typ: GoType) -> StructField {
        StructField {
            name: name.to_string(),
            typ,
            json_tag: None,
            default_tag: None,
            usage_tag: None,
            anonymous: false,
            unexported: false,
        }
    }

    /// Attach a `json` struct tag.
    pub fn with_json_tag(mut self, tag: &str) -> StructField {
        self.json_tag = Some(tag.to_string());
        self
    }

    /// Attach a `jsonrpcdefault` struct tag.
    pub fn with_default(mut self, tag: &str) -> StructField {
        self.default_tag = Some(tag.to_string());
        self
    }

    /// Attach a `jsonrpcusage` struct tag.
    pub fn with_usage(mut self, tag: &str) -> StructField {
        self.usage_tag = Some(tag.to_string());
        self
    }

    /// Mark the field as embedded.
    pub fn embedded(mut self) -> StructField {
        self.anonymous = true;
        self
    }

    /// Mark the field as unexported.
    pub fn private(mut self) -> StructField {
        self.unexported = true;
        self
    }
}

/// A Go type tree (the subset of `reflect.Type` dcrjson operates on).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GoType {
    /// Go `int`.
    Int,
    /// Go `int8`.
    Int8,
    /// Go `int16`.
    Int16,
    /// Go `int32`.
    Int32,
    /// Go `int64`.
    Int64,
    /// Go `uint`.
    Uint,
    /// Go `uint8`.
    Uint8,
    /// Go `uint16`.
    Uint16,
    /// Go `uint32`.
    Uint32,
    /// Go `uint64`.
    Uint64,
    /// Go `float32`.
    Float32,
    /// Go `float64`.
    Float64,
    /// Go `bool`.
    Bool,
    /// Go `string`.
    String,
    /// A pointer to the element type.
    Ptr(Box<GoType>),
    /// A slice of the element type.
    Slice(Box<GoType>),
    /// A fixed-size array of the element type.
    Array(usize, Box<GoType>),
    /// A map from the key type to the value type.
    Map(Box<GoType>, Box<GoType>),
    /// An anonymous struct type.
    Struct(Vec<StructField>),
    /// A defined (named) type: package qualifier, type name, and the
    /// underlying type.  The package qualifier may be empty for types
    /// defined in the main package.
    Named(String, String, Box<GoType>),
    /// An empty interface.
    Interface,
    /// A channel of the element type.
    Chan(Box<GoType>),
    /// A function type (signature not modeled; displayed as `func()`).
    Func,
    /// Go `complex64`.
    Complex64,
    /// Go `complex128`.
    Complex128,
}

impl GoType {
    /// A named struct type in the given package.
    pub fn strukt(pkg: &str, name: &str, fields: Vec<StructField>) -> GoType {
        GoType::Named(
            pkg.to_string(),
            name.to_string(),
            Box::new(GoType::Struct(fields)),
        )
    }

    /// A pointer to this type.
    pub fn ptr(self) -> GoType {
        GoType::Ptr(Box::new(self))
    }

    /// A slice of this type.
    pub fn slice(self) -> GoType {
        GoType::Slice(Box::new(self))
    }

    /// The reflection kind, resolving named types to their underlying
    /// type (Go `reflect.Type.Kind`).
    pub fn kind(&self) -> Kind {
        match self {
            GoType::Int => Kind::Int,
            GoType::Int8 => Kind::Int8,
            GoType::Int16 => Kind::Int16,
            GoType::Int32 => Kind::Int32,
            GoType::Int64 => Kind::Int64,
            GoType::Uint => Kind::Uint,
            GoType::Uint8 => Kind::Uint8,
            GoType::Uint16 => Kind::Uint16,
            GoType::Uint32 => Kind::Uint32,
            GoType::Uint64 => Kind::Uint64,
            GoType::Float32 => Kind::Float32,
            GoType::Float64 => Kind::Float64,
            GoType::Bool => Kind::Bool,
            GoType::String => Kind::String,
            GoType::Ptr(_) => Kind::Ptr,
            GoType::Slice(_) => Kind::Slice,
            GoType::Array(_, _) => Kind::Array,
            GoType::Map(_, _) => Kind::Map,
            GoType::Struct(_) => Kind::Struct,
            GoType::Named(_, _, u) => u.kind(),
            GoType::Interface => Kind::Interface,
            GoType::Chan(_) => Kind::Chan,
            GoType::Func => Kind::Func,
            GoType::Complex64 => Kind::Complex64,
            GoType::Complex128 => Kind::Complex128,
        }
    }

    /// The element type of a pointer, slice, array, or channel,
    /// resolving named wrappers (Go `reflect.Type.Elem`).
    pub fn elem(&self) -> &GoType {
        match self {
            GoType::Ptr(e) | GoType::Slice(e) | GoType::Array(_, e) | GoType::Chan(e) => e,
            GoType::Map(_, v) => v,
            GoType::Named(_, _, u) => u.elem(),
            _ => panic!("elem of non-container type"),
        }
    }

    /// The struct fields of a struct type, resolving named wrappers.
    pub fn fields(&self) -> &[StructField] {
        match self {
            GoType::Struct(fields) => fields,
            GoType::Named(_, _, u) => u.fields(),
            _ => panic!("fields of non-struct type"),
        }
    }

    /// The unqualified type name (Go `reflect.Type.Name`); empty for
    /// unnamed types.
    pub fn name(&self) -> &str {
        match self {
            GoType::Named(_, name, _) => name,
            GoType::Int => "int",
            GoType::Int8 => "int8",
            GoType::Int16 => "int16",
            GoType::Int32 => "int32",
            GoType::Int64 => "int64",
            GoType::Uint => "uint",
            GoType::Uint8 => "uint8",
            GoType::Uint16 => "uint16",
            GoType::Uint32 => "uint32",
            GoType::Uint64 => "uint64",
            GoType::Float32 => "float32",
            GoType::Float64 => "float64",
            GoType::Bool => "bool",
            GoType::String => "string",
            GoType::Complex64 => "complex64",
            GoType::Complex128 => "complex128",
            _ => "",
        }
    }

    /// The type as printed by Go's `reflect.Type` `String` method,
    /// e.g. `*dcrjson.testCmd`, `[]string`, or `map[string]float64`.
    pub fn display(&self) -> String {
        match self {
            GoType::Named(pkg, name, _) => {
                if pkg.is_empty() {
                    name.clone()
                } else {
                    format!("{pkg}.{name}")
                }
            }
            GoType::Ptr(e) => format!("*{}", e.display()),
            GoType::Slice(e) => format!("[]{}", e.display()),
            GoType::Array(n, e) => format!("[{n}]{}", e.display()),
            GoType::Map(k, v) => format!("map[{}]{}", k.display(), v.display()),
            GoType::Struct(fields) => {
                if fields.is_empty() {
                    return "struct {}".to_string();
                }
                let body: Vec<String> = fields
                    .iter()
                    .map(|f| format!("{} {}", f.name, f.typ.display()))
                    .collect();
                format!("struct {{ {} }}", body.join("; "))
            }
            GoType::Interface => "interface {}".to_string(),
            GoType::Chan(e) => format!("chan {}", e.display()),
            GoType::Func => "func()".to_string(),
            other => other.kind().as_str().to_string(),
        }
    }

    /// The base type after indirecting through all pointers along with
    /// how many indirections were necessary (dcrd `baseType`).
    pub fn base_type(&self) -> (&GoType, usize) {
        let mut t = self;
        let mut n = 0usize;
        while let GoType::Ptr(e) = t {
            t = e;
            n = n.saturating_add(1);
        }
        (t, n)
    }

    /// The base kind after indirecting through all pointers, with one
    /// `*` prepended per indirection (dcrd `baseKindString`).
    pub fn base_kind_string(&self) -> String {
        let (base, n) = self.base_type();
        format!("{}{}", "*".repeat(n), base.kind())
    }
}

/// A Go value of some [`GoType`] (the subset of `reflect.Value`
/// dcrjson operates on).
///
/// Pointer-typed slots store the pointee value directly; [`GoValue::Null`]
/// represents a nil pointer, slice, or map.
#[derive(Clone, Debug, PartialEq)]
pub enum GoValue {
    /// A nil pointer, slice, or map.
    Null,
    /// A boolean value.
    Bool(bool),
    /// A signed integer value of any width.
    Int(i64),
    /// An unsigned integer value of any width.
    Uint(u64),
    /// A `float32` value.
    Float32(f32),
    /// A `float64` value.
    Float64(f64),
    /// A string value.
    String(String),
    /// The elements of a slice or array.
    Array(Vec<GoValue>),
    /// The entries of a map in insertion order.
    Map(Vec<(String, GoValue)>),
    /// The field values of a struct, parallel to the type's fields.
    Struct(Vec<GoValue>),
}

impl GoValue {
    /// The zero value of the given type (Go `reflect.New(...).Elem()`).
    pub fn zero(typ: &GoType) -> GoValue {
        match typ.kind() {
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => GoValue::Int(0),
            Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 => {
                GoValue::Uint(0)
            }
            Kind::Float32 => GoValue::Float32(0.0),
            Kind::Float64 => GoValue::Float64(0.0),
            Kind::Bool => GoValue::Bool(false),
            Kind::String => GoValue::String(String::new()),
            Kind::Ptr | Kind::Slice | Kind::Map => GoValue::Null,
            Kind::Array => {
                let (n, elem) = match resolve(typ) {
                    GoType::Array(n, e) => (*n, e.as_ref()),
                    _ => unreachable!(),
                };
                GoValue::Array(vec![GoValue::zero(elem); n])
            }
            Kind::Struct => {
                GoValue::Struct(typ.fields().iter().map(|f| GoValue::zero(&f.typ)).collect())
            }
            _ => GoValue::Null,
        }
    }

    /// Format the value like Go's `fmt` verb `%v` (used for default
    /// values in usage and help text).  Structs print as
    /// space-separated field values in braces, slices as
    /// space-separated elements in brackets, and maps in sorted
    /// `map[k:v ...]` form.
    pub fn go_display(&self) -> String {
        match self {
            GoValue::Null => "<nil>".to_string(),
            GoValue::Bool(b) => b.to_string(),
            GoValue::Int(i) => i.to_string(),
            GoValue::Uint(u) => u.to_string(),
            GoValue::Float32(f) => crate::gojson::format_float_g32(*f),
            GoValue::Float64(f) => crate::gojson::format_float_g(*f),
            GoValue::String(s) => s.clone(),
            GoValue::Struct(fields) => {
                let body: Vec<String> = fields.iter().map(GoValue::go_display).collect();
                format!("{{{}}}", body.join(" "))
            }
            GoValue::Array(items) => {
                let body: Vec<String> = items.iter().map(GoValue::go_display).collect();
                format!("[{}]", body.join(" "))
            }
            GoValue::Map(entries) => {
                let mut sorted: Vec<&(String, GoValue)> = entries.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                let body: Vec<String> = sorted
                    .iter()
                    .map(|(k, v)| format!("{k}:{}", v.go_display()))
                    .collect();
                format!("map[{}]", body.join(" "))
            }
        }
    }
}

/// Resolve named wrappers down to the underlying type.
pub(crate) fn resolve(typ: &GoType) -> &GoType {
    match typ {
        GoType::Named(_, _, u) => resolve(u),
        other => other,
    }
}
