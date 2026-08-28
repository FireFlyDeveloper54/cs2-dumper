use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;

use rayon::prelude::*;

use super::cpp_types;
use super::comment_text;
use super::ident::IdentifierAllocator;
use crate::analysis::{Class, ClassField, Enum, SchemaMap};

const SDK_TYPES_BODY: &str = r#"// Type-safe field accessor.
// Usage:  entity->m_iHealth().value()   // read
//         entity->m_iHealth() = 100     // write
//         entity->m_iHealth().ptr()     // get pointer
template <typename T>
class FieldRef {
    T* m_ptr;
public:
    FieldRef(void* base, ptrdiff_t offset)
        : m_ptr(reinterpret_cast<T*>(reinterpret_cast<uintptr_t>(base) + offset)) {}

    T value() const { return *m_ptr; }
    T* ptr() const { return m_ptr; }
    operator T() const { return value(); }
    FieldRef& operator=(const T& v) { *m_ptr = v; return *this; }
    T& operator*() { return *m_ptr; }
    const T& operator*() const { return *m_ptr; }
    T* operator->() { return m_ptr; }
};

// Array specialization
template <typename T, size_t N>
class FieldRef<T[N]> {
    T (*m_ptr)[N];
public:
    FieldRef(void* base, ptrdiff_t offset)
        : m_ptr(reinterpret_cast<T(*)[N]>(reinterpret_cast<uintptr_t>(base) + offset)) {}

    T& operator[](size_t i) { return (*m_ptr)[i]; }
    const T& operator[](size_t i) const { return (*m_ptr)[i]; }
    constexpr size_t size() const { return N; }
    T* begin() { return &(*m_ptr)[0]; }
    T* end() { return &(*m_ptr)[N]; }
    const T* begin() const { return &(*m_ptr)[0]; }
    const T* end() const { return &(*m_ptr)[N]; }
    T (*ptr() const)[N] { return m_ptr; }
};

namespace sdk {
template <typename T>
inline T& field_ref(void* base, std::ptrdiff_t offset) noexcept {
    return *reinterpret_cast<T*>(reinterpret_cast<std::byte*>(base) + offset);
}

template <typename T>
inline const T& field_ref(const void* base, std::ptrdiff_t offset) noexcept {
    return *reinterpret_cast<const T*>(reinterpret_cast<const std::byte*>(base) + offset);
}
}

#define SCHEMA_FIELD(TYPE, NAME, OFFSET) \
    inline TYPE& NAME() noexcept { return ::sdk::field_ref<TYPE>(this, OFFSET); } \
    inline std::add_const_t<TYPE>& NAME() const noexcept { return ::sdk::field_ref<TYPE>(this, OFFSET); }

#define SCHEMA_PAD(NAME, SIZE) std::byte NAME[(SIZE)]

template <typename T>
struct CUtlVector {
    T* m_pElements;
    int m_Size;
    int m_Capacity;
};
template <typename T>
using C_UtlVectorEmbeddedNetworkVar = CUtlVector<T>;
template <typename T>
using CUtlVectorEmbeddedNetworkVar = CUtlVector<T>;
template <typename T>
struct CNetworkUtlVectorBase {
    T* m_pElements;
    int m_Size;
};
template <typename T>
using C_NetworkUtlVectorBase = CNetworkUtlVectorBase<T>;

// Basic structs
struct Vector { float x, y, z; };
struct Vector2D { float x, y; };
struct Vector4D { float x, y, z, w; };
struct QAngle { float x, y, z; };
struct Quaternion { float x, y, z, w; };
struct CTransform { Vector m_vPosition; Quaternion m_orientation; };
struct CNetworkOriginCellCoordQuantizedVector {
    uint16_t m_cellX, m_cellY, m_cellZ, m_nOutsideWorld;
    Vector m_vecX, m_vecY, m_vecZ;
};
struct CNetworkVelocityVector { float x, y, z; };
struct CNetworkViewOffsetVector { float x, y, z; };

// CHandle - entity handle wrapper
template <typename T>
class CHandle {
public:
    uint32_t handle;
    CHandle() : handle(0) {}
    CHandle(uint32_t h) : handle(h) {}
    operator uint32_t() const { return handle; }
    operator bool() const { return handle != 0; }
    uint32_t index() const { return handle & 0x7FFF; }
    uint32_t serial() const { return handle >> 15; }
};

struct ChangeAccessorFieldPathIndex_t { uint32_t value; };

struct CEntityIdentity {
    uint8_t _pad0[0x14];
    uint32_t m_nameStringableIndex;
    const char* m_name;
    const char* m_designerName;
    uint8_t _pad28[0x8];
    uint32_t m_flags;
    uint8_t _pad34[0x4];
    int32_t m_worldGroupId;
    uint32_t m_fDataObjectTypes;
    ChangeAccessorFieldPathIndex_t m_pathIndex;
    uint8_t _pad44[0x14];
    CEntityIdentity* m_pPrev;
    CEntityIdentity* m_pNext;
    CEntityIdentity* m_pPrevByClass;
    CEntityIdentity* m_pNextByClass;
};
"#;

struct ResolvedType<'a> {
    cpp_type: Cow<'a, str>,
    is_arr: bool,
}

fn resolved_static<'a>(cpp_type: &'static str) -> ResolvedType<'a> {
    ResolvedType {
        cpp_type: Cow::Borrowed(cpp_type),
        is_arr: false,
    }
}

fn sanitize_cpp_ident(raw: &str) -> Cow<'_, str> {
    super::ident::cpp_type_ident(raw)
}

fn is_cpp_keyword(name: &str) -> bool {
    super::ident::is_cpp_keyword(name)
}

fn is_engine_vector_name(name: &str) -> bool {
    matches!(
        name,
        "Vector"
            | "Vector2D"
            | "Vector4D"
            | "QAngle"
            | "Quaternion"
            | "CTransform"
            | "CNetworkOriginCellCoordQuantizedVector"
            | "CNetworkVelocityVector"
            | "CNetworkViewOffsetVector"
    )
}

/// Types defined as POD / templates in [`SDK_TYPES_BODY`]. Schema classes with
/// the same identifier must not be forwarded or re-emitted, or `sdk_classes.hpp`
/// redefines them after `sdk_types.hpp`.
fn is_baked_sdk_type(name: &str) -> bool {
    is_engine_vector_name(name)
        || matches!(
            name,
            "CEntityIdentity" | "ChangeAccessorFieldPathIndex_t" | "CHandle" | "FieldRef"
        )
}

fn resolve_type<'a>(raw: &'a str, known_types: &HashSet<&str>) -> ResolvedType<'a> {
    let ts = raw.trim();

    if ts.ends_with('*') {
        let pointee = ts.trim_end_matches('*').trim();
        if known_types.contains(pointee) {
            return ResolvedType {
                cpp_type: Cow::Owned(format!("{}*", sanitize_cpp_ident(pointee))),
                is_arr: false,
            };
        }
        return resolved_static("uintptr_t");
    }

    if let Some((inner, dims)) = cpp_types::split_fixed_array(ts) {
        let resolved = resolve_type(inner, known_types);
        return ResolvedType {
            cpp_type: Cow::Owned(format!("{}{}", resolved.cpp_type, dims)),
            is_arr: true,
        };
    }

    if is_handle_like(ts) {
        return resolved_static("uint32_t");
    }

    if is_resource_handle_like(ts) {
        return resolved_static("uint64_t");
    }

    if let Some(resolved) = wrap_vector_like(ts, known_types) {
        return resolved;
    }

    if let Some(bits) = parse_bitfield(ts) {
        let cpp_type = match bits {
            0..=8 => "uint8_t",
            9..=16 => "uint16_t",
            17..=32 => "uint32_t",
            _ => "uint64_t",
        };
        return resolved_static(cpp_type);
    }

    if let Some(mapped) = cpp_types::map_storage(ts) {
        return resolved_static(mapped);
    }

    if is_engine_vector_name(ts) {
        return ResolvedType {
            cpp_type: Cow::Borrowed(ts),
            is_arr: false,
        };
    }

    if ts.contains(' ') {
        let stripped = ts.replace(' ', "");
        if let Some(mapped) = cpp_types::map_storage(&stripped) {
            return resolved_static(mapped);
        }
        if is_engine_vector_name(&stripped) {
            return ResolvedType {
                cpp_type: Cow::Owned(stripped),
                is_arr: false,
            };
        }
    }

    if known_types.contains(ts) {
        return ResolvedType {
            cpp_type: sanitize_cpp_ident(ts),
            is_arr: false,
        };
    }

    if let Some(pos) = ts.rfind("::") {
        let last = &ts[pos + 2..];

        return if known_types.contains(ts) || known_types.contains(last) {
            ResolvedType {
                cpp_type: sanitize_cpp_ident(ts),
                is_arr: false,
            }
        } else {
            resolved_static("uint32_t")
        };
    }

    resolved_static("uintptr_t")
}

fn is_handle_like(raw: &str) -> bool {
    raw.starts_with("CHandle<")
}

fn is_resource_handle_like(raw: &str) -> bool {
    raw.starts_with("CStrongHandle<")
        || raw.starts_with("CWeakHandle<")
        || raw.starts_with("CStrongHandleCopyable<")
}

fn template_arg<'a>(raw: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = raw.strip_prefix(prefix)?.trim_start();
    rest.strip_suffix('>').map(str::trim)
}

fn wrap_vector_like<'a>(raw: &'a str, known_types: &HashSet<&str>) -> Option<ResolvedType<'a>> {
    const PREFIXES: &[(&str, &str)] = &[
        ("CUtlVector<", "CUtlVector"),
        ("C_UtlVectorEmbeddedNetworkVar<", "C_UtlVectorEmbeddedNetworkVar"),
        ("CUtlVectorEmbeddedNetworkVar<", "CUtlVectorEmbeddedNetworkVar"),
        ("C_NetworkUtlVectorBase<", "C_NetworkUtlVectorBase"),
        ("CNetworkUtlVectorBase<", "CNetworkUtlVectorBase"),
    ];
    for (prefix, name) in PREFIXES {
        if let Some(inner) = template_arg(raw, prefix) {
            let inner_ty = resolve_type(inner, known_types);
            return Some(ResolvedType {
                cpp_type: Cow::Owned(format!("{name}<{}>", inner_ty.cpp_type)),
                is_arr: false,
            });
        }
    }
    None
}

fn parse_bitfield(raw: &str) -> Option<u32> {
    raw.strip_prefix("bitfield:")?.parse::<u32>().ok()
}

pub fn write_sdk_types(classes: &[(&str, &Class)], build_number: Option<u32>) -> String {
    let mut out =
        String::with_capacity(classes.len().saturating_mul(32) + SDK_TYPES_BODY.len() + 512);
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Auto-generated by cs2-dumper (SDK mode).");
    let _ = writeln!(out, "// DO NOT EDIT MANUALLY.");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include <cstdint>");
    let _ = writeln!(out, "#include <cstddef>");
    let _ = writeln!(out, "#include <type_traits>");
    let _ = writeln!(
        out,
        "\nnamespace sdk {{ inline constexpr std::uint32_t CS2_BUILD = {}; }}",
        build_number.unwrap_or(0)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "// Forward declarations");

    for (_, class) in classes {
        if is_baked_sdk_type(&class.name) {
            continue;
        }
        let _ = writeln!(out, "class {};", sanitize_cpp_ident(&class.name));
    }

    let _ = writeln!(out);
    out.push_str(SDK_TYPES_BODY);

    if !out.ends_with('\n') {
        out.push('\n');
    }

    out
}

fn enum_value_masked(value: i64, type_name: &str) -> u64 {
    cpp_types::enum_value_masked(value, type_name)
}

fn enum_value_literal(value: i64, type_name: &str) -> String {
    format!("{:#X}", enum_value_masked(value, type_name))
}

fn render_sdk_enum(module_name: &str, enum_: &Enum, enum_ident: &str) -> String {
    let mut out = String::with_capacity(96 + enum_.members.len() * 40);
    let type_name = cpp_types::enum_underlying(enum_.storage_bytes());
    let _ = writeln!(out, "// Module: {}", comment_text(module_name));
    let _ = writeln!(
        out,
        "enum class {} : {} {{",
        enum_ident, type_name
    );

    let mut names = IdentifierAllocator::default();
    for member in &enum_.members {
        let _ = writeln!(
            out,
            "    {} = {},",
            names.allocate(sanitize_cpp_ident(&member.name).into_owned()),
            enum_value_literal(member.value, type_name)
        );
    }

    let _ = writeln!(out, "}};");
    let _ = writeln!(out);
    out
}

pub fn write_sdk_enums(enums: &[(&str, &Enum)]) -> String {
    let mut out = String::with_capacity(enums.len().saturating_mul(128) + 256);
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Auto-generated by cs2-dumper (SDK mode).");
    let _ = writeln!(out, "// DO NOT EDIT MANUALLY.");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include <cstdint>");
    let _ = writeln!(out);

    let mut enum_alloc = IdentifierAllocator::default();
    let named: Vec<(&str, &Enum, String)> = enums
        .iter()
        .map(|(module_name, enum_)| {
            (
                *module_name,
                *enum_,
                enum_alloc.allocate(sanitize_cpp_ident(&enum_.name).into_owned()),
            )
        })
        .collect();
    let bodies: Vec<String> = named
        .par_iter()
        .map(|(module_name, enum_, ident)| render_sdk_enum(module_name, enum_, ident))
        .collect();
    append_chunks(&mut out, bodies);
    out
}

fn append_chunks(out: &mut String, chunks: Vec<String>) {
    let extra: usize = chunks.iter().map(String::len).sum();
    out.reserve(extra);
    for chunk in chunks {
        out.push_str(&chunk);
    }
}

pub fn write_sdk_classes(classes: &[(&str, &Class)], enums: &[(&str, &Enum)]) -> String {
    let mut out = String::with_capacity(classes.len().saturating_mul(256) + 512);
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Auto-generated by cs2-dumper (SDK mode).");
    let _ = writeln!(out, "// DO NOT EDIT MANUALLY.");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include \"sdk_types.hpp\"");
    let _ = writeln!(out, "#include \"sdk_enums.hpp\"");
    let _ = writeln!(out);

    let mut known_types: HashSet<&str> = classes
        .iter()
        .map(|(_, class)| class.name.as_str())
        .chain(enums.iter().map(|(_, enum_)| enum_.name.as_str()))
        .collect();
    known_types.extend([
        "Vector",
        "Vector2D",
        "Vector4D",
        "QAngle",
        "Quaternion",
        "CTransform",
        "CNetworkOriginCellCoordQuantizedVector",
        "CNetworkVelocityVector",
        "CNetworkViewOffsetVector",
        "CEntityIdentity",
        "ChangeAccessorFieldPathIndex_t",
        "CHandle",
        "FieldRef",
    ]);

    let class_map: BTreeMap<&str, &Class> = classes
        .iter()
        .map(|(_, class)| (class.name.as_str(), *class))
        .collect();

    let mut ordered = Vec::new();
    let mut state: HashMap<&str, u8> = HashMap::new();

    fn visit<'a>(
        name: &'a str,
        class_map: &BTreeMap<&'a str, &'a Class>,
        state: &mut HashMap<&'a str, u8>,
        ordered: &mut Vec<&'a str>,
    ) {
        if let Some(status) = state.get(name).copied()
            && (status == 1 || status == 2)
        {
            return;
        }

        state.insert(name, 1);

        if let Some(class) = class_map.get(name)
            && let Some(parent) = class.parent_name.as_deref()
            && class_map.contains_key(parent)
        {
            visit(parent, class_map, state, ordered);
        }

        state.insert(name, 2);
        ordered.push(name);
    }

    for (_, class) in classes {
        visit(class.name.as_str(), &class_map, &mut state, &mut ordered);
    }

    let mut missing_parents = BTreeSet::new();
    for (_, class) in classes {
        if is_baked_sdk_type(&class.name) {
            continue;
        }
        let Some(parent) = class.parent_name.as_deref() else {
            continue;
        };
        if known_types.contains(parent) || is_baked_sdk_type(parent) {
            continue;
        }
        let ident = sanitize_cpp_ident(parent);
        if known_types.contains(ident.as_ref()) || is_baked_sdk_type(ident.as_ref()) {
            continue;
        }
        missing_parents.insert(ident.into_owned());
    }

    let mut class_idents: HashMap<&str, String> = HashMap::new();
    let mut class_alloc = IdentifierAllocator::default();
    for name in &ordered {
        if is_baked_sdk_type(name) {
            continue;
        }
        class_idents.insert(
            *name,
            class_alloc.allocate(sanitize_cpp_ident(&class_map[name].name).into_owned()),
        );
    }

    if !missing_parents.is_empty() {
        let _ = writeln!(
            out,
            "// missing schema bindings — empty stubs so inheritance compiles"
        );
        for parent in &missing_parents {
            let _ = writeln!(out, "class {parent} {{}};");
        }
        let _ = writeln!(out);
    }

    let bodies: Vec<String> = ordered
        .par_iter()
        .filter(|name| !is_baked_sdk_type(name))
        .map(|name| render_sdk_class(class_map[name], &known_types, &class_idents))
        .collect();
    append_chunks(&mut out, bodies);
    out
}

fn fields_sorted_by_offset(fields: &[ClassField]) -> bool {
    fields
        .windows(2)
        .all(|pair| pair[0].offset <= pair[1].offset)
}

fn emit_sdk_fields<'a>(
    out: &mut String,
    fields: impl IntoIterator<Item = &'a ClassField>,
    known_types: &HashSet<&str>,
) {
    let mut seen = HashSet::new();
    let mut names = IdentifierAllocator::default();
    for field in fields {
        if !seen.insert(field.name.as_str()) {
            continue;
        }
        let resolved = resolve_type(&field.type_name, known_types);
        let field_name = names.allocate(sanitize_cpp_ident(&field.name).into_owned());
        if resolved.is_arr {
            let _ = writeln!(
                out,
                "    FieldRef<{}> {}() {{ return {{this, {:#X}}}; }}",
                resolved.cpp_type, field_name, field.offset
            );
        } else {
            let _ = writeln!(
                out,
                "    SCHEMA_FIELD({}, {}, {:#X})",
                resolved.cpp_type, field_name, field.offset
            );
        }
    }
}

fn render_sdk_class(
    class: &Class,
    known_types: &HashSet<&str>,
    class_idents: &HashMap<&str, String>,
) -> String {
    let mut out = String::with_capacity(96 + class.fields.len() * 80);
    let class_name = class_idents
        .get(class.name.as_str())
        .cloned()
        .unwrap_or_else(|| sanitize_cpp_ident(&class.name).into_owned());
    let parent = class.parent_name.as_deref();

    if let Some(parent) = parent {
        let parent_ident = class_idents
            .get(parent)
            .cloned()
            .unwrap_or_else(|| sanitize_cpp_ident(parent).into_owned());
        let _ = writeln!(
            out,
            "class {} : public {} {{",
            class_name, parent_ident
        );
    } else {
        let _ = writeln!(out, "class {} {{", class_name);
    }
    let _ = writeln!(out, "public:");

    if fields_sorted_by_offset(&class.fields) {
        emit_sdk_fields(&mut out, class.fields.iter(), known_types);
    } else {
        let mut fields = class.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|field| field.offset);
        emit_sdk_fields(&mut out, fields, known_types);
    }
    let _ = writeln!(out, "}};");
    let _ = writeln!(out);
    out
}

pub fn write_sdk_umbrella() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "// SDK umbrella header - auto-generated by cs2-dumper."
    );
    let _ = writeln!(out, "// Include this in your code:  #include <sdk/sdk.hpp>");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include \"sdk_types.hpp\"");
    let _ = writeln!(out, "#include \"sdk_enums.hpp\"");
    let _ = writeln!(out, "#include \"sdk_classes.hpp\"");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Also provide flat offsets for convenience.");
    let _ = writeln!(out, "#include <offsets.hpp>");
    let _ = writeln!(out, "#include <buttons.hpp>");
    let _ = writeln!(out, "#include <interfaces.hpp>");
    let _ = writeln!(out, "#include <client_dll.hpp>");

    out
}

pub type SdkEnums<'a> = Vec<(&'a str, &'a Enum)>;
pub type SdkClasses<'a> = Vec<(&'a str, &'a Class)>;

pub fn collect_sdk_data(schemas: &SchemaMap) -> (SdkEnums<'_>, SdkClasses<'_>) {
    let mut enums: BTreeMap<&str, (&str, &Enum)> = BTreeMap::new();
    let mut classes: BTreeMap<&str, (&str, &Class)> = BTreeMap::new();

    let mut module_names: Vec<&str> = schemas.keys().map(String::as_str).collect();
    module_names.sort_by(|a, b| {
        let a_key = (
            if a.eq_ignore_ascii_case("client.dll") {
                0
            } else {
                1
            },
            *a,
        );
        let b_key = (
            if b.eq_ignore_ascii_case("client.dll") {
                0
            } else {
                1
            },
            *b,
        );
        a_key.cmp(&b_key)
    });

    for module_name in module_names {
        let Some((module_classes, module_enums)) = schemas.get(module_name) else {
            continue;
        };

        for enum_ in module_enums {
            enums
                .entry(enum_.name.as_str())
                .or_insert((module_name, enum_));
        }

        for class in module_classes {
            classes
                .entry(class.name.as_str())
                .or_insert((module_name, class));
        }
    }

    (
        enums.into_values().collect(),
        classes.into_values().collect(),
    )
}

fn module_slug(input: &str) -> Cow<'_, str> {
    if let Some(stem) = input.strip_suffix(".dll")
        && super::ident::already_ascii_ident(stem)
        && !stem.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
        && !is_cpp_keyword(stem)
    {
        return Cow::Borrowed(stem);
    }
    if super::ident::already_ascii_ident(input)
        && !input.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
        && !input.ends_with("_dll")
        && !is_cpp_keyword(input)
    {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.ends_with("_dll") {
        out.truncate(out.len() - 4);
    }
    if out.is_empty() {
        Cow::Borrowed("module")
    } else {
        if out.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) || is_cpp_keyword(&out) {
            out.insert(0, '_');
        }
        Cow::Owned(out)
    }
}

fn write_module_header(
    module: &str,
    module_ident: &str,
    classes: &[Class],
    enums: &[Enum],
) -> String {
    let field_count: usize = classes.iter().map(|class| class.fields.len()).sum();
    let mut out =
        String::with_capacity(256 + classes.len() * 96 + enums.len() * 128 + field_count * 64);
    let _ = writeln!(
        out,
        "#pragma once\n#include <cstddef>\n#include <cstdint>\n"
    );
    let _ = writeln!(
        out,
        "// Auto-generated per-schema-scope offsets for {}.",
        comment_text(module)
    );
    let _ = writeln!(
        out,
        "namespace offsets {{ namespace {} {{",
        module_ident
    );
    let mut declarations = IdentifierAllocator::default();
    for enum_ in enums {
        let underlying = cpp_types::enum_underlying(enum_.storage_bytes());
        let enum_name = declarations.allocate(sanitize_cpp_ident(&enum_.name).into_owned());
        let _ = writeln!(
            out,
            "enum class {} : {} {{",
            enum_name,
            underlying
        );
        let mut names = IdentifierAllocator::default();
        for member in &enum_.members {
            let _ = writeln!(
                out,
                "    {} = 0x{:X},",
                names.allocate(sanitize_cpp_ident(&member.name).into_owned()),
                enum_value_masked(member.value, underlying)
            );
        }
        let _ = writeln!(out, "}};\n");
    }
    for class in classes {
        let class_name = declarations.allocate(sanitize_cpp_ident(&class.name).into_owned());
        let _ = writeln!(out, "namespace {class_name} {{");
        let _ = writeln!(
            out,
            "inline constexpr std::size_t kSize = 0x{:X};",
            class.size.max(0)
        );
        let _ = writeln!(
            out,
            "inline constexpr std::size_t kAlignment = {};",
            class.alignment
        );
        let mut names = IdentifierAllocator::default();
        for field in &class.fields {
            let _ = writeln!(
                out,
                "inline constexpr std::ptrdiff_t {} = 0x{:X}; // {}",
                names.allocate(sanitize_cpp_ident(&field.name).into_owned()),
                field.offset,
                comment_text(&field.type_name)
            );
        }
        let _ = writeln!(out, "}}\n");
    }
    let _ = writeln!(out, "}} }}");
    out
}

fn write_class_header(module_ident: &str, class_ident: &str, class: &Class) -> String {
    let mut out = String::with_capacity(160 + class.fields.len() * 64 + class.flags.len() * 32);
    let _ = writeln!(out, "#pragma once\n#include <cstddef>\n");
    let _ = writeln!(
        out,
        "// Auto-generated schema offsets for {}.",
        comment_text(&class.name)
    );
    for flag in &class.flags {
        let _ = writeln!(out, "// {}", comment_text(flag));
    }
    let _ = writeln!(
        out,
        "namespace offsets {{ namespace {} {{ namespace {} {{",
        module_ident,
        class_ident
    );
    let _ = writeln!(
        out,
        "inline constexpr std::size_t kSize = 0x{:X};",
        class.size.max(0)
    );
    let _ = writeln!(
        out,
        "inline constexpr std::size_t kAlignment = {};",
        class.alignment
    );
    let mut names = IdentifierAllocator::default();
    for field in &class.fields {
        let _ = writeln!(
            out,
            "inline constexpr std::ptrdiff_t {} = 0x{:X}; // {}",
            names.allocate(sanitize_cpp_ident(&field.name).into_owned()),
            field.offset,
            comment_text(&field.type_name)
        );
    }
    let _ = writeln!(out, "}} }} }}");
    out
}

pub fn dump_module_headers(out_dir: &std::path::Path, schemas: &SchemaMap) -> std::io::Result<()> {
    let modules_dir = out_dir.join("sdk").join("modules");
    std::fs::create_dir_all(&modules_dir)?;
    let classes_dir = out_dir.join("sdk").join("classes");
    std::fs::create_dir_all(&classes_dir)?;
    let mut umbrella = String::from("#pragma once\n\n");
    let mut module_jobs = Vec::with_capacity(schemas.len());
    let mut class_files = Vec::new();
    let mut module_names = IdentifierAllocator::default();
    for (module, (classes, enums)) in schemas {
        let slug = module_names.allocate(module_slug(module).into_owned());
        let module_classes_dir = classes_dir.join(&slug);
        std::fs::create_dir_all(&module_classes_dir)?;
        let mut declarations = IdentifierAllocator::default();
        for enum_ in enums {
            declarations.allocate(sanitize_cpp_ident(&enum_.name).into_owned());
        }
        class_files.extend(classes.iter().map(|class| {
            let class_ident =
                declarations.allocate(sanitize_cpp_ident(&class.name).into_owned());
            let mut path = module_classes_dir.join(&class_ident);
            path.set_extension("hpp");
            (path, slug.clone(), class_ident, class)
        }));
        let _ = writeln!(umbrella, "#include \"modules/{}.hpp\"", slug);
        module_jobs.push((module.as_str(), classes.as_slice(), enums.as_slice(), slug));
    }
    let (module_res, class_res) = rayon::join(
        || {
            module_jobs
                .par_iter()
                .try_for_each(|(module, classes, enums, slug)| {
                    let mut path = modules_dir.join(slug);
                    path.set_extension("hpp");
                    std::fs::write(path, write_module_header(module, slug, classes, enums))
                })
        },
        || {
            class_files
                .par_iter()
                .try_for_each(|(path, module_ident, class_ident, class)| {
                    std::fs::write(path, write_class_header(module_ident, class_ident, class))
                })
        },
    );
    module_res?;
    class_res?;
    std::fs::write(out_dir.join("sdk").join("modules.hpp"), umbrella)?;
    Ok(())
}
pub fn dump_sdk(
    out_dir: &std::path::Path,
    schemas: &SchemaMap,
    build_number: Option<u32>,
) -> std::io::Result<()> {
    let sdk_dir = out_dir.join("sdk");
    std::fs::create_dir_all(&sdk_dir)?;

    let (enums, classes) = collect_sdk_data(schemas);

    let ((((types_body, enums_body), classes_body), umbrella), headers_res) = rayon::join(
        || {
            let bodies = rayon::join(
                || {
                    rayon::join(
                        || write_sdk_types(&classes, build_number),
                        || write_sdk_enums(&enums),
                    )
                },
                || write_sdk_classes(&classes, &enums),
            );
            (bodies, write_sdk_umbrella())
        },
        || dump_module_headers(out_dir, schemas),
    );

    [
        (sdk_dir.join("sdk_types.hpp"), types_body),
        (sdk_dir.join("sdk_enums.hpp"), enums_body),
        (sdk_dir.join("sdk_classes.hpp"), classes_body),
        (sdk_dir.join("sdk.hpp"), umbrella),
    ]
    .into_par_iter()
    .try_for_each(|(path, body)| std::fs::write(path, body))?;

    let emitted_classes = classes
        .iter()
        .filter(|(_, class)| !is_baked_sdk_type(&class.name))
        .count();
    println!("  sdk/sdk_types.hpp");
    println!("  sdk/sdk_enums.hpp     {} enums", enums.len());
    println!("  sdk/sdk_classes.hpp   {} classes", emitted_classes);
    headers_res?;
    println!("  sdk/modules.hpp       per-scope class/enum offsets");
    println!("  sdk/sdk.hpp           umbrella header");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{ClassField, EnumMember};
    use std::borrow::Cow;
    use std::process::Command;

    #[test]
    fn sanitizes_nested_cpp_names_without_changing_normal_names() {
        assert_eq!(
            sanitize_cpp_ident("CCSPlayerPawn").as_ref(),
            "CCSPlayerPawn"
        );
        assert_eq!(
            sanitize_cpp_ident("CPulseCell::TimelineEvent_t").as_ref(),
            "CPulseCell_TimelineEvent_t"
        );
        assert_eq!(sanitize_cpp_ident("3d_type").as_ref(), "_3d_type");
        assert_eq!(sanitize_cpp_ident("operator").as_ref(), "_operator");
    }

    #[test]
    fn sanitize_cpp_ident_borrows_clean_names() {
        let name = "CCSPlayerPawn";
        let out = sanitize_cpp_ident(name);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
    }

    #[test]
    fn module_slug_borrows_dll_stem() {
        let module = "client.dll";
        let slug = module_slug(module);
        assert_eq!(slug.as_ref(), "client");
        assert!(matches!(slug, Cow::Borrowed(_)));
        assert!(std::ptr::eq(slug.as_ref().as_ptr(), module.as_ptr()));
        assert_eq!(module_slug("engine2.dll").as_ref(), "engine2");
        assert_eq!(module_slug("client_dll").as_ref(), "client");
        assert_eq!(module_slug("namespace.dll").as_ref(), "_namespace");
        assert_eq!(module_slug("3d.dll").as_ref(), "_3d");
        assert_eq!(module_slug(".dll").as_ref(), "module");
    }

    #[test]
    fn module_headers_keep_schema_comments_on_one_line() {
        let class = Class {
            name: "C_Test\n#define CLASS_INJECTED 1".to_string(),
            module_name: "namespace.dll\n#define MODULE_INJECTED 1".into(),
            parent_name: None,
            size: 0x20,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![ClassField {
                name: "m_value".to_string(),
                type_name: "int32\n#define TYPE_INJECTED 1".to_string(),
                offset: 0x10,
                metadata: Vec::new(),
            }],
            static_fields: Vec::new(),
            flags: vec!["MNetworkVarNames\n#define FLAG_INJECTED 1".to_string()],
        };

        let module_body = write_module_header(
            &class.module_name,
            "_namespace",
            std::slice::from_ref(&class),
            &[],
        );
        let class_body = write_class_header("_namespace", "C_Test", &class);
        for body in [&module_body, &class_body] {
            assert!(!body.contains("\n#define"), "schema text escaped a comment: {body}");
        }
    }

    #[test]
    fn dump_module_headers_writes_every_class_file() {
        fn dummy(name: &str, module: &str) -> Class {
            Class {
                name: name.to_string(),
                module_name: module.into(),
                parent_name: None,
                size: 0x20,
                alignment: 8,
                metadata: Vec::new(),
                fields: Vec::new(),
                static_fields: Vec::new(),
                flags: Vec::new(),
            }
        }

        let client: Vec<Class> = (0..16)
            .map(|i| dummy(&format!("C_Client{i}"), "client.dll"))
            .collect();
        let server: Vec<Class> = (0..8)
            .map(|i| dummy(&format!("C_Server{i}"), "server.dll"))
            .collect();
        let schemas = SchemaMap::from([
            ("client.dll".to_string(), (client, Vec::new())),
            ("server.dll".to_string(), (server, Vec::new())),
        ]);
        let root =
            std::env::temp_dir().join(format!("cs2-dumper-sdk-classes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        dump_sdk(&root, &schemas, Some(1)).expect("write sdk");
        for i in 0..16 {
            assert!(
                root.join("sdk/classes/client")
                    .join(format!("C_Client{i}.hpp"))
                    .is_file(),
                "missing client class {i}"
            );
        }
        for i in 0..8 {
            assert!(
                root.join("sdk/classes/server")
                    .join(format!("C_Server{i}.hpp"))
                    .is_file(),
                "missing server class {i}"
            );
        }
        assert!(root.join("sdk/modules.hpp").is_file());
        assert!(root.join("sdk/modules/client.hpp").is_file());
        assert!(root.join("sdk/modules/server.hpp").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dump_module_headers_disambiguates_module_and_class_paths() {
        let class = |name: &str, module: &str| Class {
            name: name.to_string(),
            module_name: module.into(),
            parent_name: None,
            size: 0x10,
            alignment: 4,
            metadata: Vec::new(),
            fields: Vec::new(),
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let enum_ = Enum {
            name: "same-name".into(),
            alignment: 4,
            size: 4,
            members: Vec::new(),
            flags: Vec::new(),
        };
        let schemas = SchemaMap::from([
            (
                "foo-bar.dll".to_string(),
                (
                    vec![
                        class("same_name", "foo-bar.dll"),
                        class("C-Test", "foo-bar.dll"),
                        class("C_Test", "foo-bar.dll"),
                    ],
                    vec![enum_],
                ),
            ),
            ("foo_bar.dll".to_string(), (Vec::new(), Vec::new())),
        ]);
        let root = std::env::temp_dir().join(format!(
            "cs2-dumper-sdk-path-collisions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        dump_module_headers(&root, &schemas).expect("write module headers");

        let classes = root.join("sdk/classes/foo_bar");
        assert!(classes.join("same_name_2.hpp").is_file());
        assert!(classes.join("C_Test.hpp").is_file());
        assert!(classes.join("C_Test_2.hpp").is_file());
        assert!(root.join("sdk/modules/foo_bar.hpp").is_file());
        assert!(root.join("sdk/modules/foo_bar_2.hpp").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_sdk_data_prefers_client_and_borrows_schema_entries() {
        fn dummy(name: &str, module: &str, size: i32) -> Class {
            Class {
                name: name.to_string(),
                module_name: module.into(),
                parent_name: None,
                size,
                alignment: 8,
                metadata: Vec::new(),
                fields: Vec::new(),
                static_fields: Vec::new(),
                flags: Vec::new(),
            }
        }

        let schemas = SchemaMap::from([
            (
                "server.dll".to_string(),
                (vec![dummy("C_Shared", "server.dll", 0x99)], Vec::new()),
            ),
            (
                "client.dll".to_string(),
                (vec![dummy("C_Shared", "client.dll", 0x10)], Vec::new()),
            ),
        ]);
        let client = &schemas["client.dll"].0[0];
        let (enums, classes) = collect_sdk_data(&schemas);
        assert!(enums.is_empty());
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].0, "client.dll");
        assert_eq!(classes[0].1.size, 0x10);
        assert!(
            std::ptr::eq(classes[0].1, client),
            "collect_sdk_data must borrow the schema class, not clone it"
        );
    }

    #[test]
    fn collect_sdk_data_prefers_client_when_module_case_differs() {
        fn dummy(name: &str, module: &str, size: i32) -> Class {
            Class {
                name: name.to_string(),
                module_name: module.into(),
                parent_name: None,
                size,
                alignment: 8,
                metadata: Vec::new(),
                fields: Vec::new(),
                static_fields: Vec::new(),
                flags: Vec::new(),
            }
        }

        let schemas = SchemaMap::from([
            (
                "server.dll".to_string(),
                (vec![dummy("C_Shared", "server.dll", 0x99)], Vec::new()),
            ),
            (
                "CLIENT.DLL".to_string(),
                (vec![dummy("C_Shared", "CLIENT.DLL", 0x10)], Vec::new()),
            ),
        ]);
        let (enums, classes) = collect_sdk_data(&schemas);
        assert!(enums.is_empty());
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].0, "CLIENT.DLL");
        assert_eq!(classes[0].1.size, 0x10);
    }

    #[test]
    fn baked_engine_types_are_not_redefined_as_schema_classes() {
        fn dummy(name: &str, fields: Vec<ClassField>) -> Class {
            Class {
                name: name.to_string(),
                module_name: "client.dll".into(),
                parent_name: None,
                size: 0x28,
                alignment: 8,
                metadata: Vec::new(),
                fields,
                static_fields: Vec::new(),
                flags: Vec::new(),
            }
        }
        let field = |name: &str, ty: &str, offset: i32| ClassField {
            name: name.to_string(),
            type_name: ty.to_string(),
            offset,
            metadata: Vec::new(),
        };
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![
                    dummy(
                        "Vector",
                        vec![field("x", "float32", 0), field("y", "float32", 4)],
                    ),
                    dummy(
                        "CEntityIdentity",
                        vec![field("m_designerName", "CUtlSymbolLarge", 0x20)],
                    ),
                    dummy(
                        "C_CSPlayerPawn",
                        vec![field("m_vecOrigin", "Vector", 0x10)],
                    ),
                ],
                Vec::new(),
            ),
        )]);
        let root = std::env::temp_dir().join(format!(
            "cs2-dumper-sdk-baked-types-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        dump_sdk(&root, &schemas, Some(1)).expect("write sdk");
        let types = std::fs::read_to_string(root.join("sdk/sdk_types.hpp")).unwrap();
        let classes = std::fs::read_to_string(root.join("sdk/sdk_classes.hpp")).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert!(types.contains("struct Vector"));
        assert!(types.contains("struct CEntityIdentity"));
        assert!(
            !types.lines().any(|line| line.trim() == "class Vector;"),
            "baked Vector must not be forwarded as a class: {types}"
        );
        assert!(
            !types
                .lines()
                .any(|line| line.trim() == "class CEntityIdentity;"),
            "baked CEntityIdentity must not be forwarded as a class: {types}"
        );
        assert!(
            !classes.contains("class Vector"),
            "schema Vector must not redefine the baked POD: {classes}"
        );
        assert!(
            !classes.contains("class CEntityIdentity"),
            "schema CEntityIdentity must not redefine the baked POD: {classes}"
        );
        assert!(classes.contains("class C_CSPlayerPawn"));
        assert!(
            classes.contains("SCHEMA_FIELD(Vector, m_vecOrigin, 0x10)"),
            "pawn origin must keep the baked Vector type: {classes}"
        );
    }

    #[test]
    fn sdk_class_emits_fieldref_for_fixed_arrays() {
        let class = Class {
            name: "C_WithArray".to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0xA0,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![
                ClassField {
                    name: "m_name".to_string(),
                    type_name: "char[128]".to_string(),
                    offset: 0,
                    metadata: Vec::new(),
                },
                ClassField {
                    name: "m_cells".to_string(),
                    type_name: "int32[2][3]".to_string(),
                    offset: 0x80,
                    metadata: Vec::new(),
                },
            ],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let body = render_sdk_class(&class, &HashSet::new(), &HashMap::new());
        assert!(
            body.contains("FieldRef<char[128]> m_name()"),
            "char[128] must stay a FieldRef array: {body}"
        );
        assert!(
            body.contains("FieldRef<int32_t[2][3]> m_cells()"),
            "int32[2][3] must keep both ranks: {body}"
        );
        assert!(
            !body.contains("FieldRef<char[128][128]>"),
            "must not double-wrap the array rank: {body}"
        );
    }

    #[test]
    fn sdk_classes_stub_missing_parent_types() {
        let derived = Class {
            name: "C_Derived".to_string(),
            module_name: "client.dll".into(),
            parent_name: Some("CMissingBase".to_string()),
            size: 8,
            alignment: 8,
            metadata: Vec::new(),
            fields: Vec::new(),
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let schemas =
            SchemaMap::from([("client.dll".to_string(), (vec![derived], Vec::new()))]);
        let (enums, classes) = collect_sdk_data(&schemas);
        let body = write_sdk_classes(&classes, &enums);
        assert!(
            body.contains("class CMissingBase {};"),
            "missing parent must be stubbed: {body}"
        );
        assert!(
            body.contains("class C_Derived : public CMissingBase"),
            "derived must inherit the stub: {body}"
        );
    }

    #[test]
    fn sdk_classes_disambiguate_sanitized_type_names() {
        fn dummy(name: &str) -> Class {
            Class {
                name: name.to_string(),
                module_name: "client.dll".into(),
                parent_name: None,
                size: 4,
                alignment: 4,
                metadata: Vec::new(),
                fields: Vec::new(),
                static_fields: Vec::new(),
                flags: Vec::new(),
            }
        }
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (vec![dummy("C-Test"), dummy("C_Test")], Vec::new()),
        )]);
        let (enums, classes) = collect_sdk_data(&schemas);
        let body = write_sdk_classes(&classes, &enums);
        assert!(body.contains("class C_Test {"), "first ident: {body}");
        assert!(
            body.contains("class C_Test_2 {"),
            "colliding ident must be allocated: {body}"
        );
    }

    #[test]
    fn baked_transform_matches_include_tree_layout() {
        let types = write_sdk_types(&[], None);
        assert!(types.contains("struct Quaternion { float x, y, z, w; }"));
        assert!(types.contains("Vector m_vPosition"));
        assert!(types.contains("Quaternion m_orientation"));
        assert!(types.contains("uint16_t m_cellX"));
        assert!(!types.contains("Vector pos; QAngle rot"));
    }

    #[test]
    fn sdk_class_emits_fields_lowest_offset_first() {
        let class = Class {
            name: "C_OutOfOrder".to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0x28,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![
                ClassField {
                    name: "late".to_string(),
                    type_name: "int32".to_string(),
                    offset: 0x20,
                    metadata: Vec::new(),
                },
                ClassField {
                    name: "early".to_string(),
                    type_name: "int32".to_string(),
                    offset: 0x8,
                    metadata: Vec::new(),
                },
            ],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let body = render_sdk_class(&class, &HashSet::new(), &HashMap::new());
        let early = body.find("early").expect("early field");
        let late = body.find("late").expect("late field");
        assert!(
            early < late,
            "fields must be emitted in offset order: {body}"
        );
        assert!(fields_sorted_by_offset(&[
            ClassField {
                name: "a".into(),
                type_name: "int32".into(),
                offset: 0,
                metadata: Vec::new(),
            },
            ClassField {
                name: "b".into(),
                type_name: "int32".into(),
                offset: 4,
                metadata: Vec::new(),
            },
        ]));
        assert!(!fields_sorted_by_offset(&class.fields));
    }

    #[test]
    fn preserves_known_schema_pointer_types() {
        let known = HashSet::from(["C_BaseEntity", "SomeEnum"]);
        let resolved = resolve_type("C_BaseEntity*", &known);
        assert_eq!(resolved.cpp_type, "C_BaseEntity*");
        let nested = resolve_type("C_BaseEntity[2]", &known);
        assert_eq!(nested.cpp_type, "C_BaseEntity[2]");
        assert!(nested.is_arr);
        assert_eq!(
            resolve_type("int32[2][3]", &known).cpp_type,
            "int32_t[2][3]"
        );
        assert_eq!(resolve_type("Vector", &known).cpp_type, "Vector");
    }

    #[test]
    fn resource_handles_are_eight_bytes_entity_handles_are_four() {
        let known = HashSet::new();
        assert_eq!(resolve_type("CHandle< C_BaseEntity >", &known).cpp_type, "uint32_t");
        assert_eq!(
            resolve_type("CStrongHandle< InfoForResourceTypeCModel >", &known).cpp_type,
            "uint64_t"
        );
        assert_eq!(
            resolve_type("CWeakHandle< InfoForResourceTypeCTextureBase >", &known).cpp_type,
            "uint64_t"
        );
        assert_eq!(resolve_type("CStrongHandle", &known).cpp_type, "uint64_t");
    }

    #[test]
    fn utl_vectors_keep_container_layout_not_a_single_pointer() {
        let known = HashSet::from(["C_BaseEntity"]);
        assert_eq!(
            resolve_type("CUtlVector< Vector >", &known).cpp_type,
            "CUtlVector<Vector>"
        );
        assert_eq!(
            resolve_type("CUtlVector< C_BaseEntity >", &known).cpp_type,
            "CUtlVector<C_BaseEntity>"
        );
        assert_eq!(
            resolve_type("C_NetworkUtlVectorBase< int32 >", &known).cpp_type,
            "C_NetworkUtlVectorBase<int32_t>"
        );
        assert_ne!(
            resolve_type("CUtlVector< Vector >", &known).cpp_type,
            "uintptr_t"
        );
    }

    #[test]
    fn preserves_enum_values_at_signed_and_unsigned_boundaries() {
        assert_eq!(enum_value_literal(-1, "uint8_t"), "0xFF");
        assert_eq!(enum_value_literal(-2, "uint16_t"), "0xFFFE");
        assert_eq!(
            enum_value_literal(i32::MAX as i64 + 1, "uint32_t"),
            "0x80000000"
        );
        assert_eq!(enum_value_literal(-1, "uint64_t"), "0xFFFFFFFFFFFFFFFF");
    }

    #[test]
    fn synthetic_sdk_headers_compile_when_gplusplus_is_available() {
        if Command::new("g++").arg("--version").output().is_err() {
            return;
        }

        let root =
            std::env::temp_dir().join(format!("cs2-dumper-sdk-smoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let identity = Class {
            name: "CEntityIdentity".to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0x70,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![ClassField {
                name: "m_designerName".to_string(),
                type_name: "CUtlSymbolLarge".to_string(),
                offset: 0x20,
                metadata: Vec::new(),
            }],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let vector = Class {
            name: "Vector".to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0xC,
            alignment: 4,
            metadata: Vec::new(),
            fields: vec![ClassField {
                name: "x".to_string(),
                type_name: "float32".to_string(),
                offset: 0,
                metadata: Vec::new(),
            }],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let base = Class {
            name: "C_BaseEntity".to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0x20,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![ClassField {
                name: "m_vecOrigin".to_string(),
                type_name: "Vector".to_string(),
                offset: 0x10,
                metadata: Vec::new(),
            }],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let derived = Class {
            name: "C_TestEntity".to_string(),
            module_name: "client.dll".into(),
            parent_name: Some("C_BaseEntity".to_string()),
            size: 0x28,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![
                ClassField {
                    name: "m_hOwner".to_string(),
                    type_name: "C_BaseEntity*".to_string(),
                    offset: 0x20,
                    metadata: Vec::new(),
                },
                ClassField {
                    name: "m_vecWeapons".to_string(),
                    type_name: "CUtlVector< C_BaseEntity >".to_string(),
                    offset: 0x28,
                    metadata: Vec::new(),
                },
            ],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let orphan = Class {
            name: "C_Orphan".to_string(),
            module_name: "client.dll".into(),
            parent_name: Some("CMissingBase".to_string()),
            size: 0x18,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![
                ClassField {
                    name: "m_name".to_string(),
                    type_name: "char[8]".to_string(),
                    offset: 0,
                    metadata: Vec::new(),
                },
                ClassField {
                    name: "m_cells".to_string(),
                    type_name: "int32[2][2]".to_string(),
                    offset: 8,
                    metadata: Vec::new(),
                },
            ],
            static_fields: Vec::new(),
            flags: Vec::new(),
        };
        let enum_ = Enum {
            name: "TestMode".to_string(),
            alignment: 4,
            size: 4,
            members: vec![EnumMember {
                name: "Mode_Invalid".to_string(),
                value: -1,
            }],
            flags: Vec::new(),
        };
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![identity, vector, base, derived, orphan],
                vec![enum_],
            ),
        )]);

        dump_sdk(&root, &schemas, Some(12345)).expect("write synthetic SDK");
        let sdk_types = std::fs::read_to_string(root.join("sdk/sdk_types.hpp")).unwrap();
        assert!(sdk_types.contains("CS2_BUILD = 12345"));
        let source = root.join("smoke.cpp");
        std::fs::write(
            &source,
            "#include \"sdk_classes.hpp\"\nint main() { return 0; }\n",
        )
        .expect("write smoke source");

        let status = Command::new("g++")
            .args(["-std=c++20", "-fsyntax-only"])
            .arg("-I")
            .arg(root.join("sdk"))
            .arg(&source)
            .status()
            .expect("run g++");
        let _ = std::fs::remove_dir_all(&root);
        assert!(status.success(), "generated SDK does not compile");
    }
}
