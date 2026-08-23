use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;

use phf::phf_map;

use crate::analysis::{Class, Enum, SchemaMap};

static PRIM_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "bool" => "bool",
    "float32" => "float",
    "float64" => "double",
    "int8" => "int8_t",
    "int16" => "int16_t",
    "int32" => "int32_t",
    "int64" => "int64_t",
    "uint8" => "uint8_t",
    "uint16" => "uint16_t",
    "uint32" => "uint32_t",
    "uint64" => "uint64_t",
    "int" => "int32_t",
    "unsignedint" => "uint32_t",
    "long" => "long",
    "unsignedlong" => "unsigned long",
    "char" => "char",
    "void" => "void",
    "Color" => "uint32_t",
    "GameTime_t" => "float",
    "GameTick_t" => "int32_t",
    "float" => "float",
    "CUtlStringToken" => "uint32_t",
    "CGlobalSymbol" => "uint64_t",
    "PulseSymbol_t" => "uint64_t",
    "CEntityIndex" => "uint32_t",
    "CEntityHandle" => "uint32_t",
    "ItemId_t" => "uint64_t",
    "ItemIdLow_t" => "uint32_t",
    "AttachmentHandle_t" => "uint8_t",
    "AmmoIndex_t" => "uint8_t",
    "SceneHandle_t" => "uint32_t",
    "HSequence" => "int32_t",
    "attributeprovidertypes_t" => "uint32_t",
    "EntityPlatformTypes_t" => "uint8_t",
    "TakeDamageFlags_t" => "uint32_t",
    "SplitScreenSlot_t" => "uint32_t",
    "CSPlayerState" => "uint32_t",
    "CSPlayerBullets_t" => "int32_t",
    "WorldGroupId_t" => "int32_t",
    "CNetworkedQuantizedFloat" => "float",
    "CFiringModeFloat" => "float",
    "CFiringModeInt" => "int32_t",
    "HSCRIPT" => "uint64_t",
    "ScriptOrdinal_t" => "uint32_t",
    "SubclassMdlData_t" => "uint32_t",
    "RenderMode_t" => "uint8_t",
    "RenderGroup_t" => "uint32_t",
    "SolidType_t" => "uint8_t",
    "SurroundingBoundsType_t" => "uint8_t",
    "DamageMode_t" => "uint8_t",
    "DoorState_t" => "uint8_t",
    "ShatterPanelMode" => "uint8_t",
    "ShatterDamageCause" => "uint8_t",
    "ShatterGlassEdge_t" => "uint8_t",
    "ShatterGlassTint_t" => "uint8_t",
    "ShadowType_t" => "uint8_t",
    "Touch_t" => "uint8_t",
    "WaterWakeMode_t" => "uint8_t",
    "CounterType_t" => "uint8_t",
    "FontLerpMode_t" => "uint8_t",
    "FadeBlendMode_t" => "uint8_t",
    "ExplosionType_t" => "uint8_t",
    "ClaimResult_t" => "uint32_t",
    "ChickenActivity_t" => "uint32_t",
    "ChickenToCrowActivity_t" => "uint32_t",
    "ItemFlagTypes_t" => "uint8_t",
    "MoneyShellPage_t" => "uint8_t",
    "eSpectatorTeamContentChannel" => "uint32_t",
    "BoneDomain_t" => "uint32_t",
    "VPhysExpiry_t" => "uint32_t",
    "ShootMode_t" => "uint32_t",
    "PlayerConnectedState" => "uint32_t",
    "DisplacementLookups_t" => "uint32_t",
    "CStrongHandle" => "uint64_t",
    "CWeakHandle" => "uint64_t",
    "SkeletonBoneBits_t" => "uint32_t",
    "fixtures1_t" => "uint32_t",
    "AEarRspBox_t" => "uint32_t",
};

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

// Basic structs
struct Vector { float x, y, z; };
struct Vector2D { float x, y; };
struct Vector4D { float x, y, z, w; };
struct QAngle { float x, y, z; };
struct CTransform { Vector pos; QAngle rot; };
struct CNetworkOriginCellCoordQuantizedVector { float x, y, z; };
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

struct ResolvedType {
    cpp_type: String,
    is_arr: bool,
    arr_size: usize,
}

fn sanitize_cpp_ident(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut previous_separator = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            previous_separator = false;
        } else if !previous_separator {
            out.push('_');
            previous_separator = true;
        }
    }
    if out.is_empty() {
        return "Anonymous".to_string();
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if is_cpp_keyword(&out) {
        out.insert(0, '_');
    }
    out
}

fn is_cpp_keyword(name: &str) -> bool {
    matches!(
        name,
        "alignas"
            | "alignof"
            | "asm"
            | "auto"
            | "bool"
            | "break"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "constexpr"
            | "continue"
            | "default"
            | "delete"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "explicit"
            | "export"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "friend"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "mutable"
            | "namespace"
            | "new"
            | "noexcept"
            | "nullptr"
            | "operator"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "reinterpret_cast"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typedef"
            | "typename"
            | "union"
            | "unsigned"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
    )
}

fn resolve_type(raw: &str, known_types: &HashSet<&str>) -> ResolvedType {
    let ts = raw.trim();

    if ts.ends_with('*') {
        let pointee = ts.trim_end_matches('*').trim();
        if known_types.contains(pointee) {
            return ResolvedType {
                cpp_type: format!("{}*", sanitize_cpp_ident(pointee)),
                is_arr: false,
                arr_size: 0,
            };
        }
        return ResolvedType {
            cpp_type: "uintptr_t".to_string(),
            is_arr: false,
            arr_size: 0,
        };
    }

    if let Some((inner, size)) = parse_fixed_array(ts) {
        let mut resolved = resolve_type(&inner, known_types);
        resolved.is_arr = true;
        resolved.arr_size = size;
        return resolved;
    }

    if is_handle_like(ts) {
        return ResolvedType {
            cpp_type: "uint32_t".to_string(),
            is_arr: false,
            arr_size: 0,
        };
    }

    if is_vector_like(ts) {
        return ResolvedType {
            cpp_type: "uintptr_t".to_string(),
            is_arr: false,
            arr_size: 0,
        };
    }

    if let Some(bits) = parse_bitfield(ts) {
        let cpp_type = match bits {
            0..=8 => "uint8_t",
            9..=16 => "uint16_t",
            17..=32 => "uint32_t",
            _ => "uint64_t",
        };

        return ResolvedType {
            cpp_type: cpp_type.to_string(),
            is_arr: false,
            arr_size: 0,
        };
    }

    let stripped = ts.replace(' ', "");
    if let Some(mapped) = PRIM_MAP.get(stripped.as_str()) {
        return ResolvedType {
            cpp_type: (*mapped).to_string(),
            is_arr: false,
            arr_size: 0,
        };
    }

    if matches!(
        stripped.as_str(),
        "Vector"
            | "Vector2D"
            | "Vector4D"
            | "QAngle"
            | "CTransform"
            | "CNetworkOriginCellCoordQuantizedVector"
            | "CNetworkVelocityVector"
            | "CNetworkViewOffsetVector"
    ) {
        return ResolvedType {
            cpp_type: stripped,
            is_arr: false,
            arr_size: 0,
        };
    }

    if known_types.contains(ts) {
        return ResolvedType {
            cpp_type: sanitize_cpp_ident(ts),
            is_arr: false,
            arr_size: 0,
        };
    }

    if let Some(pos) = ts.rfind("::") {
        let last = &ts[pos + 2..];

        return ResolvedType {
            cpp_type: if known_types.contains(ts) || known_types.contains(last) {
                sanitize_cpp_ident(ts)
            } else {
                "uint32_t".to_string()
            },
            is_arr: false,
            arr_size: 0,
        };
    }

    ResolvedType {
        cpp_type: "uintptr_t".to_string(),
        is_arr: false,
        arr_size: 0,
    }
}

fn parse_fixed_array(raw: &str) -> Option<(String, usize)> {
    if !raw.ends_with(']') {
        return None;
    }

    let pos = raw.rfind('[')?;
    let size = raw[pos + 1..raw.len() - 1].trim().parse::<usize>().ok()?;
    let inner = raw[..pos].trim().to_string();

    Some((inner, size))
}

fn is_handle_like(raw: &str) -> bool {
    raw.starts_with("CHandle<")
        || raw.starts_with("CStrongHandle<")
        || raw.starts_with("CWeakHandle<")
}

fn is_vector_like(raw: &str) -> bool {
    raw.starts_with("CUtlVector<")
        || raw.starts_with("C_NetworkUtlVectorBase<")
        || raw.starts_with("C_UtlVectorEmbeddedNetworkVar<")
}

fn parse_bitfield(raw: &str) -> Option<u32> {
    raw.strip_prefix("bitfield:")?.parse::<u32>().ok()
}

pub fn write_sdk_types(classes: &[(&String, &Class)], build_number: Option<u32>) -> String {
    let mut out = String::new();
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
        let _ = writeln!(out, "class {};", sanitize_cpp_ident(&class.name));
    }

    let _ = writeln!(out);
    out.push_str(SDK_TYPES_BODY);

    if !out.ends_with('\n') {
        out.push('\n');
    }

    out
}

fn enum_underlying(alignment: u8) -> &'static str {
    match alignment {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint32_t",
    }
}

fn enum_max_value(type_name: &str) -> u64 {
    match type_name {
        "uint8_t" => u8::MAX as u64,
        "uint16_t" => u16::MAX as u64,
        "uint32_t" => u32::MAX as u64,
        "uint64_t" => u64::MAX,
        _ => 0,
    }
}

fn enum_value_literal(value: i64, type_name: &str) -> String {
    let bits = match type_name {
        "uint8_t" => 8,
        "uint16_t" => 16,
        "uint32_t" => 32,
        "uint64_t" => 64,
        _ => 32,
    };
    let masked = if bits == 64 {
        value as u64
    } else {
        (value as u64) & ((1u64 << bits) - 1)
    };
    format!("{:#X}", masked)
}

pub fn write_sdk_enums(enums: &[(&String, &Enum)]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Auto-generated by cs2-dumper (SDK mode).");
    let _ = writeln!(out, "// DO NOT EDIT MANUALLY.");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include <cstdint>");
    let _ = writeln!(out);

    for (module_name, enum_) in enums.iter().copied() {
        let type_name = enum_underlying(enum_.storage_bytes());
        let _ = writeln!(out, "// Module: {}", module_name);
        let _ = writeln!(
            out,
            "enum class {} : {} {{",
            sanitize_cpp_ident(&enum_.name),
            type_name
        );

        for member in &enum_.members {
            let formatted_value = enum_value_literal(member.value, type_name);

            let _ = writeln!(
                out,
                "    {} = {},",
                sanitize_cpp_ident(&member.name),
                formatted_value
            );
        }

        let _ = writeln!(out, "}};");
        let _ = writeln!(out);
    }

    out
}

pub fn write_sdk_classes(classes: &[(&String, &Class)], enums: &[(&String, &Enum)]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out);
    let _ = writeln!(out, "// Auto-generated by cs2-dumper (SDK mode).");
    let _ = writeln!(out, "// DO NOT EDIT MANUALLY.");
    let _ = writeln!(out);
    let _ = writeln!(out, "#include \"sdk_types.hpp\"");
    let _ = writeln!(out, "#include \"sdk_enums.hpp\"");
    let _ = writeln!(out);

    let known_types: HashSet<&str> = classes
        .iter()
        .map(|(_, class)| class.name.as_str())
        .chain(enums.iter().map(|(_, enum_)| enum_.name.as_str()))
        .collect();

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
        if let Some(status) = state.get(name).copied() {
            if status == 1 || status == 2 {
                return;
            }
        }

        state.insert(name, 1);

        if let Some(class) = class_map.get(name) {
            if let Some(parent) = class.parent_name.as_deref() {
                if class_map.contains_key(parent) {
                    visit(parent, class_map, state, ordered);
                }
            }
        }

        state.insert(name, 2);
        ordered.push(name);
    }

    for (_, class) in classes {
        visit(class.name.as_str(), &class_map, &mut state, &mut ordered);
    }

    for name in &ordered {
        let class = class_map[*name];
        let class_name = sanitize_cpp_ident(name);
        let parent = class.parent_name.as_deref();

        if let Some(parent) = parent {
            let _ = writeln!(
                out,
                "class {} : public {} {{",
                class_name,
                sanitize_cpp_ident(parent)
            );
        } else {
            let _ = writeln!(out, "class {} {{", class_name);
        }
        let _ = writeln!(out, "public:");

        let mut fields = class.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|field| field.offset);

        let mut seen = HashSet::new();
        for field in fields {
            if !seen.insert(field.name.as_str()) {
                continue;
            }

            let resolved = resolve_type(&field.type_name, &known_types);
            let field_name = sanitize_cpp_ident(&field.name);
            let field_type = if resolved.is_arr {
                format!("{}[{}]", resolved.cpp_type, resolved.arr_size)
            } else {
                resolved.cpp_type
            };

            if resolved.is_arr {
                let _ = writeln!(
                    out,
                    "    FieldRef<{}> {}() {{ return {{this, {:#X}}}; }}",
                    field_type, field_name, field.offset
                );
            } else {
                let _ = writeln!(
                    out,
                    "    SCHEMA_FIELD({}, {}, {:#X})",
                    field_type, field_name, field.offset
                );
            }
        }
        let _ = writeln!(out, "}};");
        let _ = writeln!(out);
    }

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

pub fn collect_sdk_data(schemas: &SchemaMap) -> (Vec<(String, Enum)>, Vec<(String, Class)>) {
    let mut enums: BTreeMap<String, (String, Enum)> = BTreeMap::new();
    let mut classes: BTreeMap<String, (String, Class)> = BTreeMap::new();

    let mut module_names: Vec<&str> = schemas.keys().map(String::as_str).collect();
    module_names.sort_by(|a, b| {
        let a_key = (if *a == "client.dll" { 0 } else { 1 }, *a);
        let b_key = (if *b == "client.dll" { 0 } else { 1 }, *b);
        a_key.cmp(&b_key)
    });

    for module_name in module_names {
        let Some((module_classes, module_enums)) = schemas.get(module_name) else {
            continue;
        };

        for enum_ in module_enums {
            enums
                .entry(enum_.name.clone())
                .or_insert_with(|| (module_name.to_string(), enum_.clone()));
        }

        for class in module_classes {
            classes
                .entry(class.name.clone())
                .or_insert_with(|| (module_name.to_string(), class.clone()));
        }
    }

    (
        enums.into_values().collect(),
        classes.into_values().collect(),
    )
}

fn module_slug(input: &str) -> String {
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
        "module".to_string()
    } else {
        out
    }
}

fn write_module_header(module: &str, classes: &[Class], enums: &[Enum]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "#pragma once\n#include <cstddef>\n#include <cstdint>\n"
    );
    let _ = writeln!(
        out,
        "// Auto-generated per-schema-scope offsets for {}.",
        module
    );
    let _ = writeln!(
        out,
        "namespace offsets {{ namespace {} {{",
        module_slug(module)
    );
    for enum_ in enums {
        let underlying = enum_underlying(enum_.storage_bytes());
        let _ = writeln!(
            out,
            "enum class {} : {} {{",
            sanitize_cpp_ident(&enum_.name),
            underlying
        );
        for member in &enum_.members {
            let _ = writeln!(
                out,
                "    {} = 0x{:X},",
                sanitize_cpp_ident(&member.name),
                u64::from_str_radix(
                    enum_value_literal(member.value, underlying)
                        .trim_start_matches("0x")
                        .trim_start_matches("0X"),
                    16,
                )
                .unwrap_or_else(|_| enum_max_value(underlying))
            );
        }
        let _ = writeln!(out, "}};\n");
    }
    for class in classes {
        let _ = writeln!(out, "namespace {} {{", sanitize_cpp_ident(&class.name));
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
        for field in &class.fields {
            let _ = writeln!(
                out,
                "inline constexpr std::ptrdiff_t {} = 0x{:X}; // {}",
                sanitize_cpp_ident(&field.name),
                field.offset,
                field.type_name
            );
        }
        let _ = writeln!(out, "}}\n");
    }
    let _ = writeln!(out, "}} }}");
    out
}

fn write_class_header(module: &str, class: &Class) -> String {
    let mut out = String::new();
    let module = module_slug(module);
    let _ = writeln!(out, "#pragma once\n#include <cstddef>\n");
    let _ = writeln!(out, "// Auto-generated schema offsets for {}.", class.name);
    for flag in &class.flags {
        let _ = writeln!(out, "// {}", flag);
    }
    let _ = writeln!(
        out,
        "namespace offsets {{ namespace {} {{ namespace {} {{",
        module,
        sanitize_cpp_ident(&class.name)
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
    for field in &class.fields {
        let _ = writeln!(
            out,
            "inline constexpr std::ptrdiff_t {} = 0x{:X}; // {}",
            sanitize_cpp_ident(&field.name),
            field.offset,
            field.type_name
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
    for (module, (classes, enums)) in schemas {
        let slug = module_slug(module);
        std::fs::write(
            modules_dir.join(format!("{}.hpp", slug)),
            write_module_header(module, classes, enums),
        )?;
        let module_classes_dir = classes_dir.join(&slug);
        std::fs::create_dir_all(&module_classes_dir)?;
        for class in classes {
            std::fs::write(
                module_classes_dir.join(format!("{}.hpp", sanitize_cpp_ident(&class.name))),
                write_class_header(module, class),
            )?;
        }
        let _ = writeln!(umbrella, "#include \"modules/{}.hpp\"", slug);
    }
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

    let enum_refs: Vec<(&String, &Enum)> = enums
        .iter()
        .map(|(module, enum_)| (module, enum_))
        .collect();
    let class_refs: Vec<(&String, &Class)> = classes
        .iter()
        .map(|(module, class)| (module, class))
        .collect();

    std::fs::write(
        sdk_dir.join("sdk_types.hpp"),
        write_sdk_types(&class_refs, build_number),
    )?;
    println!("  sdk/sdk_types.hpp");

    std::fs::write(sdk_dir.join("sdk_enums.hpp"), write_sdk_enums(&enum_refs))?;
    println!("  sdk/sdk_enums.hpp     {} enums", enums.len());

    std::fs::write(
        sdk_dir.join("sdk_classes.hpp"),
        write_sdk_classes(&class_refs, &enum_refs),
    )?;
    println!("  sdk/sdk_classes.hpp   {} classes", classes.len());

    std::fs::write(sdk_dir.join("sdk.hpp"), write_sdk_umbrella())?;
    dump_module_headers(out_dir, schemas)?;
    println!("  sdk/modules.hpp       per-scope class/enum offsets");
    println!("  sdk/sdk.hpp           umbrella header");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{ClassField, EnumMember};
    use std::process::Command;

    #[test]
    fn sanitizes_nested_cpp_names_without_changing_normal_names() {
        assert_eq!(sanitize_cpp_ident("CCSPlayerPawn"), "CCSPlayerPawn");
        assert_eq!(
            sanitize_cpp_ident("CPulseCell::TimelineEvent_t"),
            "CPulseCell_TimelineEvent_t"
        );
        assert_eq!(sanitize_cpp_ident("3d_type"), "_3d_type");
        assert_eq!(sanitize_cpp_ident("operator"), "_operator");
    }

    #[test]
    fn preserves_known_schema_pointer_types() {
        let known = HashSet::from(["C_BaseEntity", "SomeEnum"]);
        let resolved = resolve_type("C_BaseEntity*", &known);
        assert_eq!(resolved.cpp_type, "C_BaseEntity*");
        let nested = resolve_type("C_BaseEntity[2]", &known);
        assert_eq!(nested.cpp_type, "C_BaseEntity");
        assert!(nested.is_arr);
        assert_eq!(nested.arr_size, 2);
        assert_eq!(resolve_type("Vector", &known).cpp_type, "Vector");
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

        let base = Class {
            name: "C_BaseEntity".to_string(),
            module_name: "client.dll".to_string(),
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
            module_name: "client.dll".to_string(),
            parent_name: Some("C_BaseEntity".to_string()),
            size: 0x28,
            alignment: 8,
            metadata: Vec::new(),
            fields: vec![ClassField {
                name: "m_hOwner".to_string(),
                type_name: "C_BaseEntity*".to_string(),
                offset: 0x20,
                metadata: Vec::new(),
            }],
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
        let schemas =
            SchemaMap::from([("client.dll".to_string(), (vec![base, derived], vec![enum_]))]);

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
            .arg(&root.join("sdk"))
            .arg(&source)
            .status()
            .expect("run g++");
        let _ = std::fs::remove_dir_all(&root);
        assert!(status.success(), "generated SDK does not compile");
    }
}
