//! Protobuf message-layout emitter.
//!
//! Emits real, drop-in C++ structs (one per protobuf message) recovered from
//! libprotobuf's reflection tables (see `analysis::protobufs`). Each struct is
//! `#pragma pack(1)` with explicit padding so member offsets are exact by
//! construction, plus `static_assert`s on `sizeof`/`offsetof`. Cast a live
//! message pointer to it and read/write fields directly; has-bit i is tested as
//! `*(uint32_t*)((char*)msg + kHasBits) & (1u << i)`.
//!
//! Non-scalar fields are typed (not raw byte slots): singular messages are
//! `Type*`, strings/bytes are `pb::string_t*`, and repeated fields are
//! `pb::RepeatedField<T>` / `pb::RepeatedPtrField<T>` — while the explicit
//! padding + `static_assert`s keep every offset byte-exact.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::analysis::{ProtoField, ProtoMessage, ProtobufMap};

fn module_ns(module: &str) -> String {
    sanitize(module.trim_end_matches(".dll"))
}

const CPP_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char16_t",
    "char32_t",
    "class",
    "compl",
    "const",
    "constexpr",
    "const_cast",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
];

fn sanitize(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() {
        s.push('_');
    }
    if s.chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        s.insert(0, '_');
    }
    if CPP_KEYWORDS.contains(&s.as_str()) {
        s.push('_');
    }
    s
}

/// `flattened message name -> module namespace`, so a field's proto type_name
/// can be resolved to the emitted `pb::<module>::<Name>` struct.
struct Registry {
    by_mod: BTreeMap<String, BTreeSet<String>>,
    global: BTreeMap<String, String>,
    maps: BTreeMap<(String, String), (String, String)>,
}

impl Registry {
    fn build(map: &ProtobufMap) -> Self {
        let mut by_mod: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut global: BTreeMap<String, String> = BTreeMap::new();
        let mut maps = BTreeMap::new();
        for (module, msgs) in map {
            let ns = module_ns(module);
            for m in msgs {
                if m.size == 0 {
                    continue; // not emitted → don't resolve pointers to it
                }
                let flat = sanitize(&m.name);
                by_mod.entry(ns.clone()).or_default().insert(flat.clone());
                global.entry(flat).or_insert_with(|| ns.clone());
            }
        }
        for (module, msgs) in map {
            let ns = module_ns(module);
            for m in msgs {
                if m.size == 0 {
                    continue;
                }
                if m.map_entry {
                    let key = m.fields.iter().find(|f| f.number == 1);
                    let value = m.fields.iter().find(|f| f.number == 2);
                    if let (Some(key), Some(value)) = (key, value) {
                        maps.insert(
                            (ns.clone(), sanitize(&m.name)),
                            (
                                proto_value_type(key, &global, &ns),
                                proto_value_type(value, &global, &ns),
                            ),
                        );
                    }
                }
            }
        }
        Registry {
            by_mod,
            global,
            maps,
        }
    }

    /// Resolve a proto type_name (`.pkg.Outer.Inner`) to `pb::<mod>::<Name>`,
    /// preferring the referencing message's own module. `None` if unknown.
    fn resolve(&self, type_name: &str, cur_ns: &str) -> Option<String> {
        let flat = sanitize(&type_name.trim_start_matches('.').replace('.', "_"));
        if self.by_mod.get(cur_ns).is_some_and(|s| s.contains(&flat)) {
            return Some(format!("pb::{cur_ns}::{flat}"));
        }
        self.global.get(&flat).map(|m| format!("pb::{m}::{flat}"))
    }

    fn map_types(&self, type_name: &str, cur_ns: &str) -> Option<(String, String)> {
        let flat = sanitize(&type_name.trim_start_matches('.').replace('.', "_"));
        self.maps
            .get(&(cur_ns.to_string(), flat.clone()))
            .cloned()
            .or_else(|| {
                self.maps
                    .iter()
                    .find(|((_, name), _)| name == &flat)
                    .map(|(_, types)| types.clone())
            })
    }
}

fn proto_value_type(f: &ProtoField, global: &BTreeMap<String, String>, cur_ns: &str) -> String {
    if let Some((ty, _)) = scalar(f) {
        return ty.to_string();
    }
    match f.ty {
        9 | 12 => "pb::string_t".to_string(),
        10 | 11 => {
            let flat = sanitize(&f.type_name.trim_start_matches('.').replace('.', "_"));
            global
                .get(&flat)
                .map(|ns| format!("pb::{ns}::{flat}*"))
                .unwrap_or_else(|| format!("void* /* {cur_ns} */"))
        }
        _ => "uint8_t".to_string(),
    }
}

/// Scalar C++ type + byte size for a singular (non-repeated) field, else None.
fn scalar(f: &ProtoField) -> Option<(&'static str, u32)> {
    if f.label == 3 {
        return None; // repeated
    }
    Some(match f.ty {
        1 => ("double", 8),
        2 => ("float", 4),
        3 | 16 | 18 => ("int64_t", 8),
        4 | 6 => ("uint64_t", 8),
        5 | 15 | 17 => ("int32_t", 4),
        7 | 13 => ("uint32_t", 4),
        8 => ("bool", 1),
        14 => ("int32_t", 4), // enum
        _ => return None,     // 9 string, 10/11 message, 12 bytes
    })
}

/// Element C++ type for a repeated field's `RepeatedField`/`RepeatedPtrField`.
/// Returns (type, uses_ptr_field) — message/string use RepeatedPtrField.
fn repeated_elem(f: &ProtoField, reg: &Registry, cur_ns: &str) -> (String, bool) {
    match f.ty {
        1 => ("double".into(), false),
        2 => ("float".into(), false),
        3 | 16 | 18 => ("int64_t".into(), false),
        4 | 6 => ("uint64_t".into(), false),
        5 | 15 | 17 => ("int32_t".into(), false),
        7 | 13 => ("uint32_t".into(), false),
        8 => ("bool".into(), false),
        14 => ("int32_t".into(), false),         // enum
        9 | 12 => ("pb::string_t".into(), true), // string/bytes
        10 | 11 => (
            reg.resolve(&f.type_name, cur_ns)
                .unwrap_or_else(|| "void".into()),
            true,
        ),
        _ => ("void".into(), true),
    }
}

/// Human-readable proto type for the trailing comment.
fn proto_ty(f: &ProtoField) -> String {
    let base = match f.ty {
        1 => "double",
        2 => "float",
        3 => "int64",
        4 => "uint64",
        5 => "int32",
        6 => "fixed64",
        7 => "fixed32",
        8 => "bool",
        9 => "string",
        10 => "group",
        11 => "message",
        12 => "bytes",
        13 => "uint32",
        14 => "enum",
        15 => "sfixed32",
        16 => "sfixed64",
        17 => "sint32",
        18 => "sint64",
        _ => "?",
    };
    let rep = if f.label == 3 { "repeated " } else { "" };
    let tn = if f.type_name.is_empty() {
        String::new()
    } else {
        format!(" {}", f.type_name.trim_start_matches('.'))
    };
    format!("{rep}{base}{tn}")
}

/// The C++ member declaration (type only, no name) and its byte size for a
/// field, given the slot available before the next field. `None` → emit a raw
/// byte slot (slot too small for the natural type).
fn member_type(f: &ProtoField, reg: &Registry, cur_ns: &str, slot: u32) -> Option<(String, u32)> {
    if f.label == 3 {
        // repeated: RepeatedField<T> (scalar) / RepeatedPtrField<T> (msg/string), 0x18.
        if slot >= 0x18 {
            if f.is_map {
                let (key, value) = reg
                    .map_types(&f.type_name, cur_ns)
                    .unwrap_or_else(|| ("void".into(), "void".into()));
                return Some((format!("pb::MapField<{key}, {value}>"), 0x18));
            }
            let (elem, ptr) = repeated_elem(f, reg, cur_ns);
            let cont = if ptr {
                "RepeatedPtrField"
            } else {
                "RepeatedField"
            };
            return Some((format!("pb::{cont}<{elem}>"), 0x18));
        }
        return None;
    }
    if let Some((ty, sz)) = scalar(f) {
        return (sz <= slot).then(|| (ty.to_string(), sz));
    }
    match f.ty {
        9 | 12 => (slot >= 8).then(|| ("pb::string_t*".to_string(), 8)), // string/bytes
        10 | 11 => (slot >= 8).then(|| {
            let t = reg
                .resolve(&f.type_name, cur_ns)
                .unwrap_or_else(|| "void".into());
            (format!("{t}*"), 8)
        }),
        _ => None,
    }
}

fn struct_block(m: &ProtoMessage, cur_ns: &str, reg: &Registry) -> String {
    let name = sanitize(&m.name);
    let size = m.size;
    let mut s = String::new();

    let hb = m
        .has_bits_offset
        .map(|o| format!("_has_bits_ @ {o:#x}"))
        .unwrap_or_else(|| "no _has_bits_".to_string());

    // Fields in memory order; drop ones at/after object end. Oneof members
    // intentionally remain grouped so the generated C++ preserves the union
    // semantics instead of silently keeping only the first field.
    let mut fields: Vec<&ProtoField> = m.fields.iter().filter(|f| f.offset < size).collect();
    fields.sort_by_key(|f| f.offset);

    writeln!(s, "#pragma pack(push, 1)").ok();
    writeln!(s, "struct {name} {{ // sizeof {size:#x}, {hb}").ok();

    let mut asserts: Vec<String> = Vec::new();

    if fields.is_empty() {
        if size > 0 {
            writeln!(s, "    uint8_t _data[{size:#x}];").ok();
        }
    } else {
        let mut cursor: u32 = 0;
        for (i, f) in fields.iter().enumerate() {
            let off = f.offset;
            if off < cursor {
                continue;
            }
            if off > cursor {
                writeln!(s, "    uint8_t _pad_{:x}[{:#x}];", cursor, off - cursor).ok();
                cursor = off;
            }
            // Skip fields already emitted as part of an anonymous union.
            if i > 0
                && f.oneof.is_some()
                && f.oneof == fields[i - 1].oneof
                && f.offset == fields[i - 1].offset
            {
                continue;
            }

            let mut group_end = i + 1;
            while group_end < fields.len()
                && f.oneof.is_some()
                && fields[group_end].offset == off
                && fields[group_end].oneof == f.oneof
            {
                group_end += 1;
            }
            let next = fields.get(group_end).map(|n| n.offset).unwrap_or(size);
            let slot = next.saturating_sub(off);
            if slot == 0 {
                continue;
            }

            if group_end > i + 1 {
                writeln!(s, "    union {{").ok();
                for member in &fields[i..group_end] {
                    let fname = sanitize(&member.name);
                    if let Some((ty, _)) = member_type(member, reg, cur_ns, slot) {
                        writeln!(s, "        {ty} {fname}; // #{}", member.number).ok();
                    } else {
                        writeln!(
                            s,
                            "        uint8_t {fname}[{slot:#x}]; // #{}",
                            member.number
                        )
                        .ok();
                    }
                }
                writeln!(s, "    }};").ok();
                cursor = off + slot;
                continue;
            }

            let fname = sanitize(&f.name);
            let hbit = f
                .has_bit
                .map(|b| format!("has-bit {b}"))
                .unwrap_or_else(|| "no has-bit".to_string());
            match member_type(f, reg, cur_ns, slot) {
                Some((ty, sz)) => {
                    writeln!(
                        s,
                        "    {ty} {fname}; // #{} {}, {}",
                        f.number,
                        proto_ty(f),
                        hbit
                    )
                    .ok();
                    if slot > sz {
                        writeln!(s, "    uint8_t _pad_{:x}[{:#x}];", off + sz, slot - sz).ok();
                    }
                }
                None => {
                    writeln!(
                        s,
                        "    uint8_t {fname}[{slot:#x}]; // #{} {}, {}",
                        f.number,
                        proto_ty(f),
                        hbit
                    )
                    .ok();
                }
            }
            asserts.push(format!(
                "static_assert(offsetof({name}, {fname}) == {off:#x});"
            ));
            cursor = off + slot;
        }
        if cursor < size {
            writeln!(s, "    uint8_t _pad_{:x}[{:#x}];", cursor, size - cursor).ok();
        }
    }

    writeln!(
        s,
        "    static constexpr std::ptrdiff_t kSizeOf = {size:#x};"
    )
    .ok();
    if let Some(o) = m.has_bits_offset {
        writeln!(s, "    static constexpr std::ptrdiff_t kHasBits = {o:#x};").ok();
    }
    writeln!(s, "}};").ok();
    writeln!(s, "#pragma pack(pop)").ok();
    writeln!(s, "static_assert(sizeof({name}) == {size:#x});").ok();
    for a in asserts {
        writeln!(s, "{a}").ok();
    }
    s.push('\n');
    s
}

/// libprotobuf container shims (x64 layout) used by typed repeated fields.
fn base_decls() -> &'static str {
    "namespace pb {\n\
    \x20   // std::string the message owns (ArenaStringPtr points at one). Opaque.\n\
    \x20   struct string_t;\n\
    \x20   // libprotobuf RepeatedField<T> / RepeatedPtrField<T> (x64 = 0x18).\n\
    \x20   template <class T> struct RepeatedField    { void* arena; int current_size; int total_size; T* elements; };\n\
    \x20   template <class T> struct RepeatedPtrField { void* arena; int current_size; int total_size; void* rep; };\n\
    \x20   template <class K, class V> struct MapField { void* arena; int current_size; int total_size; void* rep; };\n\
    \x20   static_assert(sizeof(RepeatedField<int>) == 0x18 && sizeof(RepeatedPtrField<int>) == 0x18 && sizeof(MapField<int, int>) == 0x18);\n\
    } // namespace pb\n\n"
}

pub fn render_hpp(map: &ProtobufMap, build_number: Option<u32>) -> String {
    let reg = Registry::build(map);

    let mut s = String::new();
    s.push_str("// Generated by cs2-sdk - https://cs2-sdk.com\n");
    s.push_str("// Real protobuf message structs (offsets recovered from libprotobuf\n");
    s.push_str("// reflection tables). Each is #pragma pack(1) with exact padding;\n");
    s.push_str("// cast a live message pointer and read fields directly. has-bit i:\n");
    s.push_str("//   *(uint32_t*)((char*)msg + Msg::kHasBits) & (1u << i)\n");
    s.push_str("#pragma once\n\n#include <cstddef>\n#include <cstdint>\n\n");
    if let Some(bn) = build_number {
        writeln!(
            s,
            "namespace pb {{ inline constexpr std::uint32_t CS2_BUILD = {bn}; }}\n"
        )
        .ok();
    }
    s.push_str(base_decls());

    // Forward-declare every message struct so cross-module / forward field
    // pointers resolve regardless of emission order.
    for (module, messages) in map {
        if messages.is_empty() {
            continue;
        }
        let ns = module_ns(module);
        let mut seen = BTreeSet::new();
        let mut fwd = String::new();
        for m in messages {
            if m.size == 0 {
                continue;
            }
            let n = sanitize(&m.name);
            if seen.insert(n.clone()) {
                writeln!(fwd, "    struct {n};").ok();
            }
        }
        if !fwd.is_empty() {
            writeln!(s, "namespace pb::{ns} {{").ok();
            s.push_str(&fwd);
            writeln!(s, "}} // namespace pb::{ns}\n").ok();
        }
    }

    for (module, messages) in map {
        if messages.is_empty() {
            continue;
        }
        let ns = module_ns(module);
        writeln!(s, "namespace pb::{} {{", ns).ok();
        let mut seen = BTreeSet::new();
        for m in messages {
            if m.size == 0 || !seen.insert(sanitize(&m.name)) {
                continue;
            }
            s.push_str(&struct_block(m, &ns, &reg));
        }
        writeln!(s, "}} // namespace pb::{}\n", ns).ok();
    }
    s
}

pub fn render_json(map: &ProtobufMap) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    let modules: Vec<_> = map.iter().filter(|(_, m)| !m.is_empty()).collect();
    for (mi, (module, messages)) in modules.iter().enumerate() {
        writeln!(s, "  \"{}\": {{", module).ok();
        for (msgi, m) in messages.iter().enumerate() {
            writeln!(s, "    \"{}\": {{", m.name).ok();
            writeln!(s, "      \"size\": {},", m.size).ok();
            writeln!(s, "      \"map_entry\": {},", m.map_entry).ok();
            writeln!(
                s,
                "      \"has_bits_offset\": {},",
                m.has_bits_offset.map(|o| o as i64).unwrap_or(-1)
            )
            .ok();
            s.push_str("      \"fields\": {\n");
            for (fi, f) in m.fields.iter().enumerate() {
                let comma = if fi + 1 < m.fields.len() { "," } else { "" };
                writeln!(
                    s,
                    "        \"{}\": {{ \"offset\": {}, \"number\": {}, \"has_bit\": {}, \"type\": {}, \"label\": {}, \"oneof\": {}, \"is_map\": {} }}{}",
                    f.name,
                    f.offset,
                    f.number,
                    f.has_bit.map(|b| b as i64).unwrap_or(-1),
                    f.ty,
                    f.label,
                    serde_json::to_string(&f.oneof).unwrap_or_else(|_| "null".to_string()),
                    f.is_map,
                    comma,
                )
                .ok();
            }
            s.push_str("      }\n");
            let comma = if msgi + 1 < messages.len() { "," } else { "" };
            writeln!(s, "    }}{}", comma).ok();
        }
        let comma = if mi + 1 < modules.len() { "," } else { "" };
        writeln!(s, "  }}{}", comma).ok();
    }
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::{render_hpp, render_json};
    use crate::analysis::{ProtoField, ProtoMessage, ProtobufMap};

    #[test]
    fn preserves_oneof_members_as_union_and_json_metadata() {
        let mut map = ProtobufMap::new();
        map.insert(
            "client.dll".into(),
            vec![ProtoMessage {
                name: "Choice".into(),
                size: 0x20,
                has_bits_offset: None,
                map_entry: false,
                fields: vec![
                    ProtoField {
                        name: "as_int".into(),
                        number: 1,
                        offset: 0x10,
                        has_bit: None,
                        label: 1,
                        ty: 5,
                        type_name: String::new(),
                        is_map: false,
                        oneof: Some("value".into()),
                    },
                    ProtoField {
                        name: "as_float".into(),
                        number: 2,
                        offset: 0x10,
                        has_bit: None,
                        label: 1,
                        ty: 2,
                        type_name: String::new(),
                        is_map: false,
                        oneof: Some("value".into()),
                    },
                ],
            }],
        );
        let hpp = render_hpp(&map, Some(7));
        assert!(hpp.contains("union {"));
        assert!(hpp.contains("int32_t as_int"));
        assert!(hpp.contains("float as_float"));
        let json = render_json(&map);
        assert!(json.contains("\"oneof\": \"value\""));
    }

    #[test]
    fn renders_map_entry_as_typed_map_field() {
        let mut map = ProtobufMap::new();
        map.insert(
            "client.dll".into(),
            vec![
                ProtoMessage {
                    name: "LabelsEntry".into(),
                    size: 0x20,
                    has_bits_offset: None,
                    map_entry: true,
                    fields: vec![
                        ProtoField {
                            name: "key".into(),
                            number: 1,
                            offset: 0x10,
                            has_bit: None,
                            label: 1,
                            ty: 9,
                            type_name: String::new(),
                            is_map: false,
                            oneof: None,
                        },
                        ProtoField {
                            name: "value".into(),
                            number: 2,
                            offset: 0x18,
                            has_bit: None,
                            label: 1,
                            ty: 5,
                            type_name: String::new(),
                            is_map: false,
                            oneof: None,
                        },
                    ],
                },
                ProtoMessage {
                    name: "Container".into(),
                    size: 0x30,
                    has_bits_offset: None,
                    map_entry: false,
                    fields: vec![ProtoField {
                        name: "labels".into(),
                        number: 1,
                        offset: 0x10,
                        has_bit: None,
                        label: 3,
                        ty: 11,
                        type_name: ".LabelsEntry".into(),
                        is_map: true,
                        oneof: None,
                    }],
                },
            ],
        );
        let hpp = render_hpp(&map, None);
        assert!(hpp.contains("MapField<pb::string_t, int32_t>"));
        let json = render_json(&map);
        assert!(json.contains("\"map_entry\": true"));
        assert!(json.contains("\"is_map\": true"));
    }
}
