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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Write};
use std::sync::Arc;

use crate::analysis::{ProtoField, ProtoMessage, ProtobufMap};

use super::comment_text;
use super::ident::{already_ascii_ident, is_cpp_keyword, IdentifierAllocator};

fn module_ns(module: &str) -> Cow<'_, str> {
    sanitize(module.trim_end_matches(".dll"))
}

fn intern_ns(cache: &mut HashMap<String, Arc<str>>, module: &str) -> Arc<str> {
    let ns = module_ns(module);
    if let Some(existing) = cache.get(ns.as_ref()) {
        return Arc::clone(existing);
    }
    let interned = Arc::from(ns.as_ref());
    cache.insert(ns.into_owned(), Arc::clone(&interned));
    interned
}

fn flatten_proto_name(raw: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = raw.trim_start_matches('.');
    if trimmed.bytes().any(|b| b == b'.') {
        std::borrow::Cow::Owned(trimmed.replace('.', "_"))
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

fn sanitize(raw: &str) -> Cow<'_, str> {
    if already_ascii_ident(raw) {
        if raw.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
            let mut s = String::with_capacity(raw.len() + 1);
            s.push('_');
            s.push_str(raw);
            if is_cpp_keyword(&s) {
                s.push('_');
            }
            return Cow::Owned(s);
        }
        if is_cpp_keyword(raw) {
            let mut s = String::with_capacity(raw.len() + 1);
            s.push_str(raw);
            s.push('_');
            return Cow::Owned(s);
        }
        return Cow::Borrowed(raw);
    }
    let mut s = String::with_capacity(raw.len() + 1);
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
    if s.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        s.insert(0, '_');
    }
    if is_cpp_keyword(&s) {
        s.push('_');
    }
    Cow::Owned(s)
}

/// `flattened message name -> interned `pb::<module>::<Name>`` path, so a
/// field's proto type_name is a lookup instead of a `format!` per field.
struct Registry {
    by_mod: BTreeMap<Arc<str>, BTreeMap<String, Arc<str>>>,
    paths: BTreeMap<String, Arc<str>>,
    maps: BTreeMap<Arc<str>, BTreeMap<String, (String, String)>>,
    emitted_names: BTreeMap<Arc<str>, BTreeMap<String, String>>,
}

impl Registry {
    fn build(map: &ProtobufMap) -> Self {
        let mut ns_cache = HashMap::new();
        let mut by_mod: BTreeMap<Arc<str>, BTreeMap<String, Arc<str>>> = BTreeMap::new();
        let mut paths: BTreeMap<String, Arc<str>> = BTreeMap::new();
        let mut maps: BTreeMap<Arc<str>, BTreeMap<String, (String, String)>> = BTreeMap::new();
        let mut emitted_names: BTreeMap<Arc<str>, BTreeMap<String, String>> = BTreeMap::new();
        let mut allocators: HashMap<Arc<str>, IdentifierAllocator> = HashMap::new();
        for (module, msgs) in map {
            let ns = intern_ns(&mut ns_cache, module);
            for m in msgs {
                if m.size == 0 {
                    continue; // not emitted → don't resolve pointers to it
                }
                let names = emitted_names.entry(Arc::clone(&ns)).or_default();
                if names.contains_key(&m.name) {
                    continue;
                }
                let emitted = allocators
                    .entry(Arc::clone(&ns))
                    .or_default()
                    .allocate(sanitize(&m.name).into_owned());
                names.insert(m.name.clone(), emitted.clone());
                let key = sanitize(flatten_proto_name(&m.name).as_ref()).into_owned();
                let path = Arc::<str>::from(format!("pb::{ns}::{emitted}"));
                by_mod
                    .entry(Arc::clone(&ns))
                    .or_default()
                    .entry(key.clone())
                    .or_insert_with(|| Arc::clone(&path));
                paths.entry(key).or_insert(path);
            }
        }
        for (module, msgs) in map {
            let ns = intern_ns(&mut ns_cache, module);
            for m in msgs {
                if m.size == 0 {
                    continue;
                }
                if m.map_entry {
                    let key = m.fields.iter().find(|f| f.number == 1);
                    let value = m.fields.iter().find(|f| f.number == 2);
                    if let (Some(key), Some(value)) = (key, value) {
                        maps.entry(Arc::clone(&ns)).or_default().insert(
                            sanitize(flatten_proto_name(&m.name).as_ref()).into_owned(),
                            (
                                proto_value_type(key, &paths, ns.as_ref()),
                                proto_value_type(value, &paths, ns.as_ref()),
                            ),
                        );
                    }
                }
            }
        }
        Registry {
            by_mod,
            paths,
            maps,
            emitted_names,
        }
    }

    fn emitted_name(&self, cur_ns: &str, raw: &str) -> Option<&str> {
        self.emitted_names
            .get(cur_ns)
            .and_then(|names| names.get(raw))
            .map(String::as_str)
    }

    /// Resolve a proto type_name (`.pkg.Outer.Inner`) to interned
    /// `pb::<mod>::<Name>`, preferring the referencing message's own module.
    fn resolve(&self, type_name: &str, cur_ns: &str) -> Option<&str> {
        let flattened = flatten_proto_name(type_name);
        let flat = sanitize(flattened.as_ref());
        if let Some(path) = self.by_mod.get(cur_ns).and_then(|s| s.get(flat.as_ref())) {
            return Some(path.as_ref());
        }
        self.paths.get(flat.as_ref()).map(|path| path.as_ref())
    }

    fn map_types(&self, type_name: &str, cur_ns: &str) -> Option<(&str, &str)> {
        let flattened = flatten_proto_name(type_name);
        let flat = sanitize(flattened.as_ref());
        self.maps
            .get(cur_ns)
            .and_then(|by_name| by_name.get(flat.as_ref()))
            .or_else(|| {
                self.maps
                    .values()
                    .find_map(|by_name| by_name.get(flat.as_ref()))
            })
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

fn proto_value_type(f: &ProtoField, paths: &BTreeMap<String, Arc<str>>, cur_ns: &str) -> String {
    if let Some((ty, _)) = scalar(f) {
        return ty.to_string();
    }
    match f.ty {
        9 | 12 => "pb::string_t".to_string(),
        10 | 11 => {
            let flattened = flatten_proto_name(&f.type_name);
            let flat = sanitize(flattened.as_ref());
            paths
                .get(flat.as_ref())
                .map(|path| format!("{path}*"))
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
fn repeated_elem<'a>(f: &ProtoField, reg: &'a Registry, cur_ns: &'a str) -> (Cow<'a, str>, bool) {
    match f.ty {
        1 => (Cow::Borrowed("double"), false),
        2 => (Cow::Borrowed("float"), false),
        3 | 16 | 18 => (Cow::Borrowed("int64_t"), false),
        4 | 6 => (Cow::Borrowed("uint64_t"), false),
        5 | 15 | 17 => (Cow::Borrowed("int32_t"), false),
        7 | 13 => (Cow::Borrowed("uint32_t"), false),
        8 => (Cow::Borrowed("bool"), false),
        14 => (Cow::Borrowed("int32_t"), false),
        9 | 12 => (Cow::Borrowed("pb::string_t"), true),
        10 | 11 => (
            Cow::Borrowed(reg.resolve(&f.type_name, cur_ns).unwrap_or("void")),
            true,
        ),
        _ => (Cow::Borrowed("void"), true),
    }
}

enum MemberTy<'a> {
    Scalar(&'static str),
    PathPtr(&'a str),
    Repeated { ptr: bool, elem: Cow<'a, str> },
    Map { key: &'a str, value: &'a str },
}

impl fmt::Display for MemberTy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scalar(ty) => f.write_str(ty),
            Self::PathPtr(path) => {
                f.write_str(path)?;
                f.write_str("*")
            }
            Self::Repeated { ptr, elem } => {
                f.write_str(if *ptr {
                    "pb::RepeatedPtrField<"
                } else {
                    "pb::RepeatedField<"
                })?;
                f.write_str(elem)?;
                f.write_str(">")
            }
            Self::Map { key, value } => {
                f.write_str("pb::MapField<")?;
                f.write_str(key)?;
                f.write_str(", ")?;
                f.write_str(value)?;
                f.write_str(">")
            }
        }
    }
}

struct ProtoTy<'a> {
    repeated: bool,
    base: &'static str,
    type_name: &'a str,
}

impl std::fmt::Display for ProtoTy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.repeated {
            f.write_str("repeated ")?;
        }
        f.write_str(self.base)?;
        if !self.type_name.is_empty() {
            write!(
                f,
                " {}",
                comment_text(self.type_name.trim_start_matches('.'))
            )?;
        }
        Ok(())
    }
}

/// Human-readable proto type for the trailing comment.
fn proto_ty(f: &ProtoField) -> ProtoTy<'_> {
    ProtoTy {
        repeated: f.label == 3,
        base: match f.ty {
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
        },
        type_name: f.type_name.as_str(),
    }
}

/// The C++ member declaration (type only, no name) and its byte size for a
/// field, given the slot available before the next field. `None` → emit a raw
/// byte slot (slot too small for the natural type).
fn member_type<'a>(
    f: &ProtoField,
    reg: &'a Registry,
    cur_ns: &'a str,
    slot: u32,
) -> Option<(MemberTy<'a>, u32)> {
    if f.label == 3 {
        // repeated: RepeatedField<T> (scalar) / RepeatedPtrField<T> (msg/string), 0x18.
        if slot >= 0x18 {
            if f.is_map {
                let (key, value) = reg
                    .map_types(&f.type_name, cur_ns)
                    .unwrap_or(("void", "void"));
                return Some((MemberTy::Map { key, value }, 0x18));
            }
            let (elem, ptr) = repeated_elem(f, reg, cur_ns);
            return Some((MemberTy::Repeated { ptr, elem }, 0x18));
        }
        return None;
    }
    if let Some((ty, sz)) = scalar(f) {
        return (sz <= slot).then_some((MemberTy::Scalar(ty), sz));
    }
    match f.ty {
        9 | 12 => (slot >= 8).then_some((MemberTy::Scalar("pb::string_t*"), 8)),
        10 | 11 => (slot >= 8).then(|| match reg.resolve(&f.type_name, cur_ns) {
            Some(path) => (MemberTy::PathPtr(path), 8),
            None => (MemberTy::Scalar("void*"), 8),
        }),
        _ => None,
    }
}

fn struct_block(m: &ProtoMessage, name: &str, cur_ns: &str, reg: &Registry) -> String {
    let size = m.size;
    let mut s = String::new();

    // Fields in memory order; drop ones at/after object end. Oneof members
    // intentionally remain grouped so the generated C++ preserves the union
    // semantics instead of silently keeping only the first field.
    let mut fields: Vec<&ProtoField> = m.fields.iter().filter(|f| f.offset < size).collect();
    if !fields
        .windows(2)
        .all(|pair| pair[0].offset <= pair[1].offset)
    {
        fields.sort_by_key(|f| f.offset);
    }

    writeln!(s, "#pragma pack(push, 1)").ok();
    match m.has_bits_offset {
        Some(o) => writeln!(
            s,
            "struct {name} {{ // sizeof {size:#x}, _has_bits_ @ {o:#x}"
        )
        .ok(),
        None => writeln!(s, "struct {name} {{ // sizeof {size:#x}, no _has_bits_").ok(),
    };

    let mut asserts = String::new();

    if fields.is_empty() {
        if size > 0 {
            writeln!(s, "    uint8_t _data[{size:#x}];").ok();
        }
    } else {
        let mut cursor: u32 = 0;
        let mut field_names = IdentifierAllocator::default();
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
                    let fname = field_names.allocate(sanitize(&member.name).into_owned());
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

            let fname = field_names.allocate(sanitize(&f.name).into_owned());
            match member_type(f, reg, cur_ns, slot) {
                Some((ty, sz)) => {
                    match f.has_bit {
                        Some(b) => writeln!(
                            s,
                            "    {ty} {fname}; // #{} {}, has-bit {b}",
                            f.number,
                            proto_ty(f),
                        )
                        .ok(),
                        None => writeln!(
                            s,
                            "    {ty} {fname}; // #{} {}, no has-bit",
                            f.number,
                            proto_ty(f),
                        )
                        .ok(),
                    };
                    if slot > sz {
                        writeln!(s, "    uint8_t _pad_{:x}[{:#x}];", off + sz, slot - sz).ok();
                    }
                }
                None => {
                    match f.has_bit {
                        Some(b) => writeln!(
                            s,
                            "    uint8_t {fname}[{slot:#x}]; // #{} {}, has-bit {b}",
                            f.number,
                            proto_ty(f),
                        )
                        .ok(),
                        None => writeln!(
                            s,
                            "    uint8_t {fname}[{slot:#x}]; // #{} {}, no has-bit",
                            f.number,
                            proto_ty(f),
                        )
                        .ok(),
                    };
                }
            }
            let _ = writeln!(
                asserts,
                "static_assert(offsetof({name}, {fname}) == {off:#x});"
            );
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
    s.push_str(&asserts);
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
            if m.size == 0 || !seen.insert(m.name.as_str()) {
                continue;
            }
            if let Some(n) = reg.emitted_name(ns.as_ref(), &m.name) {
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
            if m.size == 0 || !seen.insert(m.name.as_str()) {
                continue;
            }
            if let Some(name) = reg.emitted_name(ns.as_ref(), &m.name) {
                s.push_str(&struct_block(m, name, &ns, &reg));
            }
        }
        writeln!(s, "}} // namespace pb::{}\n", ns).ok();
    }
    s
}

pub fn render_json(map: &ProtobufMap) -> Result<String, serde_json::Error> {
    let mut root = serde_json::Map::new();
    for (module, messages) in map {
        if messages.is_empty() {
            continue;
        }
        let mut msgs = serde_json::Map::new();
        for m in messages {
            let mut fields = serde_json::Map::new();
            for f in &m.fields {
                fields.insert(
                    f.name.clone(),
                    serde_json::json!({
                        "offset": f.offset,
                        "number": f.number,
                        "has_bit": f.has_bit.map(|b| b as i64).unwrap_or(-1),
                        "type": f.ty,
                        "label": f.label,
                        "oneof": f.oneof,
                        "is_map": f.is_map,
                    }),
                );
            }
            msgs.insert(
                m.name.clone(),
                serde_json::json!({
                    "size": m.size,
                    "map_entry": m.map_entry,
                    "has_bits_offset": m.has_bits_offset.map(|o| o as i64).unwrap_or(-1),
                    "fields": fields,
                }),
            );
        }
        root.insert(module.clone(), serde_json::Value::Object(msgs));
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(root))
}

#[cfg(test)]
mod tests {
    use super::{render_hpp, render_json, sanitize};
    use crate::analysis::{ProtoField, ProtoMessage, ProtobufMap};

    #[test]
    fn sanitizer_uses_current_cpp_keywords() {
        assert_eq!(sanitize("consteval").as_ref(), "consteval_");
        assert_eq!(sanitize("char8_t").as_ref(), "char8_t_");
        assert_eq!(sanitize("co_await").as_ref(), "co_await_");
        assert_eq!(sanitize("message-name").as_ref(), "message_name");
    }

    #[test]
    fn hpp_disambiguates_message_and_field_name_collisions() {
        let mut map = ProtobufMap::new();
        map.insert(
            "client.dll".into(),
            vec![
                ProtoMessage {
                    name: "message-name".into(),
                    size: 0x10,
                    has_bits_offset: None,
                    map_entry: false,
                    fields: Vec::new(),
                },
                ProtoMessage {
                    name: "message_name".into(),
                    size: 0x18,
                    has_bits_offset: None,
                    map_entry: false,
                    fields: vec![
                        ProtoField {
                            name: "field-name".into(),
                            number: 1,
                            offset: 0x10,
                            has_bit: None,
                            label: 1,
                            ty: 5,
                            type_name: "Injected\n#define TYPE_INJECTED 1".into(),
                            is_map: false,
                            oneof: None,
                        },
                        ProtoField {
                            name: "field_name".into(),
                            number: 2,
                            offset: 0x14,
                            has_bit: None,
                            label: 1,
                            ty: 5,
                            type_name: String::new(),
                            is_map: false,
                            oneof: None,
                        },
                    ],
                },
            ],
        );
        let hpp = render_hpp(&map, None);
        assert!(hpp.contains("struct message_name;"), "{hpp}");
        assert!(hpp.contains("struct message_name_2;"), "{hpp}");
        assert!(hpp.contains("int32_t field_name;"), "{hpp}");
        assert!(hpp.contains("int32_t field_name_2;"), "{hpp}");
        assert!(!hpp.contains("\n#define"), "type text escaped a comment: {hpp}");
    }

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
        let json = render_json(&map).expect("serialize");
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
        let json = render_json(&map).expect("serialize");
        assert!(json.contains("\"map_entry\": true"));
        assert!(json.contains("\"is_map\": true"));
    }

    #[test]
    fn message_pointer_uses_interned_pb_path() {
        let mut map = ProtobufMap::new();
        map.insert(
            "client.dll".into(),
            vec![
                ProtoMessage {
                    name: "Child".into(),
                    size: 0x10,
                    has_bits_offset: None,
                    map_entry: false,
                    fields: vec![],
                },
                ProtoMessage {
                    name: "Parent".into(),
                    size: 0x18,
                    has_bits_offset: None,
                    map_entry: false,
                    fields: vec![ProtoField {
                        name: "child".into(),
                        number: 1,
                        offset: 0x10,
                        has_bit: None,
                        label: 1,
                        ty: 11,
                        type_name: ".Child".into(),
                        is_map: false,
                        oneof: None,
                    }],
                },
            ],
        );
        let hpp = render_hpp(&map, None);
        assert!(hpp.contains("pb::client::Child* child"));
        assert!(hpp.contains("struct Child"));
    }
}
