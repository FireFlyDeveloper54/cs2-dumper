//! Optional packed C++ structs (`--guess-structs`).
//!
//! Schema gives field offsets, not padding. Primitive/pointer sizes are known;
//! everything else uses the most common gap to the next field (best-dumper
//! voting). Explicit `_pad_*` fills holes so `pack(1)` layout matches offsets.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::analysis::{Class, ClassField, SchemaMap};

use super::ident::{cpp_identifier, IdentifierAllocator};
use super::comment_text;

pub fn render_hpp(schemas: &SchemaMap, build_number: Option<u32>) -> String {
    let votes = vote_unknown_sizes(schemas);
    let mut s = String::new();
    writeln!(s, "#pragma once").ok();
    writeln!(s, "// Generated with --guess-structs.").ok();
    writeln!(
        s,
        "// Primitive/pointer sizes are known. Other types use the most common"
    )
    .ok();
    writeln!(
        s,
        "// field-to-field gap and may swallow padding. Prefer SCHEMA_FIELD."
    )
    .ok();
    if let Some(build) = build_number {
        writeln!(s, "// CS2_BUILD {build}").ok();
    }
    writeln!(s, "#include <cstdint>\n").ok();
    writeln!(s, "#pragma pack(push, 1)").ok();
    writeln!(s, "namespace guessed {{\n").ok();

    let mut modules: Vec<_> = schemas.iter().collect();
    modules.sort_by(|a, b| a.0.cmp(b.0));
    for (module, (classes, _)) in modules {
        let ns = cpp_identifier(module.trim_end_matches(".dll"));
        writeln!(s, "namespace {ns} {{\n").ok();
        let mut class_names = IdentifierAllocator::default();
        for class in classes {
            write_class(&mut s, class, &votes, &mut class_names);
        }
        writeln!(s, "}} // namespace {ns}\n").ok();
    }

    writeln!(s, "}} // namespace guessed").ok();
    writeln!(s, "#pragma pack(pop)").ok();
    s
}

fn write_class(
    out: &mut String,
    class: &Class,
    votes: &BTreeMap<String, i32>,
    class_names: &mut IdentifierAllocator,
) {
    let mut fields: Vec<&ClassField> = class.fields.iter().collect();
    if fields.is_empty() {
        return;
    }
    fields.sort_by_key(|f| f.offset);
    let ident_src = class.name.replace("::", "_");
    let name = class_names.allocate(cpp_identifier(&ident_src));
    writeln!(out, "struct {name} {{").ok();

    let mut cursor = 0i32;
    let mut pad_i = 0usize;
    let mut field_names = IdentifierAllocator::default();
    let class_end = class.size.max(0);
    for field in &fields {
        if field.offset < 0 {
            continue;
        }
        if field.offset > cursor {
            writeln!(
                out,
                "    std::uint8_t _pad_{pad_i}[0x{:X}];",
                field.offset - cursor
            )
            .ok();
            pad_i += 1;
        } else if field.offset < cursor {
            writeln!(
                out,
                "    // overlap skipped: {} at 0x{:X} (cursor 0x{cursor:X})",
                comment_text(&field.name),
                field.offset
            )
            .ok();
            continue;
        }

        let gap = next_gap(&fields, field.offset, class_end);
        let (cpp, size, how) = field_layout(&field.type_name, gap, votes);
        let field_name = field_names.allocate(cpp_identifier(&field.name));
        let decl = cpp_decl(&cpp, &field_name);
        writeln!(
            out,
            "    {decl}; // +0x{:X} {how} ({})",
            field.offset,
            comment_text(&field.type_name)
        )
        .ok();
        cursor = field.offset + size.max(0);
    }
    if class_end > cursor {
        writeln!(
            out,
            "    std::uint8_t _pad_{pad_i}[0x{:X}];",
            class_end - cursor
        )
        .ok();
    }
    writeln!(out, "}};").ok();
    if class_end > 0 {
        writeln!(
            out,
            "static_assert(sizeof({name}) == 0x{class_end:X}, \"guessed {name} size\");"
        )
        .ok();
    }
    writeln!(out).ok();
}

fn next_gap(fields: &[&ClassField], offset: i32, class_end: i32) -> i32 {
    fields
        .iter()
        .map(|f| f.offset)
        .filter(|next| *next > offset)
        .min()
        .unwrap_or(class_end)
        .saturating_sub(offset)
}

fn field_layout(
    type_name: &str,
    gap: i32,
    votes: &BTreeMap<String, i32>,
) -> (String, i32, &'static str) {
    let key = normalize(type_name);
    if let Some(size) = known_size(key.as_ref()) {
        let size = if gap > 0 { size.min(gap) } else { size };
        return (cpp_type(key.as_ref(), size), size, "known");
    }
    if let Some(&vote) = votes.get(key.as_ref()) {
        let size = if gap > 0 {
            vote.min(gap).max(1)
        } else {
            vote.max(1)
        };
        return (array_or_byte(size), size, "guessed");
    }
    let size = if gap > 0 { gap } else { 1 };
    (array_or_byte(size), size, "gap")
}

fn cpp_decl(cpp: &str, name: &str) -> String {
    if let Some(bracket) = cpp.find('[') {
        format!("{} {}{}", &cpp[..bracket], name, &cpp[bracket..])
    } else {
        format!("{cpp} {name}")
    }
}

fn array_or_byte(size: i32) -> String {
    if size == 1 {
        "std::uint8_t".into()
    } else {
        format!("std::uint8_t[{size}]")
    }
}

fn cpp_type(key: &str, size: i32) -> String {
    if key.ends_with('*') {
        return "void*".into();
    }
    if key.starts_with("CHandle") || key == "CEntityHandle" {
        return "std::uint32_t".into();
    }
    match key {
        "bool" => "bool".into(),
        "int8" | "int8_t" => "std::int8_t".into(),
        "uint8" | "uint8_t" | "unsignedchar" => "std::uint8_t".into(),
        "int16" | "int16_t" => "std::int16_t".into(),
        "uint16" | "uint16_t" => "std::uint16_t".into(),
        "int32" | "int32_t" | "int" => "std::int32_t".into(),
        "uint32" | "uint32_t" | "unsignedint" => "std::uint32_t".into(),
        "int64" | "int64_t" => "std::int64_t".into(),
        "uint64" | "uint64_t" => "std::uint64_t".into(),
        "float" | "float32" | "GameTime_t" => "float".into(),
        "float64" | "double" => "double".into(),
        "Vector" | "QAngle" => "float[3]".into(),
        "Vector2D" => "float[2]".into(),
        "Vector4D" | "Quaternion" => "float[4]".into(),
        _ => array_or_byte(size),
    }
}

fn known_size(key: &str) -> Option<i32> {
    if key.ends_with('*') {
        return Some(8);
    }
    if let Some(bits) = key.strip_prefix("bitfield:") {
        let bits: i32 = bits.parse().unwrap_or(8);
        return Some(((bits + 7) / 8).max(1));
    }
    if key.starts_with("CHandle") || key == "CEntityHandle" {
        return Some(4);
    }
    Some(match key {
        "bool" | "int8" | "int8_t" | "uint8" | "uint8_t" | "unsignedchar" | "char" => 1,
        "int16" | "int16_t" | "uint16" | "uint16_t" => 2,
        "int32" | "int32_t" | "int" | "uint32" | "uint32_t" | "unsignedint" | "float"
        | "float32" | "GameTime_t" | "GameTick_t" | "CUtlStringToken" => 4,
        "int64" | "int64_t" | "uint64" | "uint64_t" | "float64" | "double" => 8,
        "Vector2D" => 8,
        "Vector" | "QAngle" => 12,
        "Vector4D" | "Quaternion" => 16,
        _ => return None,
    })
}

fn normalize(raw: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = raw.trim();
    if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
        std::borrow::Cow::Owned(trimmed.split_whitespace().collect())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

fn vote_unknown_sizes(schemas: &SchemaMap) -> BTreeMap<String, i32> {
    let mut samples: BTreeMap<String, BTreeMap<i32, usize>> = BTreeMap::new();
    for (classes, _) in schemas.values() {
        for class in classes {
            let mut fields: Vec<&ClassField> = class.fields.iter().collect();
            fields.sort_by_key(|f| f.offset);
            let end = class.size.max(0);
            for field in &fields {
                let key = normalize(&field.type_name);
                if known_size(key.as_ref()).is_some() {
                    continue;
                }
                let gap = next_gap(&fields, field.offset, end);
                if gap <= 0 || gap >= 4096 {
                    continue;
                }
                *samples
                    .entry(key.into_owned())
                    .or_default()
                    .entry(gap)
                    .or_default() += 1;
            }
        }
    }
    samples
        .into_iter()
        .filter_map(|(ty, counts)| {
            counts
                .into_iter()
                .max_by_key(|(size, n)| (*n, -size))
                .map(|(size, _)| (ty, size))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{field_layout, known_size, render_hpp, vote_unknown_sizes};
    use crate::analysis::{Class, ClassField, SchemaMap};
    use std::collections::BTreeMap;

    fn field(name: &str, ty: &str, offset: i32) -> ClassField {
        ClassField {
            name: name.into(),
            type_name: ty.into(),
            offset,
            metadata: Vec::new(),
        }
    }

    fn class(name: &str, size: i32, fields: Vec<ClassField>) -> Class {
        Class {
            name: name.into(),
            module_name: "client.dll".into(),
            parent_name: None,
            size,
            alignment: 8,
            metadata: Vec::new(),
            fields,
            static_fields: Vec::new(),
            flags: Vec::new(),
        }
    }

    #[test]
    fn known_int32_does_not_swallow_following_padding() {
        let (cpp, size, how) = field_layout("int32", 8, &BTreeMap::new());
        assert_eq!(cpp, "std::int32_t");
        assert_eq!(size, 4);
        assert_eq!(how, "known");
        assert_eq!(known_size("CHandle<C_BaseEntity>"), Some(4));
        assert_eq!(known_size("C_BaseEntity*"), Some(8));
    }

    #[test]
    fn votes_unknown_type_size_from_field_gaps() {
        let schemas = SchemaMap::from([(
            "client.dll".into(),
            (
                vec![class(
                    "C_Test",
                    0x18,
                    vec![field("a", "Mystery_t", 0x0), field("b", "int32", 0x10)],
                )],
                Vec::new(),
            ),
        )]);
        let votes = vote_unknown_sizes(&schemas);
        assert_eq!(votes.get("Mystery_t"), Some(&0x10));
        let hpp = render_hpp(&schemas, Some(1));
        assert!(hpp.contains("#pragma pack(push, 1)"));
        assert!(hpp.contains("guessed"));
        assert!(hpp.contains("static_assert(sizeof(C_Test) == 0x18"));
        assert!(hpp.contains("_pad_"));
    }

    #[test]
    fn guessed_structs_disambiguate_sanitized_class_and_field_names() {
        let schemas = SchemaMap::from([(
            "client.dll".into(),
            (
                vec![
                    class(
                        "C-Test",
                        8,
                        vec![field("", "int32", 0), field("int", "int32", 4)],
                    ),
                    class("C_Test", 4, vec![field("x", "int32", 0)]),
                ],
                Vec::new(),
            ),
        )]);
        let hpp = render_hpp(&schemas, None);
        assert!(hpp.contains("struct C_Test {"), "first sanitized name: {hpp}");
        assert!(
            hpp.contains("struct C_Test_2 {"),
            "colliding class name must be allocated: {hpp}"
        );
        assert!(hpp.contains("anonymous"), "empty field name: {hpp}");
        assert!(hpp.contains("_int"), "keyword field name: {hpp}");
    }
}
