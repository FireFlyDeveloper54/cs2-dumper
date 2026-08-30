use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{self, Write};

use heck::{AsPascalCase, AsSnakeCase};

use serde_json::json;

use super::{CodeWriter, Formatter, SchemaMap, comment_text, slugify, zig_ident};

use crate::analysis::{Class, ClassMetadata, Enum, EnumMember};

use super::ident::{
    IdentifierAllocator, cpp_identifier, csharp_identifier, rust_identifier, unique_slug,
};

/// One schema module, borrowed from the live dump map so per-file emit does
/// not clone class/enum vectors.
pub(crate) struct SchemaModule<'a> {
    pub module_name: &'a str,
    pub classes: &'a [Class],
    pub enums: &'a [Enum],
}

impl SchemaModule<'_> {
    fn write_cs_body(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "// Module: {}", comment_text(self.module_name))?;
        writeln!(fmt, "// Class count: {}", self.classes.len())?;
        writeln!(fmt, "// Enum count: {}", self.enums.len())?;

        fmt.block(
            format_args!(
                "public static class {}",
                AsPascalCase(csharp_identifier(self.module_name))
            ),
            false,
            |fmt| {
                let mut declarations = IdentifierAllocator::default();
                for enum_ in self.enums {
                    let type_name = match enum_.storage_bytes() {
                        1 => "byte",
                        2 => "ushort",
                        4 => "uint",
                        8 => "ulong",
                        _ => continue,
                    };

                    writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                    writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                    let enum_name = declarations.allocate(csharp_identifier(&enum_.name));
                    fmt.block(
                        format_args!("public enum {enum_name} : {type_name}"),
                        false,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            let last = enum_.members.len().saturating_sub(1);
                            for (i, member) in enum_.members.iter().enumerate() {
                                let comma = if i == last { "" } else { "," };
                                writeln!(
                                    fmt,
                                    "{} = {:#X}{}",
                                    names.allocate(csharp_identifier(&member.name)),
                                    super::cpp_types::enum_value_masked(member.value, type_name),
                                    comma
                                )?;
                            }
                            Ok(())
                        },
                    )?;
                }

                for class in self.classes {
                    write_parent_comment(fmt, class.parent_name.as_deref())?;
                    writeln!(fmt, "// Field count: {}", class.fields.len())?;

                    write_metadata(fmt, &class.metadata)?;

                    let class_name = declarations.allocate(csharp_identifier(&class.name));
                    fmt.block(
                        format_args!("public static class {class_name}"),
                        false,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            for field in &class.fields {
                                writeln!(
                                    fmt,
                                    "public const nint {} = {:#X}; // {}",
                                    names.allocate(csharp_identifier(&field.name)),
                                    field.offset,
                                    comment_text(&field.type_name)
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            },
        )
    }

    fn write_hpp_body(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "// Module: {}", comment_text(self.module_name))?;
        writeln!(fmt, "// Class count: {}", self.classes.len())?;
        writeln!(fmt, "// Enum count: {}", self.enums.len())?;

        fmt.block(
            format_args!(
                "namespace {}",
                cpp_identifier(&AsSnakeCase(slugify(self.module_name)).to_string())
            ),
            false,
            |fmt| {
                let mut declarations = IdentifierAllocator::default();
                for enum_ in self.enums {
                    let type_name = match enum_.storage_bytes() {
                        1 => "uint8_t",
                        2 => "uint16_t",
                        4 => "uint32_t",
                        8 => "uint64_t",
                        _ => continue,
                    };

                    writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                    writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                    let enum_name = declarations.allocate(cpp_identifier(&enum_.name));
                    fmt.block(
                        format_args!("enum class {enum_name} : {type_name}"),
                        true,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            let last = enum_.members.len().saturating_sub(1);
                            for (i, member) in enum_.members.iter().enumerate() {
                                let comma = if i == last { "" } else { "," };
                                writeln!(
                                    fmt,
                                    "{} = {:#X}{}",
                                    names.allocate(cpp_identifier(&member.name)),
                                    super::cpp_types::enum_value_masked(member.value, type_name),
                                    comma
                                )?;
                            }
                            Ok(())
                        },
                    )?;
                }

                for class in self.classes {
                    write_parent_comment(fmt, class.parent_name.as_deref())?;
                    writeln!(fmt, "// Field count: {}", class.fields.len())?;

                    write_metadata(fmt, &class.metadata)?;

                    let class_name = declarations.allocate(cpp_identifier(&class.name));
                    fmt.block(format_args!("namespace {class_name}"), false, |fmt| {
                        let mut names = IdentifierAllocator::default();
                        for field in &class.fields {
                            writeln!(
                                fmt,
                                "constexpr std::ptrdiff_t {} = {:#X}; // {}",
                                names.allocate(cpp_identifier(&field.name)),
                                field.offset,
                                comment_text(&field.type_name)
                            )?;
                        }

                        Ok(())
                    })?;
                }

                Ok(())
            },
        )
    }

    fn json_value(&self) -> serde_json::Value {
        let mut class_keys = BTreeSet::new();
        let classes: BTreeMap<_, _> = self
            .classes
            .iter()
            .map(|class| {
                let fields: BTreeMap<_, _> = class
                    .fields
                    .iter()
                    .map(|field| (&field.name, field.offset))
                    .collect();

                let metadata: Vec<_> = class
                    .metadata
                    .iter()
                    .map(|metadata| match metadata {
                        ClassMetadata::NetworkChangeCallback { name } => json!({
                            "type": "NetworkChangeCallback",
                            "name": name,
                        }),
                        ClassMetadata::NetworkVarNames { name, type_name } => json!({
                            "type": "NetworkVarNames",
                            "name": name,
                            "type_name": type_name,
                        }),
                        ClassMetadata::Unknown { name } => json!({
                            "type": "Unknown",
                            "name": name,
                        }),
                    })
                    .collect();

                let mut value = json!({
                    "parent": class.parent_name,
                    "fields": fields,
                    "metadata": metadata
                });

                if !class.static_fields.is_empty() {
                    let statics: Vec<_> = class
                        .static_fields
                        .iter()
                        .map(|field| {
                            json!({
                                "name": field.name,
                                "type_name": field.type_name,
                                "index": field.index,
                            })
                        })
                        .collect();
                    value["static_fields"] = json!(statics);
                }
                if !class.flags.is_empty() {
                    value["flags"] = json!(class.flags);
                }

                (unique_slug(&class.name, &mut class_keys), value)
            })
            .collect();

        let mut enum_keys = BTreeSet::new();
        let enums: BTreeMap<_, _> = self
            .enums
            .iter()
            .map(|enum_| {
                let members: BTreeMap<_, _> = enum_
                    .members
                    .iter()
                    .map(|member| (&member.name, member.value))
                    .collect();

                let type_name = match enum_.storage_bytes() {
                    1 => "uint8",
                    2 => "uint16",
                    4 => "uint32",
                    8 => "uint64",
                    _ => "unknown",
                };

                (
                    unique_slug(&enum_.name, &mut enum_keys),
                    json!({
                        "size": enum_.size,
                        "alignment": enum_.alignment,
                        "type": type_name,
                        "members": members,
                    }),
                )
            })
            .collect();

        json!({
            "classes": classes,
            "enums": enums,
        })
    }

    fn write_rs_body(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "// Module: {}", comment_text(self.module_name))?;
        writeln!(fmt, "// Class count: {}", self.classes.len())?;
        writeln!(fmt, "// Enum count: {}", self.enums.len())?;

        fmt.block(
            format_args!(
                "pub mod {}",
                rust_identifier(&AsSnakeCase(slugify(self.module_name)).to_string())
            ),
            false,
            |fmt| {
                let mut declarations = IdentifierAllocator::default();
                for enum_ in self.enums {
                    let type_name = match enum_.storage_bytes() {
                        1 => "u8",
                        2 => "u16",
                        4 => "u32",
                        8 => "u64",
                        _ => continue,
                    };

                    writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                    writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                    let enum_name = declarations.allocate(rust_identifier(&enum_.name));
                    fmt.block(
                        format_args!("#[repr({})]\npub enum {}", type_name, enum_name),
                        false,
                        |fmt| {
                            let members = unique_enum_members_masked(&enum_.members, type_name);
                            let mut names = IdentifierAllocator::default();
                            let last = members.len().saturating_sub(1);
                            for (i, member) in members.iter().enumerate() {
                                let comma = if i == last { "" } else { "," };
                                writeln!(
                                    fmt,
                                    "{} = {:#X}{}",
                                    names.allocate(rust_identifier(&member.name)),
                                    super::cpp_types::enum_value_masked(member.value, type_name),
                                    comma
                                )?;
                            }
                            Ok(())
                        },
                    )?;
                }

                for class in self.classes {
                    write_parent_comment(fmt, class.parent_name.as_deref())?;
                    writeln!(fmt, "// Field count: {}", class.fields.len())?;

                    write_metadata(fmt, &class.metadata)?;

                    let class_name = declarations.allocate(rust_identifier(&class.name));
                    fmt.block(format_args!("pub mod {class_name}"), false, |fmt| {
                        let mut names = IdentifierAllocator::default();
                        for field in &class.fields {
                            writeln!(
                                fmt,
                                "pub const {}: usize = {:#X}; // {}",
                                names.allocate(rust_identifier(&field.name)),
                                field.offset,
                                comment_text(&field.type_name)
                            )?;
                        }

                        Ok(())
                    })?;
                }

                Ok(())
            },
        )
    }

    fn write_zig_body(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "// Module: {}", comment_text(self.module_name))?;
        writeln!(fmt, "// Class count: {}", self.classes.len())?;
        writeln!(fmt, "// Enum count: {}", self.enums.len())?;

        let snake = AsSnakeCase(slugify(self.module_name).as_ref()).to_string();
        let module_name = zig_ident(&snake);

        fmt.block(
            format_args!("pub const {} = struct", module_name),
            true,
            |fmt| {
                let mut declarations = IdentifierAllocator::default();
                for enum_ in self.enums {
                    let type_name = match enum_.storage_bytes() {
                        1 => "u8",
                        2 => "u16",
                        4 => "u32",
                        8 => "u64",
                        _ => continue,
                    };

                    writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                    writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                    let enum_name = declarations.allocate(slugify(&enum_.name).into_owned());
                    let enum_name = zig_ident(&enum_name);

                    fmt.block(
                        format_args!("pub const {} = enum({})", enum_name, type_name),
                        true,
                        |fmt| {
                            let members = unique_enum_members_masked(&enum_.members, type_name);
                            let mut names = IdentifierAllocator::default();
                            let last = members.len().saturating_sub(1);
                            for (i, member) in members.iter().enumerate() {
                                let comma = if i == last { "" } else { "," };
                                writeln!(
                                    fmt,
                                    "{} = {}{}",
                                    zig_ident(&names.allocate(slugify(&member.name).into_owned())),
                                    format_zig_enum_member_value(member.value, type_name),
                                    comma
                                )?;
                            }
                            Ok(())
                        },
                    )?;
                }

                for class in self.classes {
                    write_parent_comment(fmt, class.parent_name.as_deref())?;
                    writeln!(fmt, "// Field count: {}", class.fields.len())?;

                    write_metadata(fmt, &class.metadata)?;

                    let class_name = declarations.allocate(slugify(&class.name).into_owned());
                    let class_name = zig_ident(&class_name);

                    fmt.block(
                        format_args!("pub const {} = struct", class_name),
                        true,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            for field in &class.fields {
                                writeln!(
                                    fmt,
                                    "pub const {}: usize = {:#X}; // {}",
                                    zig_ident(&names.allocate(slugify(&field.name).into_owned())),
                                    field.offset,
                                    comment_text(&field.type_name)
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl CodeWriter for SchemaModule<'_> {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace CS2Dumper.Schemas", false, |fmt| {
            self.write_cs_body(fmt)
        })
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#pragma once\n")?;
        writeln!(fmt, "#include <cstddef>")?;
        writeln!(fmt, "#include <cstdint>\n")?;

        fmt.block("namespace cs2_dumper", false, |fmt| {
            fmt.block("namespace schemas", false, |fmt| self.write_hpp_body(fmt))
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content = BTreeMap::from([(self.module_name, self.json_value())]);
        super::formatter::write_pretty_json(fmt, &content)
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            fmt,
            "#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]\n"
        )?;

        fmt.block("pub mod cs2_dumper", false, |fmt| {
            fmt.block("pub mod schemas", false, |fmt| self.write_rs_body(fmt))
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const cs2_dumper = struct", true, |fmt| {
            fmt.block("pub const schemas = struct", true, |fmt| {
                self.write_zig_body(fmt)
            })
        })
    }
}

impl CodeWriter for SchemaMap {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace CS2Dumper.Schemas", false, |fmt| {
            for (module_name, (classes, enums)) in self {
                SchemaModule {
                    module_name,
                    classes,
                    enums,
                }
                .write_cs_body(fmt)?;
            }
            Ok(())
        })
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#pragma once\n")?;
        writeln!(fmt, "#include <cstddef>")?;
        writeln!(fmt, "#include <cstdint>\n")?;

        fmt.block("namespace cs2_dumper", false, |fmt| {
            fmt.block("namespace schemas", false, |fmt| {
                for (module_name, (classes, enums)) in self {
                    SchemaModule {
                        module_name,
                        classes,
                        enums,
                    }
                    .write_hpp_body(fmt)?;
                }
                Ok(())
            })
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content: BTreeMap<_, _> = self
            .iter()
            .map(|(module_name, (classes, enums))| {
                (
                    module_name,
                    SchemaModule {
                        module_name,
                        classes,
                        enums,
                    }
                    .json_value(),
                )
            })
            .collect();
        super::formatter::write_pretty_json(fmt, &content)
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            fmt,
            "#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]\n"
        )?;

        fmt.block("pub mod cs2_dumper", false, |fmt| {
            fmt.block("pub mod schemas", false, |fmt| {
                for (module_name, (classes, enums)) in self {
                    SchemaModule {
                        module_name,
                        classes,
                        enums,
                    }
                    .write_rs_body(fmt)?;
                }
                Ok(())
            })
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const cs2_dumper = struct", true, |fmt| {
            fmt.block("pub const schemas = struct", true, |fmt| {
                for (module_name, (classes, enums)) in self {
                    SchemaModule {
                        module_name,
                        classes,
                        enums,
                    }
                    .write_zig_body(fmt)?;
                }
                Ok(())
            })
        })
    }
}

fn unique_enum_members_masked<'a>(members: &'a [EnumMember], storage: &str) -> Vec<&'a EnumMember> {
    let mut used_values = HashSet::new();
    members
        .iter()
        .filter(|member| {
            used_values.insert(super::cpp_types::enum_value_masked(member.value, storage))
        })
        .collect()
}

fn write_parent_comment(fmt: &mut Formatter<'_>, parent: Option<&str>) -> fmt::Result {
    match parent {
        Some(name) => writeln!(fmt, "// Parent: {}", slugify(name)),
        None => writeln!(fmt, "// Parent: None"),
    }
}

fn write_metadata(fmt: &mut Formatter<'_>, metadata: &[ClassMetadata]) -> fmt::Result {
    if metadata.is_empty() {
        return Ok(());
    }

    writeln!(fmt, "//")?;
    writeln!(fmt, "// Metadata:")?;

    for metadata in metadata {
        match metadata {
            ClassMetadata::NetworkChangeCallback { name } => {
                writeln!(fmt, "// NetworkChangeCallback: {}", comment_text(name))?;
            }
            ClassMetadata::NetworkVarNames { name, type_name } => {
                writeln!(
                    fmt,
                    "// NetworkVarNames: {} ({})",
                    comment_text(name),
                    comment_text(type_name)
                )?;
            }
            ClassMetadata::Unknown { name } => {
                writeln!(fmt, "// {}", comment_text(name))?;
            }
        }
    }

    Ok(())
}

fn format_zig_enum_member_value(value: i64, type_name: &str) -> String {
    format!(
        "{:#X}",
        super::cpp_types::enum_value_masked(value, type_name)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::static_fields::StaticField;
    use crate::analysis::{Class, ClassField, Enum, EnumMember};

    fn render_json(schemas: &SchemaMap) -> serde_json::Value {
        let mut out = String::new();
        let mut fmt = Formatter::new(&mut out, 4);
        schemas.write_json(&mut fmt).expect("json render");
        serde_json::from_str(&out).expect("the writer must emit valid json")
    }

    fn schemas(static_fields: Vec<StaticField>) -> SchemaMap {
        SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "C_BaseEntity".to_string(),
                    module_name: "client.dll".into(),
                    parent_name: None,
                    size: 0x100,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: "m_iHealth".to_string(),
                        type_name: "int32".to_string(),
                        offset: 0x338,
                        metadata: Vec::new(),
                    }],
                    static_fields,
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )])
    }

    fn rendered_class(schemas: &SchemaMap) -> serde_json::Value {
        render_json(schemas)["client.dll"]["classes"]["C_BaseEntity"].clone()
    }

    /// A build whose static-field geometry does not validate must produce the
    /// exact object shape this dumper emitted before static fields existed.
    #[test]
    fn a_class_without_static_fields_renders_exactly_as_before() {
        let class = rendered_class(&schemas(Vec::new()));
        let keys: Vec<_> = class
            .as_object()
            .expect("class object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["fields", "metadata", "parent"]);
        assert_eq!(class["fields"]["m_iHealth"], 0x338);
    }

    #[test]
    fn validated_static_fields_are_emitted_in_declaration_order() {
        let class = rendered_class(&schemas(vec![
            StaticField {
                name: "m_bIsDefault".to_string(),
                type_name: "bool".to_string(),
                index: 0,
            },
            StaticField {
                name: "sm_pInstance".to_string(),
                type_name: "CGameRules*".to_string(),
                index: 1,
            },
        ]));

        let statics = class["static_fields"]
            .as_array()
            .expect("static_fields array");
        assert_eq!(statics.len(), 2);
        assert_eq!(statics[0]["name"], "m_bIsDefault");
        assert_eq!(statics[0]["type_name"], "bool");
        assert_eq!(statics[0]["index"], 0);
        assert_eq!(statics[1]["name"], "sm_pInstance");
        assert_eq!(statics[1]["type_name"], "CGameRules*");
        assert_eq!(statics[1]["index"], 1);

        // The pre-existing keys keep their meaning alongside the new one.
        assert_eq!(class["fields"]["m_iHealth"], 0x338);
    }

    /// The non-JSON writers are consumed as generated source; adding a section
    /// to them would change every downstream file, so they must stay untouched.
    #[test]
    fn static_fields_do_not_leak_into_the_generated_source_writers() {
        let populated = schemas(vec![StaticField {
            name: "sm_pInstance".to_string(),
            type_name: "CGameRules*".to_string(),
            index: 0,
        }]);
        let bare = schemas(Vec::new());

        for file_type in ["cs", "hpp", "rs", "zig"] {
            let render = |schemas: &SchemaMap| {
                let mut out = String::new();
                let mut fmt = Formatter::new(&mut out, 4);
                match file_type {
                    "cs" => schemas.write_cs(&mut fmt),
                    "hpp" => schemas.write_hpp(&mut fmt),
                    "rs" => schemas.write_rs(&mut fmt),
                    "zig" => schemas.write_zig(&mut fmt),
                    _ => unreachable!(),
                }
                .expect("render");
                out
            };
            assert_eq!(
                render(&populated),
                render(&bare),
                "{file_type} output changed once static fields were present"
            );
        }
    }

    #[test]
    fn hpp_emits_masked_high_bit_enum_members_not_storage_width_max() {
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                Vec::new(),
                vec![Enum {
                    name: "EFlags".into(),
                    alignment: 4,
                    size: 4,
                    members: vec![EnumMember {
                        name: "High".into(),
                        value: i32::MAX as i64 + 1,
                    }],
                    flags: Vec::new(),
                }],
            ),
        )]);
        let mut out = String::new();
        let mut fmt = Formatter::new(&mut out, 4);
        schemas.write_hpp(&mut fmt).expect("hpp render");
        assert!(
            out.contains("0x80000000"),
            "expected masked 0x80000000 in {out}"
        );
        assert!(
            !out.contains("0xFFFFFFFF"),
            "width-max must not replace the member value: {out}"
        );
    }

    #[test]
    fn cs_rs_zig_mask_enum_members_to_storage_width() {
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                Vec::new(),
                vec![Enum {
                    name: "ESmall".into(),
                    alignment: 1,
                    size: 1,
                    members: vec![
                        EnumMember {
                            name: "Overflow".into(),
                            value: 0x100,
                        },
                        EnumMember {
                            name: "Neg".into(),
                            value: -1,
                        },
                    ],
                    flags: Vec::new(),
                }],
            ),
        )]);
        let render = |file_type: &str| {
            let mut out = String::new();
            let mut fmt = Formatter::new(&mut out, 4);
            match file_type {
                "cs" => schemas.write_cs(&mut fmt),
                "rs" => schemas.write_rs(&mut fmt),
                "zig" => schemas.write_zig(&mut fmt),
                _ => unreachable!(),
            }
            .expect("render");
            out
        };
        let cs = render("cs");
        assert!(
            cs.contains("Overflow = 0x0"),
            "C# byte 0x100 must wrap: {cs}"
        );
        assert!(cs.contains("Neg = 0xFF"), "C# byte -1 must be 0xFF: {cs}");
        assert!(!cs.contains("0x100"), "unmasked 0x100 is not a byte: {cs}");
        let rs = render("rs");
        assert!(
            rs.contains("Overflow = 0x0"),
            "Rust u8 0x100 must wrap: {rs}"
        );
        assert!(rs.contains("Neg = 0xFF"), "Rust u8 -1 must be 0xFF: {rs}");
        assert!(!rs.contains("u8::MAX"), "do not special-case only -1: {rs}");
        let zig = render("zig");
        assert!(
            zig.contains("Overflow = 0x0"),
            "Zig u8 0x100 must wrap: {zig}"
        );
        assert!(zig.contains("Neg = 0xFF"), "Zig u8 -1 must be 0xFF: {zig}");
    }
}
