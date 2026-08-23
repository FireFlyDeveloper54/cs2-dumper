use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Write};

use heck::{AsPascalCase, AsSnakeCase};

use serde_json::json;

use super::{CodeWriter, Formatter, SchemaMap, slugify, zig_ident};

use crate::analysis::ClassMetadata;

impl CodeWriter for SchemaMap {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace CS2Dumper.Schemas", false, |fmt| {
            for (module_name, (classes, enums)) in self {
                writeln!(fmt, "// Module: {}", module_name)?;
                writeln!(fmt, "// Class count: {}", classes.len())?;
                writeln!(fmt, "// Enum count: {}", enums.len())?;

                fmt.block(
                    &format!("public static class {}", AsPascalCase(slugify(module_name))),
                    false,
                    |fmt| {
                        for enum_ in enums {
                            let type_name = match enum_.storage_bytes() {
                                1 => "byte",
                                2 => "ushort",
                                4 => "uint",
                                8 => "ulong",
                                _ => continue,
                            };

                            writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                            writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                            fmt.block(
                                &format!("public enum {} : {}", slugify(&enum_.name), type_name),
                                false,
                                |fmt| {
                                    let members = enum_
                                        .members
                                        .iter()
                                        .map(|member| {
                                            let formatted_value =
                                                if (0..=i32::MAX as i64).contains(&member.value) {
                                                    format!("{:#X}", member.value)
                                                } else {
                                                    format!(
                                                        "unchecked(({}){})",
                                                        type_name, member.value
                                                    )
                                                };

                                            format!("{} = {}", member.name, formatted_value)
                                        })
                                        .collect::<Vec<_>>()
                                        .join(",\n");

                                    writeln!(fmt, "{}", members)
                                },
                            )?;
                        }

                        for class in classes {
                            let parent_name = class
                                .parent_name
                                .as_deref()
                                .map(slugify)
                                .unwrap_or("None".to_string());

                            writeln!(fmt, "// Parent: {}", parent_name)?;
                            writeln!(fmt, "// Field count: {}", class.fields.len())?;

                            write_metadata(fmt, &class.metadata)?;

                            fmt.block(
                                &format!("public static class {}", slugify(&class.name)),
                                false,
                                |fmt| {
                                    for field in &class.fields {
                                        writeln!(
                                            fmt,
                                            "public const nint {} = {:#X}; // {}",
                                            field.name, field.offset, field.type_name
                                        )?;
                                    }

                                    Ok(())
                                },
                            )?;
                        }

                        Ok(())
                    },
                )?;
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
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;
                    writeln!(fmt, "// Enum count: {}", enums.len())?;

                    fmt.block(
                        &format!("namespace {}", AsSnakeCase(slugify(module_name))),
                        false,
                        |fmt| {
                            for enum_ in enums {
                                let type_name = match enum_.storage_bytes() {
                                    1 => "uint8_t",
                                    2 => "uint16_t",
                                    4 => "uint32_t",
                                    8 => "uint64_t",
                                    _ => continue,
                                };

                                writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                                writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                                fmt.block(
                                    &format!("enum class {} : {}", slugify(&enum_.name), type_name),
                                    true,
                                    |fmt| {
                                        let members = enum_
                                            .members
                                            .iter()
                                            .map(|member| {
                                                let formatted_value = if (0..=i32::MAX as i64)
                                                    .contains(&member.value)
                                                {
                                                    format!("{:#X}", member.value)
                                                } else {
                                                    let max_value = match type_name {
                                                        "uint8_t" => 0xFFu64,
                                                        "uint16_t" => 0xFFFFu64,
                                                        "uint32_t" => 0xFFFFFFFFu64,
                                                        "uint64_t" => 0xFFFFFFFFFFFFFFFFu64,
                                                        _ => 0,
                                                    };

                                                    format!("{:#X}", max_value)
                                                };

                                                format!("{} = {}", member.name, formatted_value)
                                            })
                                            .collect::<Vec<_>>()
                                            .join(",\n");

                                        writeln!(fmt, "{}", members)
                                    },
                                )?;
                            }

                            for class in classes {
                                let parent_name = class
                                    .parent_name
                                    .as_deref()
                                    .map(slugify)
                                    .unwrap_or("None".to_string());

                                writeln!(fmt, "// Parent: {}", parent_name)?;
                                writeln!(fmt, "// Field count: {}", class.fields.len())?;

                                write_metadata(fmt, &class.metadata)?;

                                fmt.block(
                                    &format!("namespace {}", slugify(&class.name)),
                                    false,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "constexpr std::ptrdiff_t {} = {:#X}; // {}",
                                                field.name, field.offset, field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content: BTreeMap<_, _> = self
            .iter()
            .map(|(module_name, (classes, enums))| {
                let classes: BTreeMap<_, _> = classes
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

                        // Only present when the static-field geometry validated
                        // against the live process, so a dump from a build this
                        // dumper cannot read stays byte-identical to before.
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

                        (slugify(&class.name), value)
                    })
                    .collect();

                let enums: BTreeMap<_, _> = enums
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
                            slugify(&enum_.name),
                            json!({
                                "size": enum_.size,
                                "alignment": enum_.alignment,
                                "type": type_name,
                                "members": members,
                            }),
                        )
                    })
                    .collect();

                (
                    module_name,
                    json!({
                        "classes": classes,
                        "enums": enums,
                    }),
                )
            })
            .collect();

        fmt.write_str(&serde_json::to_string_pretty(&content).unwrap())
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            fmt,
            "#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]\n"
        )?;

        fmt.block("pub mod cs2_dumper", false, |fmt| {
            fmt.block("pub mod schemas", false, |fmt| {
                for (module_name, (classes, enums)) in self {
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;
                    writeln!(fmt, "// Enum count: {}", enums.len())?;

                    fmt.block(
                        &format!("pub mod {}", AsSnakeCase(slugify(module_name))),
                        false,
                        |fmt| {
                            for enum_ in enums {
                                let type_name = match enum_.storage_bytes() {
                                    1 => "u8",
                                    2 => "u16",
                                    4 => "u32",
                                    8 => "u64",
                                    _ => continue,
                                };

                                writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                                writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                                fmt.block(
                                    &format!(
                                        "#[repr({})]\npub enum {}",
                                        type_name,
                                        slugify(&enum_.name),
                                    ),
                                    false,
                                    |fmt| {
                                        let mut used_values = HashSet::new();

                                        let members = enum_
                                            .members
                                            .iter()
                                            .filter_map(|member| {
                                                // Skip duplicate values.
                                                if !used_values.insert(member.value) {
                                                    return None;
                                                }

                                                let formatted_value = if member.value == -1 {
                                                    format!("{}::MAX", type_name)
                                                } else {
                                                    format!("{:#X}", member.value)
                                                };

                                                Some(format!(
                                                    "{} = {}",
                                                    member.name, formatted_value
                                                ))
                                            })
                                            .collect::<Vec<_>>()
                                            .join(",\n");

                                        writeln!(fmt, "{}", members)
                                    },
                                )?;
                            }

                            for class in classes {
                                let parent_name = class
                                    .parent_name
                                    .as_deref()
                                    .map(slugify)
                                    .unwrap_or("None".to_string());

                                writeln!(fmt, "// Parent: {}", parent_name)?;
                                writeln!(fmt, "// Field count: {}", class.fields.len())?;

                                write_metadata(fmt, &class.metadata)?;

                                fmt.block(
                                    &format!("pub mod {}", slugify(&class.name)),
                                    false,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "pub const {}: usize = {:#X}; // {}",
                                                field.name, field.offset, field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const cs2_dumper = struct", true, |fmt| {
            fmt.block("pub const schemas = struct", true, |fmt| {
                for (module_name, (classes, enums)) in self {
                    writeln!(fmt, "// Module: {}", module_name)?;
                    writeln!(fmt, "// Class count: {}", classes.len())?;
                    writeln!(fmt, "// Enum count: {}", enums.len())?;

                    let module_name = zig_ident(&AsSnakeCase(slugify(module_name)).to_string());

                    fmt.block(
                        &format!("pub const {} = struct", module_name),
                        true,
                        |fmt| {
                            for enum_ in enums {
                                let type_name = match enum_.storage_bytes() {
                                    1 => "u8",
                                    2 => "u16",
                                    4 => "u32",
                                    8 => "u64",
                                    _ => continue,
                                };

                                writeln!(fmt, "// Alignment: {}", enum_.alignment)?;
                                writeln!(fmt, "// Member count: {}", enum_.members.len())?;

                                let enum_name = zig_ident(&slugify(&enum_.name));

                                fmt.block(
                                    &format!("pub const {} = enum({})", enum_name, type_name),
                                    true,
                                    |fmt| {
                                        let mut used_values = HashSet::new();

                                        let members = enum_
                                            .members
                                            .iter()
                                            .filter_map(|member| {
                                                // Skip duplicate values.
                                                if !used_values.insert(member.value) {
                                                    return None;
                                                }

                                                let formatted_value = format_zig_enum_member_value(
                                                    member.value,
                                                    type_name,
                                                );

                                                Some(format!(
                                                    "{} = {}",
                                                    zig_ident(&member.name),
                                                    formatted_value
                                                ))
                                            })
                                            .collect::<Vec<_>>()
                                            .join(",\n");

                                        writeln!(fmt, "{}", members)
                                    },
                                )?;
                            }

                            for class in classes {
                                let parent_name = class
                                    .parent_name
                                    .as_deref()
                                    .map(slugify)
                                    .unwrap_or("None".to_string());

                                writeln!(fmt, "// Parent: {}", parent_name)?;
                                writeln!(fmt, "// Field count: {}", class.fields.len())?;

                                write_metadata(fmt, &class.metadata)?;

                                let class_name = zig_ident(&slugify(&class.name));

                                fmt.block(
                                    &format!("pub const {} = struct", class_name),
                                    true,
                                    |fmt| {
                                        for field in &class.fields {
                                            writeln!(
                                                fmt,
                                                "pub const {}: usize = {:#X}; // {}",
                                                zig_ident(&field.name),
                                                field.offset,
                                                field.type_name
                                            )?;
                                        }

                                        Ok(())
                                    },
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
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
                writeln!(fmt, "// NetworkChangeCallback: {}", name)?;
            }
            ClassMetadata::NetworkVarNames { name, type_name } => {
                writeln!(fmt, "// NetworkVarNames: {} ({})", name, type_name)?;
            }
            ClassMetadata::Unknown { name } => {
                writeln!(fmt, "// {}", name)?;
            }
        }
    }

    Ok(())
}

fn format_zig_enum_member_value(value: i64, type_name: &str) -> String {
    if value >= 0 {
        return format!("{:#X}", value);
    }

    let wrapped_value = match type_name {
        "u8" => value as u8 as u64,
        "u16" => value as u16 as u64,
        "u32" => value as u32 as u64,
        "u64" => value as u64,
        _ => 0,
    };

    format!("{:#X}", wrapped_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::static_fields::StaticField;
    use crate::analysis::{Class, ClassField};

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
                    module_name: "client.dll".to_string(),
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
}
