use std::collections::BTreeMap;

use serde_json::json;

use crate::analysis::{ClassMetadata, SchemaMap};

// Stable, language-neutral layout report intended for comparing CS2 updates.
pub fn render_json(schemas: &SchemaMap) -> Result<String, serde_json::Error> {
    let modules: BTreeMap<_, _> = schemas
        .iter()
        .map(|(module, (classes, enums))| {
            let classes: BTreeMap<_, _> = classes
                .iter()
                .map(|class| {
                    let fields: BTreeMap<_, _> = class
                        .fields
                        .iter()
                        .map(|field| {
                            (
                                &field.name,
                                json!({
                                    "offset": field.offset,
                                    "type": field.type_name,
                                    "metadata": field.metadata,
                                }),
                            )
                        })
                        .collect();
                    let metadata: Vec<_> = class.metadata.iter().map(metadata_json).collect();
                    (
                        &class.name,
                        json!({
                            "parent": class.parent_name,
                            "size": class.size,
                            "alignment": class.alignment,
                            "metadata": metadata,
                            "flags": class.flags,
                            "fields": fields,
                        }),
                    )
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
                    (
                        &enum_.name,
                        json!({
                            "size": enum_.size,
                            "alignment": enum_.alignment,
                            "flags": enum_.flags,
                            "members": members,
                        }),
                    )
                })
                .collect();
            (module, json!({ "classes": classes, "enums": enums }))
        })
        .collect();

    serde_json::to_string_pretty(&json!({ "modules": modules }))
}

fn metadata_json(metadata: &ClassMetadata) -> serde_json::Value {
    match metadata {
        ClassMetadata::NetworkChangeCallback { name } => {
            json!({ "type": "NetworkChangeCallback", "name": name })
        }
        ClassMetadata::NetworkVarNames { name, type_name } => {
            json!({ "type": "NetworkVarNames", "name": name, "type_name": type_name })
        }
        ClassMetadata::Unknown { name } => json!({ "type": "Unknown", "name": name }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Class, ClassField, SchemaMap};

    #[test]
    fn render_json_emits_class_field_offset_without_panicking() {
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "C_TestPawn".into(),
                    module_name: "client.dll".into(),
                    parent_name: None,
                    size: 0x500,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: "m_iHealth".into(),
                        type_name: "int32".into(),
                        offset: 0x4A8,
                        metadata: Vec::new(),
                    }],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )]);
        let raw = render_json(&schemas).expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert_eq!(
            json["modules"]["client.dll"]["classes"]["C_TestPawn"]["fields"]["m_iHealth"]["offset"],
            0x4A8
        );
    }
}
