use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::{Value, json};

/// Compare two schema_index.json documents and report class, field, enum, and member changes.
pub fn render_json(previous: &str, current: &str) -> Result<String> {
    let previous: Value =
        serde_json::from_str(previous).context("invalid previous schema_index.json")?;
    let current: Value =
        serde_json::from_str(current).context("invalid current schema_index.json")?;
    let old_classes = index_entries(&previous, "classes");
    let new_classes = index_entries(&current, "classes");
    let old_enums = index_entries(&previous, "enums");
    let new_enums = index_entries(&current, "enums");

    let (class_added, class_removed, class_changed) = compare_classes(&old_classes, &new_classes);
    let (enum_added, enum_removed, enum_changed) = compare_enums(&old_enums, &new_enums);

    Ok(serde_json::to_string_pretty(&json!({
        "previous_classes": old_classes.len(),
        "current_classes": new_classes.len(),
        "classes": { "added": class_added, "removed": class_removed, "changed": class_changed },
        "previous_enums": old_enums.len(),
        "current_enums": new_enums.len(),
        "enums": { "added": enum_added, "removed": enum_removed, "changed": enum_changed },
    }))?)
}

fn compare_classes<'a>(
    old: &BTreeMap<String, &'a Value>,
    new: &BTreeMap<String, &'a Value>,
) -> (Vec<String>, Vec<String>, Vec<Value>) {
    let added = new
        .keys()
        .filter(|key| !old.contains_key(*key))
        .cloned()
        .collect();
    let removed = old
        .keys()
        .filter(|key| !new.contains_key(*key))
        .cloned()
        .collect();
    let mut changed = Vec::new();
    for (key, after) in new {
        let Some(before) = old.get(key) else { continue };
        let layout_changes =
            changed_scalar_fields(before, after, &["parent", "size", "alignment", "metadata"]);
        let field_changes = compare_named_values(before.get("fields"), after.get("fields"));
        if !layout_changes.is_empty() || has_changes(&field_changes) {
            changed.push(json!({
                "class": key,
                "layout_changes": layout_changes,
                "fields": field_changes,
            }));
        }
    }
    (added, removed, changed)
}

fn compare_enums<'a>(
    old: &BTreeMap<String, &'a Value>,
    new: &BTreeMap<String, &'a Value>,
) -> (Vec<String>, Vec<String>, Vec<Value>) {
    let added = new
        .keys()
        .filter(|key| !old.contains_key(*key))
        .cloned()
        .collect();
    let removed = old
        .keys()
        .filter(|key| !new.contains_key(*key))
        .cloned()
        .collect();
    let mut changed = Vec::new();
    for (key, after) in new {
        let Some(before) = old.get(key) else { continue };
        let layout_changes = changed_scalar_fields(before, after, &["size", "alignment"]);
        let member_changes = compare_named_values(before.get("members"), after.get("members"));
        if !layout_changes.is_empty() || has_changes(&member_changes) {
            changed.push(json!({
                "enum": key,
                "layout_changes": layout_changes,
                "members": member_changes,
            }));
        }
    }
    (added, removed, changed)
}

fn changed_scalar_fields(before: &Value, after: &Value, fields: &[&str]) -> Vec<Value> {
    fields
        .iter()
        .filter_map(|field| {
            (before.get(*field) != after.get(*field)).then(|| {
                json!({
                    "field": field,
                    "before": before.get(*field),
                    "after": after.get(*field),
                })
            })
        })
        .collect()
}

fn compare_named_values(before: Option<&Value>, after: Option<&Value>) -> Value {
    let before = before.and_then(Value::as_object);
    let after = after.and_then(Value::as_object);
    let empty = serde_json::Map::new();
    let before = before.unwrap_or(&empty);
    let after = after.unwrap_or(&empty);
    let added: Vec<_> = after
        .keys()
        .filter(|key| !before.contains_key(*key))
        .cloned()
        .collect();
    let removed: Vec<_> = before
        .keys()
        .filter(|key| !after.contains_key(*key))
        .cloned()
        .collect();
    let changed: Vec<_> = after
        .iter()
        .filter_map(|(key, new_value)| {
            let old_value = before.get(key)?;
            (old_value != new_value)
                .then(|| json!({ "name": key, "before": old_value, "after": new_value }))
        })
        .collect();
    json!({ "added": added, "removed": removed, "changed": changed })
}

fn has_changes(value: &Value) -> bool {
    ["added", "removed", "changed"].iter().any(|key| {
        value
            .get(*key)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    })
}

fn index_entries<'a>(document: &'a Value, kind: &str) -> BTreeMap<String, &'a Value> {
    let mut result = BTreeMap::new();
    let Some(modules) = document.get("modules").and_then(Value::as_object) else {
        return result;
    };
    for (module, value) in modules {
        let Some(entries) = value.get(kind).and_then(Value::as_object) else {
            continue;
        };
        for (name, layout) in entries {
            result.insert(format!("{}::{}", module, name), layout);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::render_json;

    #[test]
    fn reports_precise_class_and_enum_changes() {
        let old = r#"{"modules":{"client.dll":{"classes":{"C":{"size":4,"alignment":4,"parent":null,"metadata":[],"fields":{"x":{"offset":0,"type":"int","metadata":[]},"gone":{"offset":2,"type":"bool","metadata":[]}}}},"enums":{"E":{"size":4,"alignment":4,"members":{"A":0}}}}}}"#;
        let new = r#"{"modules":{"client.dll":{"classes":{"C":{"size":8,"alignment":4,"parent":null,"metadata":[],"fields":{"x":{"offset":4,"type":"int","metadata":[]},"new_field":{"offset":6,"type":"bool","metadata":[]}}}},"enums":{"E":{"size":4,"alignment":4,"members":{"A":1,"B":2}}}}}}"#;
        let report = render_json(old, new).expect("valid schema diff");
        assert!(report.contains("client.dll::C"));
        assert!(report.contains("new_field"));
        assert!(report.contains("gone"));
        assert!(report.contains("client.dll::E"));
        assert!(report.contains("\"A\""));
        assert!(report.contains("\"B\""));
    }
}
