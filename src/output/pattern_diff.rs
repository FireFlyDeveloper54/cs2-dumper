use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::patterns::PatternReport;

/// Compare this run's pattern report with the previous report in the same
/// output directory. The report is intentionally based on serialized data so
/// it remains compatible as PatternHit gains new fields.
pub fn render_json(previous: &str, current: &PatternReport) -> Result<String> {
    let previous: Value =
        serde_json::from_str(previous).context("invalid previous patterns.json")?;
    let current = serde_json::to_value(current)?;
    let old = index_hits(&previous);
    let new = index_hits(&current);

    let added: Vec<_> = new
        .keys()
        .filter(|key| !old.contains_key(*key))
        .cloned()
        .collect();
    let removed: Vec<_> = old
        .keys()
        .filter(|key| !new.contains_key(*key))
        .cloned()
        .collect();
    let mut changed = Vec::new();

    for (key, after) in &new {
        let Some(before) = old.get(key) else {
            continue;
        };
        let mut reasons = Vec::new();
        if value_u64(before, "rva") != value_u64(after, "rva") {
            reasons.push("rva");
        }
        if value_bool(before, "found") != value_bool(after, "found") {
            reasons.push("found");
        }
        if value_str(before, "pattern_synth") != value_str(after, "pattern_synth") {
            reasons.push("pattern_synth");
        }
        if value_u64(before, "matches") != value_u64(after, "matches") {
            reasons.push("matches");
        }
        if value_f64(before, "confidence") != value_f64(after, "confidence") {
            reasons.push("confidence");
        }
        if !reasons.is_empty() {
            changed.push(json!({
                "pattern": key,
                "changes": reasons,
                "before": summary(before),
                "after": summary(after),
            }));
        }
    }

    Ok(serde_json::to_string_pretty(&json!({
        "previous_total": old.len(),
        "current_total": new.len(),
        "added": added,
        "removed": removed,
        "changed": changed,
    }))?)
}

fn index_hits(report: &Value) -> BTreeMap<String, &Value> {
    report
        .get("hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let module = hit.get("module")?.as_str()?;
            let name = hit.get("name")?.as_str()?;
            Some((format!("{}::{}", module, name), hit))
        })
        .collect()
}

fn summary(hit: &Value) -> Value {
    json!({
        "found": value_bool(hit, "found"),
        "rva": value_u64(hit, "rva"),
        "matches": value_u64(hit, "matches"),
        "confidence": value_f64(hit, "confidence"),
        "pattern_synth": value_str(hit, "pattern_synth"),
    })
}

fn value_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}
fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key)?.as_bool()
}
fn value_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str()
}
fn value_f64(value: &Value, key: &str) -> Option<f64> {
    value.get(key)?.as_f64()
}
