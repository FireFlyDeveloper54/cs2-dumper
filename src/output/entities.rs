//! Emitter for the live entity snapshot (entities.json).

use std::collections::BTreeMap;

use serde_json::json;

use crate::analysis::entities::EntitySnapshotEntry;

pub fn render_json(entities: &[EntitySnapshotEntry], build: Option<u32>) -> String {
    // Per-classname counts — "what's in the world", most-common first.
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for e in entities {
        *counts.entry(e.classname.as_str()).or_default() += 1;
    }
    let mut by_class: Vec<(&str, u32)> = counts.into_iter().collect();
    by_class.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let by_class_json: Vec<_> = by_class
        .iter()
        .map(|(k, v)| json!({ "classname": k, "count": v }))
        .collect();

    serde_json::to_string_pretty(&json!({
        "build_number": build,
        "note": "Live snapshot of the CGameEntitySystem at dump time.",
        "entity_handle_capacity": 32768,
        "entity_index_max": 32767,
        "entity_count": entities.len(),
        "class_count": by_class_json.len(),
        "by_class": by_class_json,
        "entities": entities,
    }))
    .unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_full_entity_handle_space() {
        let report: serde_json::Value = serde_json::from_str(&render_json(&[], None)).unwrap();
        assert_eq!(report["entity_handle_capacity"], 32768);
        assert_eq!(report["entity_index_max"], 32767);
    }
}
