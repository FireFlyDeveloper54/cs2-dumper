//! Version and RVA drift report for CreateInterface registrations.
//!
//! The legacy `interfaces.json` remains the compatibility contract. This
//! additive report compares it with the previous run and highlights both
//! address changes and interface-version family changes such as `Foo001` to
//! `Foo002`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::analysis::InterfaceMap;

pub fn render_json(previous: &str, current: &InterfaceMap) -> Result<String> {
    let previous: Value =
        serde_json::from_str(previous).context("invalid previous interfaces.json")?;
    let current = serde_json::to_value(current)?;
    let old = index(&previous);
    let new = index(&current);

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
        let Some(before) = old.get(key) else { continue };
        if before != after {
            changed.push(json!({
                "interface": key,
                "before_rva": before,
                "after_rva": after,
            }));
        }
    }

    let version_drift = version_drift(&old, &new);
    serde_json::to_string_pretty(&json!({
        "previous_total": old.len(),
        "current_total": new.len(),
        "added": added,
        "removed": removed,
        "changed": changed,
        "version_drift": version_drift,
    }))
    .map_err(Into::into)
}

fn index(document: &Value) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let Some(modules) = document.as_object() else {
        return out;
    };
    for (module, entries) in modules {
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (name, value) in entries {
            let Some(rva) = value.as_u64() else { continue };
            out.insert(format!("{}::{}", module.to_ascii_lowercase(), name), rva);
        }
    }
    out
}

fn version_drift(old: &BTreeMap<String, u64>, new: &BTreeMap<String, u64>) -> Vec<Value> {
    let old_families = families(old.keys());
    let new_families = families(new.keys());
    let mut out = Vec::new();
    for (family, previous) in old_families {
        let Some(current) = new_families.get(&family) else {
            continue;
        };
        if previous != *current {
            out.push(json!({
                "family": family,
                "previous": previous,
                "current": current,
            }));
        }
    }
    out
}

fn families<'a>(keys: impl Iterator<Item = &'a String>) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for key in keys {
        let Some((module, name)) = key.split_once("::") else {
            continue;
        };
        let Some(split) = name
            .len()
            .checked_sub(name.bytes().rev().take_while(u8::is_ascii_digit).count())
        else {
            continue;
        };
        if split == name.len() || split == 0 {
            continue;
        }
        let family = format!("{}::{}", module, &name[..split]);
        out.entry(family).or_default().insert(name.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::render_json;
    use crate::analysis::InterfaceMap;

    #[test]
    fn reports_address_and_version_drift() {
        let previous = r#"{
            "client.dll": { "Source2Client001": 16, "Keep001": 32 }
        }"#;
        let mut current = InterfaceMap::new();
        current.insert(
            "client.dll".into(),
            [("Source2Client002".into(), 24), ("Keep001".into(), 40)]
                .into_iter()
                .collect(),
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_json(previous, &current).unwrap()).unwrap();
        assert_eq!(value["added"][0], "client.dll::Source2Client002");
        assert_eq!(value["changed"][0]["after_rva"], 40);
        assert_eq!(
            value["version_drift"][0]["family"],
            "client.dll::Source2Client"
        );
    }

    #[test]
    fn empty_inputs_still_produce_a_report() {
        let value: serde_json::Value =
            serde_json::from_str(&render_json("{}", &InterfaceMap::new()).unwrap()).unwrap();
        assert_eq!(value["previous_total"], 0);
        assert_eq!(value["current_total"], 0);
        assert_eq!(value["added"].as_array().unwrap().len(), 0);
        assert_eq!(value["removed"].as_array().unwrap().len(), 0);
        assert_eq!(value["changed"].as_array().unwrap().len(), 0);
        assert_eq!(value["version_drift"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn legacy_shapes_are_skipped_instead_of_aborting() {
        // Older dumps nested extra metadata, used arrays, or stored addresses as
        // strings. None of that may abort the report stage.
        let previous = r#"{
            "client.dll": { "Keep001": 32, "Stringly001": "0x20", "Nested001": { "rva": 1 } },
            "engine2.dll": [1, 2, 3],
            "build_number": 14000
        }"#;
        let mut current = InterfaceMap::new();
        current.insert(
            "CLIENT.DLL".into(),
            [("Keep001".into(), 32)].into_iter().collect(),
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_json(previous, &current).unwrap()).unwrap();
        assert_eq!(value["previous_total"], 1);
        assert_eq!(value["current_total"], 1);
        assert_eq!(value["added"].as_array().unwrap().len(), 0);
        assert_eq!(value["removed"].as_array().unwrap().len(), 0);
        assert_eq!(value["changed"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn malformed_previous_json_is_reported_as_an_error() {
        assert!(render_json("not json", &InterfaceMap::new()).is_err());
    }
}
