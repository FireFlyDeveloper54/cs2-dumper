//! Emitters for the ConVar / ConCommand catalogue.
//!
//!   convars.json  — structured catalogue (drives the site's ConVars browser)
//!   convars.hpp   — human-readable reference table (comments only; convars
//!                   aren't hookable types, so there's nothing to `#include`
//!                   for — the value is the reference itself).

use serde_json::json;

use crate::analysis::convars::ConVarsDump;

/// Structured JSON: `{ build_number, convar_count, command_count, convars[], commands[] }`.
pub fn render_json(dump: &ConVarsDump, build: Option<u32>) -> String {
    let convars: Vec<_> = dump
        .convars
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "value": c.value,
                "type": c.type_name,
                "type_id": c.type_id,
                "flags": format!("0x{:X}", c.flags),
                "flag_names": c.flag_names,
                "description": c.description,
                "address": format!("0x{:X}", c.address),
            })
        })
        .collect();

    let commands: Vec<_> = dump
        .commands
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "flags": format!("0x{:X}", c.flags),
                "flag_names": c.flag_names,
                "description": c.description,
                "address": format!("0x{:X}", c.address),
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "build_number": build,
        "convar_count": dump.convars.len(),
        "command_count": dump.commands.len(),
        "registry_layout": {
            "cv_base": format!("0x{:X}", dump.registry_layout.cv_base),
            "cv_head": format!("0x{:X}", dump.registry_layout.cv_head),
            "cv_stride": format!("0x{:X}", dump.registry_layout.cv_stride),
            "cv_next": format!("0x{:X}", dump.registry_layout.cv_next),
            "cc_base": format!("0x{:X}", dump.registry_layout.cc_base),
            "cc_head": format!("0x{:X}", dump.registry_layout.cc_head),
            "cc_stride": format!("0x{:X}", dump.registry_layout.cc_stride),
            "cc_next": format!("0x{:X}", dump.registry_layout.cc_next),
        },
        "convars": convars,
        "commands": commands,
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// Reference `.hpp` — an aligned, commented table of every convar/command.
pub fn render_hpp(dump: &ConVarsDump, build: Option<u32>) -> String {
    let mut s = String::new();
    s.push_str("// convars.hpp — CS2 ConVar / ConCommand catalogue (auto-generated)\n");
    if let Some(b) = build {
        s.push_str(&format!("// build: {b}\n"));
    }
    s.push_str(&format!(
        "// {} convars, {} commands. Read-only snapshot of the tier0 CCvar registry.\n",
        dump.convars.len(),
        dump.commands.len()
    ));
    s.push_str("#pragma once\n\n");

    // ---- convars --------------------------------------------------------
    let name_w = dump
        .convars
        .iter()
        .map(|c| c.name.len())
        .chain(dump.commands.iter().map(|c| c.name.len()))
        .max()
        .unwrap_or(0)
        .min(56);
    let type_w = dump
        .convars
        .iter()
        .map(|c| c.type_name.len())
        .max()
        .unwrap_or(0);
    let val_w = dump
        .convars
        .iter()
        .map(|c| c.value.len())
        .max()
        .unwrap_or(0)
        .min(20);

    s.push_str("// === ConVars ===\n");
    s.push_str("// name | type | value | flags | description\n");
    for c in &dump.convars {
        let flags = if c.flag_names.is_empty() {
            String::new()
        } else {
            c.flag_names.join("|")
        };
        s.push_str(&format!(
            "// {:name_w$}  {:type_w$}  {:val_w$}  {}",
            c.name,
            c.type_name,
            trunc(&c.value, 20),
            flags,
        ));
        if !c.description.is_empty() {
            s.push_str(&format!("  // {}", c.description));
        }
        s.push('\n');
    }

    // ---- commands -------------------------------------------------------
    s.push_str("\n// === ConCommands ===\n");
    s.push_str("// name | flags | description\n");
    for c in &dump.commands {
        let flags = if c.flag_names.is_empty() {
            String::new()
        } else {
            c.flag_names.join("|")
        };
        s.push_str(&format!("// {:name_w$}  {}", c.name, flags));
        if !c.description.is_empty() {
            s.push_str(&format!("  // {}", c.description));
        }
        s.push('\n');
    }

    s
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_keeps_legacy_fields_and_reports_layout() {
        let report: serde_json::Value =
            serde_json::from_str(&render_json(&ConVarsDump::default(), Some(1)))
                .expect("valid convars json");
        assert_eq!(report["build_number"], 1);
        assert_eq!(report["convar_count"], 0);
        assert_eq!(report["command_count"], 0);
        assert_eq!(report["registry_layout"]["cv_base"], "0x50");
        assert!(report["convars"].is_array());
        assert!(report["commands"].is_array());
    }
}
