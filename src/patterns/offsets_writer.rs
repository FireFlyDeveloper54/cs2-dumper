use super::PatternHit;
use crate::analysis::{InterfaceMap, OffsetMap};
use crate::output::ident::{IdentifierAllocator, cpp_identifier};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Map a DLL filename to the namespace stem we expose it under.
fn normalized_module(module: &str) -> String {
    module.trim().to_ascii_lowercase()
}

/// Sanitise a Pattern name into a valid identifier.
fn sanitise_stem(name: &str) -> String {
    name.replace("::", "_")
        .replace(|c: char| !(c.is_ascii_alphanumeric() || c == '_'), "_")
}

/// Clean an offset symbol to the unified convention: no Hungarian `dw`
/// prefix and no `_ptr` suffix.
fn clean_off_name(name: &str) -> String {
    let mut name = sanitise_stem(name);
    if let Some(stripped) = name.strip_suffix("_ptr") {
        name = stripped.to_string();
    }
    if name.starts_with("dw")
        && name[2..]
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
    {
        name = name[2..].to_string();
    }
    name
}

fn module_names(
    hits: &[PatternHit],
    analysis: &OffsetMap,
    interfaces: &InterfaceMap,
) -> BTreeMap<String, String> {
    let mut normalized = BTreeSet::new();
    normalized.extend(analysis.keys().map(|module| normalized_module(module)));
    normalized.extend(interfaces.keys().map(|module| normalized_module(module)));
    normalized.extend(
        hits.iter()
            .filter(|hit| hit.found && hit.resolve == "riprel")
            .map(|hit| normalized_module(&hit.module)),
    );
    let mut allocator = IdentifierAllocator::default();
    normalized
        .into_iter()
        .map(|module| {
            let stem = module.strip_suffix(".dll").unwrap_or(&module);
            let emitted = allocator.allocate(cpp_identifier(stem));
            (module, emitted)
        })
        .collect()
}

fn symbol_names(
    hits: &[PatternHit],
    analysis: &OffsetMap,
    interfaces: &InterfaceMap,
    modules: &BTreeMap<String, String>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut logical_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (module, offsets) in analysis {
        let emitted_module = &modules[&normalized_module(module)];
        logical_names
            .entry(emitted_module.clone())
            .or_default()
            .extend(offsets.keys().map(|name| clean_off_name(name)));
    }
    for hit in hits
        .iter()
        .filter(|hit| hit.found && hit.resolve == "riprel" && hit.rva.is_some())
    {
        let emitted_module = &modules[&normalized_module(&hit.module)];
        logical_names
            .entry(emitted_module.clone())
            .or_default()
            .insert(clean_off_name(&hit.name));
    }
    for (module, registered) in interfaces {
        let emitted_module = &modules[&normalized_module(module)];
        logical_names
            .entry(emitted_module.clone())
            .or_default()
            .extend(registered.keys().map(|name| sanitise_stem(name)));
    }
    logical_names
        .into_iter()
        .map(|(module, names)| {
            let mut allocator = IdentifierAllocator::default();
            let names = names
                .into_iter()
                .map(|logical| {
                    let emitted = allocator.allocate(cpp_identifier(&logical));
                    (logical, emitted)
                })
                .collect();
            (module, names)
        })
        .collect()
}

#[derive(Clone, Debug, Serialize)]
struct MergedEntry {
    rva: String,
    source: &'static str,
    original_name: String,
}

#[derive(Clone, Debug, Serialize)]
struct MergeCollision {
    module: String,
    symbol: String,
    winner: MergedEntry,
    discarded: MergedEntry,
}

#[derive(Debug, Serialize)]
struct MergeReport {
    format: &'static str,
    modules: BTreeMap<String, BTreeMap<String, MergedEntry>>,
    collisions: Vec<MergeCollision>,
}

fn entry(rva: u64, source: &'static str, original_name: &str) -> MergedEntry {
    MergedEntry {
        rva: format!("0x{rva:X}"),
        source,
        original_name: original_name.to_string(),
    }
}

/// Insert in precedence order. We retain a losing candidate in the JSON
/// report rather than silently changing the value exposed to consumers.
fn insert(report: &mut MergeReport, module: String, symbol: String, candidate: MergedEntry) {
    let entries = report.modules.entry(module.clone()).or_default();
    if let Some(winner) = entries.get(&symbol) {
        if winner.rva != candidate.rva || winner.source != candidate.source {
            report.collisions.push(MergeCollision {
                module,
                symbol,
                winner: winner.clone(),
                discarded: candidate,
            });
        }
    } else {
        entries.insert(symbol, candidate);
    }
}

/// Build one deterministic view shared by `offsets_merged.hpp` and JSON.
/// Canonical a2x offset patterns win over RIP-relative pattern globals, which
/// in turn win over the registered CreateInterface RVA for the same symbol.
fn merged_offsets(
    hits: &[PatternHit],
    analysis: &OffsetMap,
    interfaces: &InterfaceMap,
) -> MergeReport {
    let mut report = MergeReport {
        format: "cs2-dumper.offsets_merged.v1",
        modules: BTreeMap::new(),
        collisions: Vec::new(),
    };
    let module_names = module_names(hits, analysis, interfaces);
    let symbol_names = symbol_names(hits, analysis, interfaces, &module_names);

    for (module, offsets) in analysis {
        for (name, rva) in offsets {
            insert(
                &mut report,
                module_names[&normalized_module(module)].clone(),
                symbol_names[&module_names[&normalized_module(module)]][&clean_off_name(name)]
                    .clone(),
                entry(*rva as u64, "canonical_offset", name),
            );
        }
    }
    for hit in hits
        .iter()
        .filter(|hit| hit.found && hit.resolve == "riprel")
    {
        if let Some(rva) = hit.rva {
            insert(
                &mut report,
                module_names[&normalized_module(&hit.module)].clone(),
                symbol_names[&module_names[&normalized_module(&hit.module)]]
                    [&clean_off_name(&hit.name)]
                    .clone(),
                entry(rva, "riprel_pattern", &hit.name),
            );
        }
    }
    for (module, registered) in interfaces {
        for (name, rva) in registered {
            insert(
                &mut report,
                module_names[&normalized_module(module)].clone(),
                symbol_names[&module_names[&normalized_module(module)]][&sanitise_stem(name)]
                    .clone(),
                entry(*rva, "interface_registry", name),
            );
        }
    }
    report
}

/// C++ header containing the unified dynamically-resolved RVA tree.
pub fn render_offsets_hpp(
    hits: &[PatternHit],
    analysis: &OffsetMap,
    interfaces: &InterfaceMap,
) -> String {
    let report = merged_offsets(hits, analysis, interfaces);
    let mut output = String::new();
    output.push_str("// Generated by cs2-dumper. Dynamically resolved RVAs.\n");
    output.push_str("#pragma once\n\n#include <cstddef>\n#include <cstdint>\n\n");
    output.push_str("namespace offsets {\n");
    for (module, entries) in &report.modules {
        let _ = writeln!(output, "    namespace {module} {{");
        for (name, value) in entries {
            let _ = writeln!(
                output,
                "        constexpr std::ptrdiff_t {name} = {};",
                value.rva
            );
        }
        output.push_str("    }\n");
    }
    output.push_str("}\n");
    output
}

/// Machine-readable counterpart to `offsets_merged.hpp`. Besides the winning
/// value it preserves source and collision provenance for update diagnostics.
pub fn render_offsets_json(
    hits: &[PatternHit],
    analysis: &OffsetMap,
    interfaces: &InterfaceMap,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&merged_offsets(hits, analysis, interfaces))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_keeps_all_sources_and_collision_provenance() {
        let analysis = OffsetMap::from([(
            "client.dll".to_string(),
            BTreeMap::from([("dwEntityList".to_string(), 0x111u32)]),
        )]);
        let interfaces = InterfaceMap::from([(
            "client.dll".to_string(),
            BTreeMap::from([("EntityList".to_string(), 0x333u64)]),
        )]);
        let hits = [PatternHit {
            name: "EntityList_ptr".into(),
            module: "client.dll".into(),
            resolve: "riprel",
            pattern: "48 8B ?".into(),
            prototype: None,
            bytes: None,
            pattern_synth: None,
            repaired_from: None,
            found: true,
            match_rva: Some(0),
            match_va: Some(0),
            rva: Some(0x222),
            va: Some(0),
            matches: 1,
            confidence: 1.0,
            error: None,
        }];

        let rendered = render_offsets_json(&hits, &analysis, &interfaces).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(value["modules"]["client"]["EntityList"]["rva"], "0x111");
        assert_eq!(
            value["modules"]["client"]["EntityList"]["source"],
            "canonical_offset"
        );
        assert_eq!(value["collisions"].as_array().expect("collisions").len(), 2);
    }

    #[test]
    fn hpp_disambiguates_modules_keywords_and_sanitized_symbols() {
        let analysis = OffsetMap::from([
            (
                "foo-bar.dll".to_string(),
                BTreeMap::from([
                    (String::new(), 1u32),
                    ("9name".to_string(), 2u32),
                    ("_class".to_string(), 3u32),
                    ("class".to_string(), 4u32),
                ]),
            ),
            (
                "foo_bar.dll".to_string(),
                BTreeMap::from([("Other".to_string(), 5u32)]),
            ),
        ]);
        let hpp = render_offsets_hpp(&[], &analysis, &InterfaceMap::new());
        assert!(hpp.contains("namespace foo_bar {"), "{hpp}");
        assert!(hpp.contains("namespace foo_bar_2 {"), "{hpp}");
        assert!(hpp.contains("anonymous = 0x1"), "{hpp}");
        assert!(hpp.contains("_9name = 0x2"), "{hpp}");
        assert!(hpp.contains("_class = 0x3"), "{hpp}");
        assert!(hpp.contains("_class_2 = 0x4"), "{hpp}");
    }
}
