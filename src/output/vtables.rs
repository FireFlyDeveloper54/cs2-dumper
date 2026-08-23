//! Vtable emitters: `vtables.json` plus consumer `vtables.hpp` / `vtables.cs`.
//!
//! JSON is the machine-readable dump (`module -> interface -> methods`).
//! The headers expose per-slot indices so a consumer can hook by index
//! without baking absolute addresses.

use std::collections::BTreeSet;
use std::fmt::Write;

use anyhow::Result;
use serde_json::json;

use crate::analysis::{VTableInfo, VTableMap};

use super::ident::{sanitize_ident, slugify};

fn module_ns(module: &str) -> String {
    slugify(module)
}

fn iface_ns(info: &VTableInfo, iface_name: &str, used: &mut BTreeSet<String>) -> String {
    let preferred = info
        .rtti_class
        .as_deref()
        .filter(|name| !name.is_empty())
        .map(sanitize_ident)
        .unwrap_or_else(|| sanitize_ident(iface_name));
    if used.insert(preferred.clone()) {
        return preferred;
    }
    let alt = sanitize_ident(&format!("{preferred}_{iface_name}"));
    used.insert(alt.clone());
    alt
}

fn slot_ident(index: usize, recovered: Option<&str>, used: &mut BTreeSet<String>) -> String {
    let candidate = recovered
        .filter(|name| !name.is_empty())
        .map(sanitize_ident)
        .filter(|name| !is_keyword(name))
        .unwrap_or_else(|| format!("method_{index}"));
    if used.insert(candidate.clone()) {
        candidate
    } else {
        let alt = format!("{candidate}_{index}");
        used.insert(alt.clone());
        alt
    }
}

fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "alignas"
            | "alignof"
            | "asm"
            | "auto"
            | "bool"
            | "break"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "consteval"
            | "constexpr"
            | "constinit"
            | "continue"
            | "decltype"
            | "default"
            | "delete"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "explicit"
            | "export"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "friend"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "mutable"
            | "namespace"
            | "new"
            | "noexcept"
            | "nullptr"
            | "operator"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "reinterpret_cast"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "static_assert"
            | "static_cast"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typedef"
            | "typeid"
            | "typename"
            | "union"
            | "unsigned"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
    )
}

/// Per-slot index header. Namespace is the RTTI class when recovered,
/// otherwise the interface version string.
pub fn render_hpp(map: &VTableMap, build_number: Option<u32>) -> String {
    let mut s = String::new();
    s.push_str("// Generated using https://github.com/a2x/cs2-dumper\n");
    s.push_str("// Primary vtable only (*(void**)instance).\n");
    s.push_str("#pragma once\n\n");
    s.push_str("#include <cstddef>\n");
    s.push_str("#include <cstdint>\n\n");
    if let Some(bn) = build_number {
        writeln!(s, "inline constexpr std::uint32_t CS2_BUILD = {bn};\n").ok();
    }
    s.push_str("namespace cs2 {\nnamespace vtables {\n");
    for (module, ifaces) in map {
        if ifaces.is_empty() {
            continue;
        }
        let ns = module_ns(module);
        writeln!(s, "    namespace {ns} {{").ok();
        let mut used_ns = BTreeSet::new();
        for (iface_name, info) in ifaces {
            let class_ns = iface_ns(info, iface_name, &mut used_ns);
            let rtti = info.rtti_class.as_deref().unwrap_or(iface_name);
            writeln!(
                s,
                "        // {rtti} (iface: {iface_name}) | vtable @ {}+{:#X} ({} methods)",
                info.vtable_module,
                info.vtable_rva,
                info.methods.len()
            )
            .ok();
            writeln!(s, "        namespace {class_ns} {{").ok();
            let mut used_slots = BTreeSet::new();
            for (index, method) in info.methods.iter().enumerate() {
                let ident = slot_ident(index, method.name.as_deref(), &mut used_slots);
                writeln!(
                    s,
                    "            inline constexpr std::ptrdiff_t {ident} = {index}; // {}+{:#X}",
                    method.module, method.rva
                )
                .ok();
            }
            writeln!(s, "        }}").ok();
        }
        writeln!(s, "    }}\n").ok();
    }
    s.push_str("}\n}\n");
    s
}

pub fn render_cs(map: &VTableMap, build_number: Option<u32>) -> String {
    let mut s = String::new();
    s.push_str("// Generated using https://github.com/a2x/cs2-dumper\n");
    s.push_str("namespace CS2.VTables {\n");
    if let Some(bn) = build_number {
        writeln!(s, "    public static class Build {{ public const uint Number = {bn}; }}").ok();
    }
    for (module, ifaces) in map {
        if ifaces.is_empty() {
            continue;
        }
        let ns = module_ns(module);
        writeln!(s, "    public static class {ns} {{").ok();
        let mut used_ns = BTreeSet::new();
        for (iface_name, info) in ifaces {
            let class_ns = iface_ns(info, iface_name, &mut used_ns);
            let rtti = info.rtti_class.as_deref().unwrap_or(iface_name);
            writeln!(
                s,
                "        // {rtti} (iface: {iface_name}) | vtable @ {}+0x{:X} ({} methods)",
                info.vtable_module,
                info.vtable_rva,
                info.methods.len()
            )
            .ok();
            writeln!(s, "        public static class {class_ns} {{").ok();
            let mut used_slots = BTreeSet::new();
            for (index, method) in info.methods.iter().enumerate() {
                let ident = slot_ident(index, method.name.as_deref(), &mut used_slots);
                writeln!(
                    s,
                    "            public const int {ident} = {index}; // {}+0x{:X}",
                    method.module, method.rva
                )
                .ok();
            }
            writeln!(s, "        }}").ok();
        }
        writeln!(s, "    }}").ok();
    }
    s.push_str("}\n");
    s
}

pub fn render_json(map: &VTableMap) -> Result<String> {
    let modules: serde_json::Map<String, serde_json::Value> = map
        .iter()
        .map(|(module, ifaces)| {
            let ifaces_json: serde_json::Map<String, serde_json::Value> = ifaces
                .iter()
                .map(|(iface_name, info)| {
                    let methods: Vec<serde_json::Value> = info
                        .methods
                        .iter()
                        .enumerate()
                        .map(|(index, m)| {
                            json!({
                                "index": index,
                                "module": m.module,
                                "rva": m.rva,
                                "name": m.name,
                            })
                        })
                        .collect();
                    (
                        iface_name.clone(),
                        json!({
                            "vtable_rva": info.vtable_rva,
                            "vtable_module": info.vtable_module,
                            "rtti_class": info.rtti_class,
                            "methods": methods,
                        }),
                    )
                })
                .collect();
            (module.clone(), serde_json::Value::Object(ifaces_json))
        })
        .collect();

    let root = json!({
        "note": "Primary vtable only (*(void**)instance). Classes reached via secondary vtables (multiple inheritance) are not walked and may be incomplete.",
        "modules": serde_json::Value::Object(modules),
    });

    Ok(serde_json::to_string_pretty(&root)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{VTableMethod, VTableMap};
    use std::collections::BTreeMap;

    fn sample() -> VTableMap {
        let info = VTableInfo {
            vtable_rva: 0x1000,
            vtable_module: "client.dll".into(),
            rtti_class: Some("CSource2Client".into()),
            methods: vec![
                VTableMethod {
                    module: "client.dll".into(),
                    rva: 0x2000,
                    name: Some("Connect".into()),
                },
                VTableMethod {
                    module: "client.dll".into(),
                    rva: 0x2010,
                    name: None,
                },
            ],
        };
        BTreeMap::from([(
            "client.dll".into(),
            BTreeMap::from([("Source2Client002".into(), info)]),
        )])
    }

    #[test]
    fn hpp_uses_rtti_namespace_and_recovered_slot_names() {
        let hpp = render_hpp(&sample(), Some(42));
        assert!(hpp.contains("CS2_BUILD = 42"));
        assert!(hpp.contains("namespace client_dll"));
        assert!(hpp.contains("namespace CSource2Client"));
        assert!(hpp.contains("iface: Source2Client002"));
        assert!(hpp.contains("inline constexpr std::ptrdiff_t Connect = 0"));
        assert!(hpp.contains("inline constexpr std::ptrdiff_t method_1 = 1"));
    }

    #[test]
    fn cs_emits_const_slot_indices() {
        let cs = render_cs(&sample(), None);
        assert!(cs.contains("public const int Connect = 0"));
        assert!(cs.contains("public const int method_1 = 1"));
    }
}
